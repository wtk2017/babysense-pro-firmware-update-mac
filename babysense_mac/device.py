"""Identify the Babysense Pro parent unit's update drive and read its file tables."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Protocol

from . import constants as C
from . import fat16

READ_CHUNK_SECTORS = 256


class BlockDevice(Protocol):
    """What the installer needs from a drive (the USB parent unit or a disk image)."""

    def inquiry(self) -> bytes: ...

    def test_unit_ready(self) -> bool: ...

    def read_capacity(self) -> tuple[int, int]: ...

    def write_protected(self) -> bool: ...

    def read10(self, lba: int, count: int, block: int = 512) -> bytes: ...

    def write10(self, lba: int, data: bytes, block: int = 512) -> None: ...

    def synchronize_cache(self) -> str: ...


class UnsupportedDevice(RuntimeError):
    """The connected drive is not the tested Babysense Pro parent unit."""


@dataclass(frozen=True)
class DriveInfo:
    vendor: str
    product: str
    revision: str
    removable: bool
    sectors: int
    sector_size: int
    write_protected: bool

    @property
    def megabytes(self) -> float:
        return self.sectors * self.sector_size / 1e6


@dataclass(frozen=True)
class DriveSummary:
    info: DriveInfo
    geometry: fat16.Geometry
    volume_label: str
    files: tuple[str, ...]


def identify(
    dev: BlockDevice, attempts: int = C.READY_ATTEMPTS, sleep: Callable[[float], None] = time.sleep
) -> DriveInfo:
    raw = dev.inquiry()
    if len(raw) < 36:
        raise UnsupportedDevice("the drive returned a short identification")
    vendor, product = raw[8:16], raw[16:32]
    if vendor != C.SCSI_VENDOR or not product.startswith(C.SCSI_PRODUCT_PREFIX):
        raise UnsupportedDevice(f"this is not a Babysense Pro parent unit drive ({vendor!r} {product!r})")
    for _ in range(attempts):
        if dev.test_unit_ready():
            break
        sleep(0.5)
    else:
        raise UnsupportedDevice("the parent unit's drive never became ready")
    sectors, sector_size = dev.read_capacity()
    return DriveInfo(
        vendor.decode("latin-1").strip(),
        product.rstrip(b"\0 ").decode("latin-1"),
        raw[32:36].decode("latin-1").strip(),
        bool(raw[1] & 0x80),
        sectors,
        sector_size,
        dev.write_protected(),
    )


def check_supported(info: DriveInfo, allow_untested: bool = False) -> list[str]:
    """Raise for anything unsafe; return warnings for untested-but-allowed differences."""
    if info.sector_size != C.BLOCK_SIZE:
        raise UnsupportedDevice(f"unexpected sector size {info.sector_size}")
    if info.write_protected:
        raise UnsupportedDevice("the parent unit's drive is write-protected")
    if not info.removable:
        raise UnsupportedDevice("the drive does not report itself as removable")
    if info.sectors == C.TESTED_DEVICE_SECTORS:
        return []
    message = f"this unit's drive has {info.sectors} sectors; the tested unit has {C.TESTED_DEVICE_SECTORS}"
    if not allow_untested:
        raise UnsupportedDevice(
            message + ". Stopping to be safe. Please open an issue with the output of `./babysense-update check`."
        )
    return [message]


def read_sectors(dev: BlockDevice, lba: int, count: int) -> bytes:
    parts, end = [], lba + count
    while lba < end:
        n = min(READ_CHUNK_SECTORS, end - lba)
        chunk = dev.read10(lba, n)
        if len(chunk) != n * C.BLOCK_SIZE:
            raise OSError(f"short read at sector {lba}")
        parts.append(chunk)
        lba += n
    return b"".join(parts)


def read_metadata(dev: BlockDevice) -> tuple[fat16.Geometry, bytes]:
    """Geometry plus the whole metadata region (boot sector, FATs, root directory)."""
    geometry = fat16.parse_geometry(read_sectors(dev, 0, 1))
    return geometry, read_sectors(dev, 0, geometry.first_data_sector)


def summarize(dev: BlockDevice, info: DriveInfo) -> DriveSummary:
    geometry, metadata = read_metadata(dev)
    entries = fat16.root_entries(metadata, geometry)
    label = next((e.display_name for e in entries if e.is_volume_label), "")
    files = tuple(e.display_name for e in entries if not e.is_volume_label)
    return DriveSummary(info, geometry, label, files)
