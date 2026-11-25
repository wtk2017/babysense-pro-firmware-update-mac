"""A disk-image stand-in for the parent unit's drive, to try the tool without hardware.

`create_device_image` lays out a FAT16 volume exactly like the real parent unit
presents it (same boot sector values, volume label and version-marker entry).
`ImageDevice` exposes that image through the same interface as the USB device.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

from . import constants as C
from . import fat16

DEVICE_TOTAL_SECTORS = 990_931  # what the parent unit's boot sector claims
RESERVED, FAT_COUNT, FAT_SECTORS, ROOT_ENTRIES, SECTORS_PER_CLUSTER = 4, 2, 242, 512, 16
VOLUME_LABEL_ENTRY = b"SN93701PU  "
VERSION_MARKER_ENTRY = b"01.00.01051"


def device_metadata(total_sectors: int = DEVICE_TOTAL_SECTORS) -> bytes:
    """Boot sector + two FATs + root directory, matching the real parent unit."""
    boot = bytearray(C.BLOCK_SIZE)
    boot[0:11] = b"\xeb\x3c\x90MSDOS5.0"
    small_total = total_sectors if total_sectors < 0x10000 else 0
    large_total = 0 if small_total else total_sectors
    struct.pack_into(
        "<HBHBHHBHHHII",
        boot,
        11,
        C.BLOCK_SIZE,
        SECTORS_PER_CLUSTER,
        RESERVED,
        FAT_COUNT,
        ROOT_ENTRIES,
        small_total,
        0xF8,
        FAT_SECTORS,
        63,
        255,
        0,
        large_total,
    )
    boot[36:39] = b"\x80\x00\x29"
    boot[43:62] = b"NO NAME    FAT16   "
    boot[510:512] = b"\x55\xaa"
    first_root = RESERVED + FAT_COUNT * FAT_SECTORS
    root_sectors = ROOT_ENTRIES * 32 // C.BLOCK_SIZE
    metadata = bytearray((first_root + root_sectors) * C.BLOCK_SIZE)
    metadata[: C.BLOCK_SIZE] = boot
    for fat in range(FAT_COUNT):
        offset = (RESERVED + fat * FAT_SECTORS) * C.BLOCK_SIZE
        metadata[offset : offset + 4] = b"\xf8\xff\xff\xff"
    root = first_root * C.BLOCK_SIZE
    metadata[root : root + 12] = VOLUME_LABEL_ENTRY + b"\x08"
    metadata[root + 32 : root + 44] = VERSION_MARKER_ENTRY + b"\x20"
    return bytes(metadata)


def create_device_image(path: Path, file_sectors: int = DEVICE_TOTAL_SECTORS) -> None:
    """A sparse image file holding a fresh copy of the parent unit's drive layout."""
    with open(path, "wb") as handle:
        handle.truncate(file_sectors * C.BLOCK_SIZE)
        handle.write(device_metadata())


def looks_like_device_image(path: Path) -> bool:
    """True only for an image laid out like the parent unit (so `simulate` never edits other disks)."""
    with open(path, "rb") as handle:
        head = handle.read(len(device_metadata()))
    try:
        geometry = fat16.parse_geometry(head)
    except fat16.FatError:
        return False
    if len(head) < geometry.first_data_sector * C.BLOCK_SIZE:
        return False
    labels = [e.raw_name for e in fat16.root_entries(head, geometry) if e.is_volume_label]
    return labels == [VOLUME_LABEL_ENTRY]


class ImageDevice:
    """Implements device.BlockDevice on top of an image file."""

    def __init__(self, path: Path, sectors: int = C.TESTED_DEVICE_SECTORS) -> None:
        self._handle = open(path, "r+b")  # noqa: SIM115 - closed in close()
        self._sectors = sectors

    def inquiry(self) -> bytes:
        return b"\x00\x80\x06\x12\x1f\x00\x00\x00" + C.SCSI_VENDOR + C.SCSI_PRODUCT_PREFIX.ljust(16, b"\0") + b"rev1"

    def test_unit_ready(self) -> bool:
        return True

    def read_capacity(self) -> tuple[int, int]:
        return self._sectors, C.BLOCK_SIZE

    def write_protected(self) -> bool:
        return False

    def _check(self, lba: int, count: int) -> None:
        if lba < 0 or count <= 0 or lba + count > self._sectors:
            raise OSError(f"sectors {lba}..{lba + count - 1} are outside the device")

    def read10(self, lba: int, count: int, block: int = 512) -> bytes:
        self._check(lba, count)
        self._handle.seek(lba * block)
        return self._handle.read(count * block).ljust(count * block, b"\0")

    def write10(self, lba: int, data: bytes, block: int = 512) -> None:
        self._check(lba, len(data) // block)
        self._handle.seek(lba * block)
        self._handle.write(data)

    def synchronize_cache(self) -> str:
        self._handle.flush()
        os.fsync(self._handle.fileno())
        return "ok"

    def close(self) -> None:
        self._handle.close()

    def __enter__(self) -> ImageDevice:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
