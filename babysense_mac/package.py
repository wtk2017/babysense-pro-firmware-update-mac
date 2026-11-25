"""Read the firmware image out of Babysense's updater package without running it.

The package (.msix) is a zip. Its BabysenseProFirmwareUpdate.Core.dll embeds the
firmware image and a SHA-256 "pin" for it as .NET manifest resources. We check
the package identity and publisher, the pin, and that the updater still copies
the image to the device as firmware.bin. The pin sits inside the same package,
so it proves integrity, not origin; origin comes from Microsoft's checksum and,
by default, from the tested SHA-256 list in constants.TESTED_FIRMWARE.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import stat
import struct
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree

from . import constants as C

MAX_MEMBER_BYTES = 128 * 1024 * 1024
MAX_RESOURCES = 64
MAX_PIN_BYTES = 4096
PIN_PATTERN = re.compile(rb"([0-9a-fA-F]{64})\s+\*?([^\s*]+\.bin)")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
VERSION_PATTERN = re.compile(r"(?<![A-Za-z0-9])V(\d{2})(\d{2})(?![A-Za-z0-9])")
APPX_NAMESPACE = "{http://schemas.microsoft.com/appx/manifest/foundation/windows10}"
CLR_DIRECTORY_INDEX = 14
CORRUPT_PACKAGE_ERRORS = (zipfile.BadZipFile, zlib.error, RuntimeError, EOFError, ElementTree.ParseError)


class PackageError(RuntimeError):
    """The package is not the expected Babysense updater, or its contents fail a check."""


class UntestedFirmware(PackageError):
    """The firmware is genuine (matches its pin) but has not been tested with this tool."""


@dataclass(frozen=True)
class Manifest:
    identity: str
    publisher: str
    version: str
    architecture: str


@dataclass(frozen=True)
class Firmware:
    data: bytes
    sha256: str
    file_name: str
    version: str
    tested: bool
    updater_version: str


def read_manifest(archive: zipfile.ZipFile) -> Manifest:
    root = ElementTree.fromstring(_member(archive, "AppxManifest.xml"))  # noqa: S314 - verified package, size-capped
    identity = root.find(f"{APPX_NAMESPACE}Identity")
    if identity is None:
        raise PackageError("the package manifest has no identity")
    return Manifest(
        identity.get("Name", ""),
        identity.get("Publisher", ""),
        identity.get("Version", ""),
        identity.get("ProcessorArchitecture", ""),
    )


def _member(archive: zipfile.ZipFile, name: str) -> bytes:
    try:
        info = archive.getinfo(name)
    except KeyError as exc:
        raise PackageError(f"the package has no {name}") from exc
    if info.file_size > MAX_MEMBER_BYTES:
        raise PackageError(f"{name} is unexpectedly large")
    return archive.read(info)


def _unpack(fmt: str, data: bytes, offset: int) -> tuple[int, ...]:
    if offset < 0 or offset + struct.calcsize(fmt) > len(data):
        raise PackageError("the DLL is truncated or malformed")
    return struct.unpack_from(fmt, data, offset)


def _sections(pe: bytes, pe_offset: int) -> list[tuple[int, int, int]]:
    count, optional_size = _unpack("<H", pe, pe_offset + 6)[0], _unpack("<H", pe, pe_offset + 20)[0]
    table = pe_offset + 24 + optional_size
    sections = []
    for i in range(count):
        virtual_size, virtual_address, raw_size, raw_offset = _unpack("<IIII", pe, table + i * 40 + 8)
        sections.append((virtual_address, max(virtual_size, raw_size), raw_offset))
    return sections


def _rva_to_offset(sections: list[tuple[int, int, int]], rva: int) -> int:
    for virtual_address, size, raw_offset in sections:
        if virtual_address <= rva < virtual_address + size:
            return rva - virtual_address + raw_offset
    raise PackageError("the DLL points outside its own sections")


def _resource_block(pe: bytes) -> tuple[int, int]:
    pe_offset = _unpack("<I", pe, 0x3C)[0]
    if pe[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise PackageError("the DLL is not a PE file")
    magic = _unpack("<H", pe, pe_offset + 24)[0]
    if magic not in (0x10B, 0x20B):
        raise PackageError("unknown PE optional header")
    directories = pe_offset + 24 + (96 if magic == 0x10B else 112)
    clr_rva = _unpack("<I", pe, directories + CLR_DIRECTORY_INDEX * 8)[0]
    sections = _sections(pe, pe_offset)
    resources_rva, resources_size = _unpack("<II", pe, _rva_to_offset(sections, clr_rva) + 24)
    if not resources_rva:
        return 0, 0
    start = _rva_to_offset(sections, resources_rva)
    if start + resources_size > len(pe):
        raise PackageError("the DLL's resources run past the end of the file")
    return start, start + resources_size


def clr_resources(pe: bytes) -> list[bytes]:
    """All .NET manifest resources of a PE file, in order (length-prefixed blobs)."""
    position, end = _resource_block(pe)
    blobs: list[bytes] = []
    while position + 4 <= end:
        length = _unpack("<I", pe, position)[0]
        if position + 4 + length > end:
            break
        if len(blobs) == MAX_RESOURCES:
            raise PackageError("the DLL has an implausible number of resources")
        blobs.append(pe[position + 4 : position + 4 + length])
        position += 4 + length
    return blobs


def _pin(resources: list[bytes]) -> tuple[str, str]:
    pins = [m for m in (PIN_PATTERN.search(r) for r in resources if len(r) <= MAX_PIN_BYTES) if m]
    if len(pins) != 1:
        raise PackageError(f"expected one firmware checksum pin, found {len(pins)}")
    return pins[0].group(1).decode().lower(), pins[0].group(2).decode("utf-8", "replace")


def _read_package(msix: bytes) -> tuple[Manifest, bytes]:
    try:
        with zipfile.ZipFile(io.BytesIO(msix)) as archive:
            manifest = read_manifest(archive)
            dll = _member(archive, C.CORE_DLL_NAME)
    except PackageError:
        raise
    except CORRUPT_PACKAGE_ERRORS as exc:
        raise PackageError(f"the updater package is damaged ({exc}); delete the cached copy and try again") from exc
    if (manifest.identity, manifest.publisher) != (C.STORE_PACKAGE_IDENTITY, C.STORE_PUBLISHER):
        raise PackageError(f"not Babysense's updater package ({manifest.identity}, {manifest.publisher})")
    return manifest, dll


def extract_firmware(msix: bytes, allow_untested: bool = False) -> Firmware:
    """The verified firmware image inside the (already checksum-verified) package bytes."""
    manifest, dll = _read_package(msix)
    if C.DEVICE_FIRMWARE_NAME.encode("utf-16-le") not in dll:
        raise PackageError("Babysense's updater no longer uses firmware.bin; this tool needs an update")
    resources = clr_resources(dll)
    images = [r for r in resources if r.startswith(C.FIRMWARE_HEADER)]
    if len(images) != 1:
        raise PackageError(f"expected one embedded firmware image, found {len(images)}")
    pinned_sha256, file_name = _pin(resources)
    actual = hashlib.sha256(images[0]).hexdigest()
    if actual != pinned_sha256:
        raise PackageError("the embedded firmware does not match its checksum pin")
    match = VERSION_PATTERN.search(file_name)
    version = f"V{match.group(1)}{match.group(2)}" if match else "unknown"
    tested = actual in C.TESTED_FIRMWARE
    if not tested and not allow_untested:
        raise UntestedFirmware(
            f"Babysense's updater now contains firmware {version} (SHA-256 {actual[:16]}...), which this tool "
            "has not been tested with. Re-run with --allow-untested-firmware to use it anyway."
        )
    return Firmware(images[0], actual, file_name, version, tested, manifest.version)


def load_verified(path: Path, sha256: str, owners: set[int] | None = None) -> bytes:
    """Read a cached firmware file and re-check it (the privileged step trusts nothing on disk)."""
    if not SHA256_PATTERN.fullmatch(sha256):
        raise PackageError("the expected firmware checksum is malformed")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise PackageError(f"cannot open the firmware file ({exc.strerror})") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > C.MAX_FIRMWARE_BYTES:
            raise PackageError("the firmware file is not a regular file of a plausible size")
        if owners is not None and info.st_uid not in owners:
            raise PackageError("the firmware file belongs to another user")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(C.MAX_FIRMWARE_BYTES + 1)
    finally:
        os.close(descriptor)
    if hashlib.sha256(data).hexdigest() != sha256:
        raise PackageError("the firmware file on disk does not match the expected checksum")
    if not data.startswith(C.FIRMWARE_HEADER):
        raise PackageError("the firmware file does not start with the expected SONiX header")
    return data
