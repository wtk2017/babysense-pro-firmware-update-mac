"""Build small synthetic stand-ins for Babysense's updater package (no Babysense files in this repo)."""

from __future__ import annotations

import hashlib
import struct
import zipfile
from pathlib import Path

from babysense_mac import constants as C

SECTION_RVA, RAW_OFFSET, PE_OFFSET = 0x2000, 0x400, 0x80


def build_pe(resources: list[bytes], extra: bytes = b"", magic: int = 0x20B) -> bytes:
    """A minimal PE32+ file with a CLR header whose manifest resources are `resources`."""
    blob = b"".join(struct.pack("<I", len(r)) + r for r in resources)
    clr = bytearray(72)
    struct.pack_into("<I", clr, 0, 72)
    struct.pack_into("<II", clr, 24, SECTION_RVA + 72 if resources else 0, len(blob))
    section = bytes(clr) + blob + extra
    header = bytearray(RAW_OFFSET)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, PE_OFFSET)
    header[PE_OFFSET : PE_OFFSET + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", header, PE_OFFSET + 4, 0x8664, 1, 0, 0, 0, 240, 0x2022)
    optional = PE_OFFSET + 24
    struct.pack_into("<H", header, optional, magic)
    directories = optional + (96 if magic == 0x10B else 112)
    struct.pack_into("<II", header, directories + 14 * 8, SECTION_RVA, 72)
    table = optional + 240
    header[table : table + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", header, table + 8, len(section), SECTION_RVA, len(section), RAW_OFFSET)
    return bytes(header) + section


def manifest(identity: str = C.STORE_PACKAGE_IDENTITY, publisher: str = C.STORE_PUBLISHER) -> bytes:
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">'
        f'<Identity Name="{identity}" Publisher="{publisher}" Version="1.0.74.0" ProcessorArchitecture="x64"/>'
        "</Package>"
    ).encode()


def pin_for(image: bytes, name: str = "Babysense_pro_software_update_V0207.bin") -> bytes:
    return f"{hashlib.sha256(image).hexdigest()} *{name}\n".encode()


def build_msix(
    path: Path,
    image: bytes,
    resources: list[bytes] | None = None,
    marker: bool = True,
    manifest_xml: bytes | None = None,
    dll: bytes | None = None,
) -> Path:
    if resources is None:
        resources = [image, pin_for(image)]
    extra = C.DEVICE_FIRMWARE_NAME.encode("utf-16-le") if marker else b""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AppxManifest.xml", manifest_xml or manifest())
        archive.writestr(C.CORE_DLL_NAME, dll if dll is not None else build_pe(resources, extra))
    return path
