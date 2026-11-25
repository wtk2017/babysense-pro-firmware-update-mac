"""Plan adding one file to the root folder of a FAT16 volume (pure functions, no I/O).

A plan is computed from the volume's metadata region (boot sector, FATs and root
directory). It only ever uses free clusters and an empty root slot, and it lists
every metadata sector it changes so the caller can enforce an exact allowlist.
"""

from __future__ import annotations

import math
import struct
import time
from dataclasses import dataclass
from typing import Iterable

DIR_ENTRY_SIZE = 32
FAT16_END_OF_CHAIN = 0xFFFF
ATTR_ARCHIVE, ATTR_VOLUME_ID, ATTR_LONG_NAME = 0x20, 0x08, 0x0F
NTRES_LOWERCASE_NAME = 0x18  # how Windows stores an all-lowercase 8.3 name
END_OF_DIRECTORY, DELETED_ENTRY = 0x00, 0xE5
FAT16_MIN_CLUSTERS, FAT16_MAX_CLUSTERS = 4085, 65524


class FatError(ValueError):
    """The volume is not the expected FAT16 layout, or the requested change is unsafe."""


@dataclass(frozen=True)
class Geometry:
    bytes_per_sector: int
    sectors_per_cluster: int
    reserved_sectors: int
    fat_count: int
    fat_sectors: int
    root_entries: int
    total_sectors: int

    @property
    def first_root_sector(self) -> int:
        return self.reserved_sectors + self.fat_count * self.fat_sectors

    @property
    def root_sectors(self) -> int:
        return (self.root_entries * DIR_ENTRY_SIZE + self.bytes_per_sector - 1) // self.bytes_per_sector

    @property
    def first_data_sector(self) -> int:
        return self.first_root_sector + self.root_sectors

    @property
    def cluster_bytes(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster

    @property
    def cluster_count(self) -> int:
        return (self.total_sectors - self.first_data_sector) // self.sectors_per_cluster

    def cluster_to_sector(self, cluster: int) -> int:
        return self.first_data_sector + (cluster - 2) * self.sectors_per_cluster

    def fat_ranges(self) -> list[range]:
        start = self.reserved_sectors
        return [range(start + i * self.fat_sectors, start + (i + 1) * self.fat_sectors) for i in range(self.fat_count)]

    def root_range(self) -> range:
        return range(self.first_root_sector, self.first_data_sector)


@dataclass(frozen=True)
class RootEntry:
    slot: int
    raw_name: bytes
    attributes: int
    first_cluster: int
    size: int

    @property
    def is_volume_label(self) -> bool:
        return bool(self.attributes & ATTR_VOLUME_ID)

    @property
    def display_name(self) -> str:
        if self.is_volume_label:
            return self.raw_name.decode("latin-1").rstrip()
        base = self.raw_name[:8].decode("latin-1").rstrip()
        ext = self.raw_name[8:].decode("latin-1").rstrip()
        return f"{base}.{ext}" if ext else base


@dataclass(frozen=True)
class Plan:
    new_metadata: bytes
    changed_sectors: tuple[int, ...]
    first_cluster: int
    cluster_count: int
    data_sector: int
    data_sectors: int
    root_slot: int
    root_sector: int


def _u16(buf: bytes, offset: int) -> int:
    return struct.unpack_from("<H", buf, offset)[0]


def parse_geometry(metadata: bytes) -> Geometry:
    """Read and sanity-check the boot sector. Only 512-byte-sector FAT16 is accepted."""
    if len(metadata) < 512 or metadata[510:512] != b"\x55\xaa":
        raise FatError("boot sector signature 55AA is missing")
    if metadata[54:59] != b"FAT16":
        raise FatError("volume is not FAT16")
    total = _u16(metadata, 19) or struct.unpack_from("<I", metadata, 32)[0]
    geometry = Geometry(
        _u16(metadata, 11),
        metadata[13],
        _u16(metadata, 14),
        metadata[16],
        _u16(metadata, 22),
        _u16(metadata, 17),
        total,
    )
    _validate(geometry)
    return geometry


def _validate(g: Geometry) -> None:
    if g.bytes_per_sector != 512:
        raise FatError(f"unsupported sector size {g.bytes_per_sector}")
    if g.sectors_per_cluster not in (1, 2, 4, 8, 16, 32, 64, 128):
        raise FatError(f"invalid sectors per cluster {g.sectors_per_cluster}")
    if g.reserved_sectors < 1 or g.fat_count not in (1, 2) or g.fat_sectors < 1:
        raise FatError("invalid reserved/FAT layout")
    if g.root_entries < 16 or g.root_entries % 16:
        raise FatError(f"invalid root entry count {g.root_entries}")
    if not FAT16_MIN_CLUSTERS <= g.cluster_count <= FAT16_MAX_CLUSTERS:
        raise FatError(f"cluster count {g.cluster_count} is not FAT16")
    if g.fat_sectors * g.bytes_per_sector // 2 < g.cluster_count + 2:
        raise FatError("FAT is too small for the cluster count")


def short_name(name: str) -> bytes:
    """8.3 name bytes for a plain, all-lowercase name such as 'firmware.bin'."""
    base, _, ext = name.partition(".")
    valid = 1 <= len(base) <= 8 and len(ext) <= 3 and (base + ext).isalnum() and name == name.lower()
    if not valid or not name.isascii():
        raise FatError(f"{name!r} is not a plain lowercase 8.3 name")
    return base.upper().ljust(8).encode("ascii") + ext.upper().ljust(3).encode("ascii")


def fat_datetime(timestamp: float) -> tuple[int, int]:
    """(date, time) in FAT encoding, local time, 2-second resolution."""
    t = time.localtime(timestamp)
    date = ((max(t.tm_year, 1980) - 1980) << 9) | (t.tm_mon << 5) | t.tm_mday
    clock = (t.tm_hour << 11) | (t.tm_min << 5) | (t.tm_sec // 2)
    return date, clock


def directory_entry(name: str, first_cluster: int, size: int, timestamp: float) -> bytes:
    date, clock = fat_datetime(timestamp)
    return struct.pack(
        "<11sBBBHHHHHHHI",
        short_name(name),
        ATTR_ARCHIVE,
        NTRES_LOWERCASE_NAME,
        0,
        clock,
        date,
        date,
        0,
        clock,
        date,
        first_cluster,
        size,
    )


def parse_entries(raw_directory: bytes) -> list[RootEntry]:
    """Live short-name entries in a run of directory bytes (deleted and long-name parts skipped)."""
    out = []
    for slot in range(len(raw_directory) // DIR_ENTRY_SIZE):
        raw = raw_directory[slot * DIR_ENTRY_SIZE : (slot + 1) * DIR_ENTRY_SIZE]
        if raw[0] == END_OF_DIRECTORY:
            break
        if raw[0] == DELETED_ENTRY or raw[11] == ATTR_LONG_NAME:
            continue
        out.append(RootEntry(slot, raw[:11], raw[11], _u16(raw, 26), struct.unpack_from("<I", raw, 28)[0]))
    return out


def root_entries(metadata: bytes, g: Geometry) -> list[RootEntry]:
    start = g.first_root_sector * g.bytes_per_sector
    return parse_entries(metadata[start : start + g.root_entries * DIR_ENTRY_SIZE])


def _free_root_slot(metadata: bytes, g: Geometry, wanted: bytes) -> int:
    if any(e.raw_name == wanted and not e.is_volume_label for e in root_entries(metadata, g)):
        raise FatError("a file with that name already exists on the volume")
    base = g.first_root_sector * g.bytes_per_sector
    for slot in range(g.root_entries):
        raw = metadata[base + slot * DIR_ENTRY_SIZE : base + (slot + 1) * DIR_ENTRY_SIZE]
        if raw[0] == END_OF_DIRECTORY:
            if any(raw):
                raise FatError(f"root slot {slot} is marked free but is not empty")
            return slot
    raise FatError("the root directory is full")


def free_run(metadata: bytes, g: Geometry, needed: int, last_cluster: int) -> int:
    """First cluster of the lowest run of `needed` free clusters ending at or before last_cluster."""
    fat_offset = g.reserved_sectors * g.bytes_per_sector
    run_start, run_length = 0, 0
    for cluster in range(2, min(g.cluster_count + 1, last_cluster) + 1):
        if _u16(metadata, fat_offset + 2 * cluster) == 0:
            run_start = cluster if run_length == 0 else run_start
            run_length += 1
            if run_length == needed:
                return run_start
        else:
            run_length = 0
    raise FatError(f"no run of {needed} free clusters inside the device")


def with_root_entry(metadata: bytes, g: Geometry, slot: int, entry: bytes) -> bytes:
    offset = g.first_root_sector * g.bytes_per_sector + slot * DIR_ENTRY_SIZE
    return metadata[:offset] + entry + metadata[offset + DIR_ENTRY_SIZE :]


def _with_chain(metadata: bytes, g: Geometry, first: int, count: int) -> bytes:
    out = bytearray(metadata)
    for k in range(count):
        cluster = first + k
        value = FAT16_END_OF_CHAIN if k == count - 1 else cluster + 1
        for fat in g.fat_ranges():
            offset = fat.start * g.bytes_per_sector + 2 * cluster
            if _u16(out, offset) != 0:
                raise FatError(f"cluster {cluster} is not free")
            struct.pack_into("<H", out, offset, value)
    return bytes(out)


def make_plan(metadata: bytes, name: str, size: int, device_sectors: int, timestamp: float | None = None) -> Plan:
    """Plan `name` as one contiguous file of `size` bytes in the lowest free space."""
    g = parse_geometry(metadata)
    if len(metadata) < g.first_data_sector * g.bytes_per_sector:
        raise FatError("metadata region is incomplete")
    if size <= 0:
        raise FatError("file size must be positive")
    needed = math.ceil(size / g.cluster_bytes)
    last_cluster = 1 + (device_sectors - g.first_data_sector) // g.sectors_per_cluster
    first = free_run(metadata, g, needed, last_cluster)
    slot = _free_root_slot(metadata, g, short_name(name))
    entry = directory_entry(name, first, size, time.time() if timestamp is None else timestamp)
    new = with_root_entry(_with_chain(metadata, g, first, needed), g, slot, entry)
    changed = tuple(s for s in range(g.first_data_sector) if _sector(new, s) != _sector(metadata, s))
    plan = Plan(
        new,
        changed,
        first,
        needed,
        g.cluster_to_sector(first),
        needed * g.sectors_per_cluster,
        slot,
        g.first_root_sector + slot * DIR_ENTRY_SIZE // g.bytes_per_sector,
    )
    check_plan_sectors(g, plan, device_sectors)
    return plan


def _sector(buf: bytes, index: int) -> bytes:
    return buf[index * 512 : (index + 1) * 512]


def check_plan_sectors(g: Geometry, plan: Plan, device_sectors: int) -> None:
    """Every changed sector must be a FAT or root-directory sector; data must fit the device."""
    allowed = set(g.root_range()).union(*[set(r) for r in g.fat_ranges()])
    outside = [s for s in plan.changed_sectors if s not in allowed]
    if outside:
        raise FatError(f"plan would change sectors outside the FATs/root directory: {outside}")
    if plan.data_sector + plan.data_sectors > device_sectors:
        raise FatError("planned data would run past the end of the device")


def sector_runs(sectors: Iterable[int]) -> list[tuple[int, int]]:
    """Collapse sector numbers into (start, count) runs."""
    runs: list[tuple[int, int]] = []
    for s in sorted(sectors):
        if runs and runs[-1][0] + runs[-1][1] == s:
            runs[-1] = (runs[-1][0], runs[-1][1] + 1)
        else:
            runs.append((s, 1))
    return runs
