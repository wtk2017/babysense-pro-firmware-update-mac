import struct
import time

import pytest

from babysense_mac import fat16, simulate

pytestmark = pytest.mark.unit
META = simulate.device_metadata()
DEVICE_SECTORS = 990_400


def test_geometry_matches_the_real_parent_unit():
    g = fat16.parse_geometry(META)
    assert (g.first_root_sector, g.first_data_sector, g.cluster_count, g.cluster_bytes) == (488, 520, 61900, 8192)
    assert g.cluster_to_sector(2) == 520
    assert [r.start for r in g.fat_ranges()] == [4, 246]
    assert g.root_range() == range(488, 520)


@pytest.mark.parametrize(
    "patch, message",
    [
        ((510, b"\0\0"), "signature"),
        ((54, b"FAT32"), "not FAT16"),
        ((11, struct.pack("<H", 4096)), "sector size"),
        ((13, b"\x03"), "sectors per cluster"),
        ((16, b"\x03"), "reserved/FAT"),
        ((17, struct.pack("<H", 10)), "root entry count"),
        ((22, struct.pack("<H", 1)), "FAT is too small"),
    ],
)
def test_geometry_rejects_unexpected_layouts(patch, message):
    offset, value = patch
    broken = META[:offset] + value + META[offset + len(value) :]
    with pytest.raises(fat16.FatError, match=message):
        fat16.parse_geometry(broken)


def test_geometry_rejects_non_fat16_cluster_counts():
    tiny = META[:19] + struct.pack("<H", 2000) + META[21:32] + bytes(4) + META[36:]
    with pytest.raises(fat16.FatError, match="not FAT16"):
        fat16.parse_geometry(tiny)


@pytest.mark.parametrize("name", ["FIRMWARE.BIN", "toolongname.bin", "a.b.c", "fïrmware.bin", "x.long", ""])
def test_short_name_rejects_anything_but_plain_lowercase_8_3(name):
    with pytest.raises(fat16.FatError):
        fat16.short_name(name)


def test_short_name_and_entry_layout_match_windows():
    assert fat16.short_name("firmware.bin") == b"FIRMWAREBIN"
    assert fat16.short_name("readme") == b"README     "
    ts = time.mktime((2026, 11, 25, 10, 30, 42, 0, 0, -1))
    entry = fat16.directory_entry("firmware.bin", 2, 32_374_784, ts)
    assert len(entry) == 32
    assert entry[:11] == b"FIRMWAREBIN" and entry[11] == 0x20 and entry[12] == 0x18
    date, clock = fat16.fat_datetime(ts)
    assert date == ((2026 - 1980) << 9) | (11 << 5) | 25 and clock == (10 << 11) | (30 << 5) | 21
    assert struct.unpack_from("<HI", entry, 26) == (2, 32_374_784)


def test_root_entries_show_label_and_version_marker():
    entries = fat16.root_entries(META, fat16.parse_geometry(META))
    assert [(e.display_name, e.is_volume_label) for e in entries] == [("SN93701PU", True), ("01.00.01.051", False)]


def test_parse_entries_skips_deleted_and_long_name_parts():
    deleted = b"\xe5" + b"OLD     TXT"[1:] + b"\x20" + bytes(20)
    long_name = b"\x41" + bytes(10) + b"\x0f" + bytes(20)
    plain = b"README     " + b"\x20" + bytes(20)
    entries = fat16.parse_entries(deleted + long_name + plain + bytes(32))
    assert [e.display_name for e in entries] == ["README"]


def test_plan_uses_lowest_free_clusters_and_only_fat_and_root_sectors():
    plan = fat16.make_plan(META, "firmware.bin", 32_374_784, DEVICE_SECTORS, timestamp=0)
    assert (plan.first_cluster, plan.cluster_count, plan.data_sector, plan.root_slot) == (2, 3952, 520, 2)
    assert plan.changed_sectors == tuple(range(4, 20)) + tuple(range(246, 262)) + (488,)
    g = fat16.parse_geometry(plan.new_metadata)
    fat = plan.new_metadata[4 * 512 :]
    assert struct.unpack_from("<H", fat, 2 * 2)[0] == 3
    assert struct.unpack_from("<H", fat, 2 * 3953)[0] == 0xFFFF
    assert fat16.root_entries(plan.new_metadata, g)[2].display_name == "FIRMWARE.BIN"


def test_plan_skips_allocated_clusters():
    used = bytearray(META)
    for fat_start in (4, 246):
        struct.pack_into("<H", used, fat_start * 512 + 4, 0xFFFF)
    plan = fat16.make_plan(bytes(used), "firmware.bin", 10_000, DEVICE_SECTORS)
    assert plan.first_cluster == 3


def test_plan_refuses_existing_file_full_root_and_no_space():
    plan = fat16.make_plan(META, "firmware.bin", 10_000, DEVICE_SECTORS)
    with pytest.raises(fat16.FatError, match="already exists"):
        fat16.make_plan(plan.new_metadata, "firmware.bin", 10_000, DEVICE_SECTORS)
    full = bytearray(META)
    root = 488 * 512
    for slot in range(512):
        full[root + slot * 32 : root + slot * 32 + 12] = b"FILE%04dBIN\x20" % slot
    with pytest.raises(fat16.FatError, match="full"):
        fat16.make_plan(bytes(full), "firmware.bin", 10_000, DEVICE_SECTORS)
    with pytest.raises(fat16.FatError, match="no run"):
        fat16.make_plan(META, "firmware.bin", 100_000, 600)
    with pytest.raises(fat16.FatError, match="positive"):
        fat16.make_plan(META, "firmware.bin", 0, DEVICE_SECTORS)
    with pytest.raises(fat16.FatError, match="incomplete"):
        fat16.make_plan(META[:1024], "firmware.bin", 10_000, DEVICE_SECTORS)


def test_plan_refuses_a_dirty_free_slot():
    dirty = bytearray(META)
    dirty[488 * 512 + 64 + 5] = 0x41  # slot 2 starts with 0x00 but is not empty
    with pytest.raises(fat16.FatError, match="not empty"):
        fat16.make_plan(bytes(dirty), "firmware.bin", 10_000, DEVICE_SECTORS)


def test_plan_sector_check_rejects_boot_sector_and_overflow():
    g = fat16.parse_geometry(META)
    plan = fat16.make_plan(META, "firmware.bin", 10_000, DEVICE_SECTORS)
    with pytest.raises(fat16.FatError, match="outside"):
        fat16.check_plan_sectors(g, fat16.Plan(plan.new_metadata, (0,), 2, 2, 520, 32, 2, 488), DEVICE_SECTORS)
    with pytest.raises(fat16.FatError, match="past the end"):
        fat16.check_plan_sectors(g, plan, 530)


def test_with_chain_refuses_used_clusters():
    g = fat16.parse_geometry(META)
    plan = fat16.make_plan(META, "firmware.bin", 10_000, DEVICE_SECTORS)
    with pytest.raises(fat16.FatError, match="not free"):
        fat16._with_chain(plan.new_metadata, g, 2, 1)


def test_sector_runs():
    assert fat16.sector_runs([7, 4, 5, 6, 488, 246]) == [(4, 4), (246, 1), (488, 1)]
    assert fat16.sector_runs([]) == []
