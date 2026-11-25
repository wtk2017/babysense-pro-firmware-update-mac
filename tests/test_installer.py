import pytest

from babysense_mac import device, fat16, installer, simulate
from babysense_mac.scsi import BulkOnlyScsi, DeviceGone
from tests.fakes import FakeBotDevice, FakeClock, PlainDisk, VirtualDrive, make_firmware

pytestmark = pytest.mark.unit
FIRMWARE = make_firmware(300_000)
BIG_FIRMWARE = make_firmware(2_500_000)
BOT_OPTIONS = ("disconnect_after_bytes", "sectors", "sync_error", "write_error_after_bytes")
INSTALL_OPTIONS = ("expect_capture", "allow_untested_device")


def run(storage, clock=None, firmware=FIRMWARE, **kwargs):
    bot = FakeBotDevice(storage, **{k: v for k, v in kwargs.items() if k in BOT_OPTIONS})
    said = []
    try:
        result = installer.install(
            BulkOnlyScsi(bot, 0x8C, 0x0D, allow_writes=True),
            firmware,
            said.append,
            clock=clock or FakeClock(),
            timestamp=0,
            **{k: v for k, v in kwargs.items() if k in INSTALL_OPTIONS},
        )
    finally:
        run.last_bot = bot
    return result, said, bot


def test_parent_unit_stores_the_firmware_when_written_in_windows_order():
    clock = FakeClock()
    drive = VirtualDrive(clock)
    result, said, bot = run(drive, clock)
    assert drive.received() == FIRMWARE
    assert drive.discarded == 0
    assert (result.first_cluster, result.data_sector) == (2, 520)
    assert 0.1 < result.megabytes_per_second < 0.2
    assert result.flush.startswith("not supported")
    assert any("Step 4 of 4" in line for line in said) and any("Finishing" in line for line in said)
    assert bot.commands[-2:] == [0x35, 0x03]


def test_write_order_is_entry_then_fat_then_size_then_data():
    clock = FakeClock()
    drive = VirtualDrive(clock)
    run(drive, clock)
    log = drive.write_log
    assert log[0] == 488 and log[1:3] == [4, 246] and log[3] == 488
    assert all(lba >= 520 for lba in log[4:])


def test_stops_before_sending_data_if_the_unit_does_not_register_the_file():
    drive = VirtualDrive(FakeClock(), registers=False)
    with pytest.raises(installer.InstallAborted, match="did not register firmware.bin.*Do NOT press RESET"):
        run(drive)
    assert all(lba < 520 for lba in drive.write_log)


def test_too_fast_means_discarded_and_must_not_reset():
    with pytest.raises(installer.InstallAborted, match="discarded some of it.*Do NOT press RESET"):
        run(PlainDisk())


def test_partial_discard_is_caught_mid_transfer():
    clock = FakeClock()
    drive = VirtualDrive(clock, keep_bytes=150_000)
    with pytest.raises(installer.InstallAborted, match="discarded some of it"):
        run(drive, clock, firmware=BIG_FIRMWARE)
    assert 0x35 not in run.last_bot.commands
    assert drive.discarded < len(BIG_FIRMWARE)  # stopped early, not after sending everything


def test_plain_disk_works_when_capture_speed_is_not_expected():
    disk = PlainDisk()
    result, _, _ = run(disk, expect_capture=False)
    assert disk.read(520, len(FIRMWARE) // 512) == FIRMWARE[: (len(FIRMWARE) // 512) * 512]
    assert result.clusters == 37


def test_disconnect_mid_transfer_says_do_not_reset():
    clock = FakeClock()
    with pytest.raises(installer.InstallAborted, match=r"stopped after 0\.\d MB.*Do NOT press RESET"):
        run(VirtualDrive(clock), clock, disconnect_after_bytes=150_000)
    assert 0x35 not in run.last_bot.commands


@pytest.mark.parametrize("error, text", [(ValueError("boom"), "boom"), (KeyboardInterrupt(), "KeyboardInterrupt")])
def test_any_failure_after_the_first_write_says_do_not_reset(error, text):
    clock = FakeClock()
    with pytest.raises(installer.InstallAborted, match=f"{text}.*Do NOT press RESET"):
        run(VirtualDrive(clock), clock, write_error_after_bytes=(150_000, error))


def test_failures_before_any_write_are_reported_as_they_are():
    with pytest.raises(device.UnsupportedDevice):
        run(VirtualDrive(FakeClock()), sectors=1_000_000)


def test_untested_device_works_only_when_allowed():
    clock = FakeClock()
    result, said, _ = run(VirtualDrive(clock), clock, sectors=1_000_000, allow_untested_device=True)
    assert result.warnings and said[0].startswith("Warning:")


def test_disconnect_while_finishing_is_an_interrupted_update():
    clock = FakeClock()
    with pytest.raises(installer.InstallAborted, match="Do NOT press RESET"):
        run(VirtualDrive(clock), clock, sync_error=DeviceGone("gone at the very end"))


def test_write_guard_allows_exactly_the_plan():
    plan = fat16.make_plan(simulate.device_metadata(), "firmware.bin", 10_000, 990_400)
    allowed = installer.plan_ranges(plan)
    assert allowed[-1] == (520, 552) and (4, 5) in allowed and (488, 489) in allowed
    disk = PlainDisk()
    guard = installer.WriteGuard(BulkOnlyScsi(FakeBotDevice(disk), 0x8C, 0x0D, allow_writes=True), allowed)
    guard.write(520, bytes(512))
    assert guard.attempted and guard.bytes_written == 512
    for lba, data, message in (
        (0, bytes(512), "not in the plan"),  # boot sector
        (300, bytes(512), "not in the plan"),  # a FAT sector the plan doesn't change
        (551, bytes(1024), "not in the plan"),  # runs past the planned data
        (520, bytes(100), "whole number of sectors"),
        (520, b"", "whole number of sectors"),
    ):
        with pytest.raises(PermissionError, match=message):
            guard.write(lba, data)
    assert disk.write_log == [520]
