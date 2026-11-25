import struct

import pytest

from babysense_mac import scsi
from tests.fakes import FakeBotDevice, PlainDisk

pytestmark = pytest.mark.unit
EP_IN, EP_OUT = 0x8C, 0x0D


def session(device, writes=False):
    return scsi.BulkOnlyScsi(device, EP_IN, EP_OUT, allow_writes=writes)


def test_identifies_and_reads_capacity():
    dev = FakeBotDevice(PlainDisk())
    s = session(dev)
    assert s.inquiry()[8:16] == b"SONiXTek"
    assert s.read_capacity() == (990_400, 512)
    assert s.test_unit_ready() is True
    assert s.write_protected() is False
    assert s.read10(0, 1)[510:512] == b"\x55\xaa"


def test_read_only_session_cannot_write_and_sends_nothing():
    dev = FakeBotDevice(PlainDisk())
    with pytest.raises(PermissionError):
        session(dev).write10(600, bytes(512))
    with pytest.raises(PermissionError):
        session(dev).synchronize_cache()
    assert dev.commands == []


def test_unknown_opcodes_are_refused_even_with_writes():
    with pytest.raises(PermissionError):
        session(FakeBotDevice(PlainDisk()), writes=True).command(bytes([0x04, 0, 0, 0, 0, 0]))  # FORMAT UNIT
    with pytest.raises(PermissionError):
        session(FakeBotDevice(PlainDisk())).command(b"")


def test_write_session_writes_and_validates_length():
    disk = PlainDisk()
    s = session(FakeBotDevice(disk), writes=True)
    s.write10(600, b"\x11" * 1024)
    assert disk.read(600, 2) == b"\x11" * 1024
    with pytest.raises(ValueError):
        s.write10(600, b"\x11" * 100)
    with pytest.raises(ValueError):
        s.command(bytes([0x28]) + bytes(9), data_in=512, payload=b"x")


def test_command_block_wrapper_fields():
    sent = []

    class Spy(FakeBotDevice):
        def bulk_out(self, endpoint, data, timeout_ms):
            sent.append((endpoint, data))
            super().bulk_out(endpoint, data, timeout_ms)

    s = session(Spy(PlainDisk()))
    s.inquiry()
    s.inquiry()
    first, second = sent[0][1], sent[1][1]
    assert sent[0][0] == EP_OUT and len(first) == 31
    signature, tag, length, flags, lun, cdb_len = struct.unpack_from("<IIIBBB", first)
    assert (signature, length, flags, lun, cdb_len, first[15]) == (scsi.CBW_SIGNATURE, 36, 0x80, 0, 6, 0x12)
    assert struct.unpack_from("<I", second, 4)[0] == tag + 1


def test_data_stall_is_cleared_reported_and_status_still_read():
    dev = FakeBotDevice(PlainDisk(), stall_data_for=(0x12,))
    done = session(dev).command(bytes([0x12, 0, 0, 0, 36, 0]), data_in=36)
    assert (done.status, done.data, done.data_stalled, dev.cleared) == (0, b"", True, [EP_IN])


def test_status_stall_is_cleared_and_retried():
    dev = FakeBotDevice(PlainDisk(), stall_status_once=True)
    assert session(dev).test_unit_ready() is True
    assert dev.cleared == [EP_IN]


def test_failed_command_raises_with_sense():
    dev = FakeBotDevice(PlainDisk(), ready_after=5)
    s = session(dev)
    assert s.test_unit_ready() is False
    sense = s.request_sense()
    assert (sense.key, sense.asc, sense.ascq) == (2, 4, 1)
    assert "sense key=0x2" in str(sense)
    with pytest.raises(scsi.ScsiError, match="0x25"):
        session(FailingCapacity(PlainDisk())).read_capacity()


class FailingCapacity(FakeBotDevice):
    def _execute(self, cdb):
        if cdb[0] == 0x25:
            return self._fail(3, 0x11, 0)
        return super()._execute(cdb)


def test_request_sense_without_data_returns_none():
    class NoSense(FakeBotDevice):
        def _execute(self, cdb):
            return (1, b"") if cdb[0] == 0x03 else super()._execute(cdb)

    assert session(NoSense(PlainDisk())).request_sense() is None


def test_synchronize_cache_reports_not_supported_like_the_real_unit():
    result = session(FakeBotDevice(PlainDisk()), writes=True).synchronize_cache()
    assert result.startswith("not supported") and "0x5" in result


@pytest.mark.parametrize(
    "status_block, message",
    [
        (b"\x00" * 5, "status block has 5 bytes"),
        (struct.pack("<IIIB", 0xDEADBEEF, 1, 0, 0), "out of sync"),
    ],
)
def test_bad_status_blocks_raise(status_block, message):
    class Broken(FakeBotDevice):
        def bulk_in(self, endpoint, length, timeout_ms):
            return status_block

    with pytest.raises(scsi.TransportError, match=message):
        session(Broken(PlainDisk())).test_unit_ready()


def test_write_rejected_with_failure_status_clears_the_out_endpoint():
    class RejectsWrites(FakeBotDevice):
        def _receive_write(self, data):
            self._expect_write = None
            self._status, _ = self._fail(5, 0x21, 0)
            raise scsi.StallError("rejected")

    dev = RejectsWrites(PlainDisk())
    with pytest.raises(scsi.ScsiError):
        session(dev, writes=True).write10(600, bytes(512))
    assert EP_OUT in dev.cleared


def test_write_that_stalls_but_reports_success_is_a_failure():
    dev = FakeBotDevice(PlainDisk(), stall_writes_but_report_success=True)
    with pytest.raises(scsi.TransportError, match="did not accept all data"):
        session(dev, writes=True).write10(600, bytes(512))
    assert EP_OUT in dev.cleared


def test_write_with_residue_is_a_failure():
    dev = FakeBotDevice(PlainDisk(), residue_for={0x2A: 512})
    with pytest.raises(scsi.TransportError, match="bytes not taken: 512"):
        session(dev, writes=True).write10(600, bytes(1024))


def test_short_reads_are_failures():
    with pytest.raises(scsi.TransportError, match="short read"):
        session(FakeBotDevice(PlainDisk(), residue_for={0x28: 512})).read10(0, 1)

    class ShortDisk(PlainDisk):
        def read(self, lba, count):
            return bytes(100)

    with pytest.raises(scsi.TransportError, match="short read"):
        session(FakeBotDevice(ShortDisk())).read10(0, 1)

    class ShortCapacity(FakeBotDevice):
        def _execute(self, cdb):
            return (0, b"\x00\x0f") if cdb[0] == 0x25 else super()._execute(cdb)

    with pytest.raises(scsi.TransportError, match="short answer"):
        session(ShortCapacity(PlainDisk())).read_capacity()
