"""Test doubles that reproduce the Babysense Pro parent unit as observed on real hardware."""

from __future__ import annotations

import struct

from babysense_mac import constants as C
from babysense_mac import fat16, simulate
from babysense_mac.scsi import CBW_SIGNATURE, CSW_SIGNATURE, DeviceGone, StallError

# The parent unit's real USB configuration descriptor (bulk IN 0x8C, bulk OUT 0x0D).
CONFIG_DESCRIPTOR = bytes.fromhex("0902200001010080fa" "090400000208065000" "07058c02000200" "07050d02000200")
FIRMWARE_SECTOR_SECONDS = 512 / 125_000  # the unit stores ~0.125 MB/s


def make_firmware(size: int = 300_000) -> bytes:
    body = bytes((i * 7 + 3) % 251 for i in range(size - len(C.FIRMWARE_HEADER)))
    return C.FIRMWARE_HEADER + body


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class PlainDisk:
    """An ordinary drive: stores everything, instantly."""

    def __init__(self, sectors: int = C.TESTED_DEVICE_SECTORS) -> None:
        self.sectors = sectors
        self.blocks: dict[int, bytes] = {}
        meta = simulate.device_metadata()
        for s in range(len(meta) // 512):
            self.blocks[s] = meta[s * 512 : (s + 1) * 512]
        self.write_log: list[int] = []

    def read(self, lba: int, count: int) -> bytes:
        return b"".join(self.blocks.get(s, bytes(512)) for s in range(lba, lba + count))

    def write(self, lba: int, data: bytes) -> None:
        self.write_log.append(lba)
        for i in range(len(data) // 512):
            self.blocks[lba + i] = data[i * 512 : (i + 1) * 512]


class VirtualDrive:
    """The parent unit's firmware-generated drive, as observed:

    * FAT writes are ignored; the FAT always reads back as it was generated.
    * The root directory is one buffer: writes replace it, every root sector reads it.
    * Data written into the clusters of a registered FIRMWARE.BIN is stored (slowly).
    * Any other data is silently discarded, and data sectors read back as zeros.

    `keep_bytes` models a faulty unit that stores only the start of the file and
    silently discards the rest at USB speed.
    """

    def __init__(self, clock: FakeClock | None = None, registers: bool = True, keep_bytes: int | None = None) -> None:
        self.meta = simulate.device_metadata()
        self.geometry = fat16.parse_geometry(self.meta)
        root = self.geometry.first_root_sector * 512
        self.root = self.meta[root : root + 512]
        self.clock, self.registers, self.keep_bytes = clock, registers, keep_bytes
        self.window: tuple[int, int] | None = None
        self.stored = bytearray()
        self.size = 0
        self.discarded = 0
        self.write_log: list[int] = []
        self.sectors = C.TESTED_DEVICE_SECTORS

    def read(self, lba: int, count: int) -> bytes:
        g, out = self.geometry, []
        for s in range(lba, lba + count):
            if s in g.root_range():
                out.append(self.root)
            elif s < g.first_data_sector:
                out.append(self.meta[s * 512 : (s + 1) * 512])
            else:
                out.append(bytes(512))
        return b"".join(out)

    def write(self, lba: int, data: bytes) -> None:
        self.write_log.append(lba)
        for i in range(len(data) // 512):
            self._write_sector(lba + i, data[i * 512 : (i + 1) * 512])

    def _write_sector(self, sector: int, chunk: bytes) -> None:
        g = self.geometry
        if sector in g.root_range():
            if self.registers:
                self.root = chunk
                self._register()
        elif sector < g.first_data_sector:
            return
        elif self.window and self.window[0] <= sector < self.window[1] and self._keeps(sector):
            offset = (sector - self.window[0]) * 512
            self.stored[offset : offset + 512] = chunk
            if self.clock:
                self.clock.advance(FIRMWARE_SECTOR_SECONDS)
        else:
            self.discarded += 512

    def _keeps(self, sector: int) -> bool:
        return self.keep_bytes is None or (sector - self.window[0]) * 512 < self.keep_bytes

    def _register(self) -> None:
        for entry in fat16.parse_entries(self.root):
            if entry.raw_name == b"FIRMWAREBIN" and entry.size and entry.first_cluster >= 2:
                start = self.geometry.cluster_to_sector(entry.first_cluster)
                self.window = (start, start + (entry.size + 511) // 512)
                self.stored = bytearray((self.window[1] - self.window[0]) * 512)
                self.size = entry.size

    def received(self) -> bytes:
        return bytes(self.stored[: self.size])


class FakeBotDevice:
    """A USB Bulk-Only Transport target in front of PlainDisk/VirtualDrive (implements scsi.Transport)."""

    def __init__(
        self,
        storage: PlainDisk | VirtualDrive,
        ready_after: int = 0,
        stall_data_for: tuple = (),
        stall_status_once: bool = False,
        disconnect_after_bytes: int | None = None,
        write_protected: bool = False,
        vendor: bytes = C.SCSI_VENDOR,
        removable: bool = True,
        sectors: int = C.TESTED_DEVICE_SECTORS,
        residue_for: dict | None = None,
        stall_writes_but_report_success: bool = False,
        sync_error: Exception | None = None,
        write_error_after_bytes: tuple | None = None,
    ) -> None:
        self.storage, self.ready_after = storage, ready_after
        self.stall_data_for, self.stall_status_once = stall_data_for, stall_status_once
        self.disconnect_after_bytes, self.write_protected = disconnect_after_bytes, write_protected
        self.vendor, self.removable, self.sectors = vendor, removable, sectors
        self.residue_for = residue_for or {}
        self.stall_writes_but_report_success = stall_writes_but_report_success
        self.sync_error, self.write_error_after_bytes = sync_error, write_error_after_bytes
        self.commands: list[int] = []
        self.cleared: list[int] = []
        self.bytes_received = 0
        self._tag = 0
        self._status = 0
        self._residue = 0
        self._pending = b""
        self._expect_write: tuple[int, int] | None = None
        self._stall_data = False
        self._sense = (0, 0, 0)

    def bulk_out(self, endpoint: int, data: bytes, timeout_ms: int) -> None:
        if self._expect_write:
            self._receive_write(data)
            return
        signature, tag, length, flags, _lun, cdb_length = struct.unpack_from("<IIIBBB", data)
        assert signature == CBW_SIGNATURE and len(data) == 31
        cdb = data[15 : 15 + cdb_length]
        self.commands.append(cdb[0])
        self._tag, self._residue = tag, self.residue_for.get(cdb[0], 0)
        if cdb[0] == 0x2A:
            self._expect_write = (struct.unpack(">I", cdb[2:6])[0], length)
            return
        if cdb[0] == 0x35 and self.sync_error:
            raise self.sync_error
        self._status, payload = self._execute(cdb)
        self._pending = payload[:length] if flags & 0x80 else b""
        self._stall_data = bool(cdb[0] in self.stall_data_for and length)

    def bulk_in(self, endpoint: int, length: int, timeout_ms: int) -> bytes:
        if self._stall_data:
            self._stall_data, self._pending = False, b""
            raise StallError("stalled")
        if self._pending:
            data, self._pending = self._pending[:length], self._pending[length:]
            return data
        if self.stall_status_once:
            self.stall_status_once = False
            raise StallError("stalled")
        return struct.pack("<IIIB", CSW_SIGNATURE, self._tag, self._residue, self._status)

    def clear_halt(self, endpoint: int) -> None:
        self.cleared.append(endpoint)

    def _receive_write(self, data: bytes) -> None:
        lba, _length = self._expect_write
        self._expect_write = None
        self.bytes_received += len(data)
        if self.disconnect_after_bytes is not None and self.bytes_received > self.disconnect_after_bytes:
            raise DeviceGone("unplugged")
        if self.write_error_after_bytes and self.bytes_received > self.write_error_after_bytes[0]:
            raise self.write_error_after_bytes[1]
        self._status = 0
        if self.stall_writes_but_report_success:
            raise StallError("stalled the data phase")
        self.storage.write(lba, data)

    def _execute(self, cdb: bytes) -> tuple[int, bytes]:
        op = cdb[0]
        if op == 0x12:
            flags = b"\x80" if self.removable else b"\x00"
            return 0, b"\x00" + flags + b"\x06\x12\x1f\x00\x00\x00" + self.vendor + b"510PF".ljust(16, b"\0") + b"rev1"
        if op == 0x00:
            self.ready_after -= 1
            return (0, b"") if self.ready_after < 0 else self._fail(2, 0x04, 0x01)
        if op == 0x03:
            key, asc, ascq = self._sense
            return 0, bytes([0x70, 0, key]) + bytes(9) + bytes([asc, ascq]) + bytes(4)
        if op == 0x25:
            return 0, struct.pack(">II", self.sectors - 1, 512)
        if op == 0x1A:
            return 0, bytes([3, 0, 0x80 if self.write_protected else 0, 0])
        if op == 0x28:
            lba, count = struct.unpack(">I", cdb[2:6])[0], struct.unpack(">H", cdb[7:9])[0]
            return 0, self.storage.read(lba, count)
        return self._fail(5, 0x20, 0x00)  # e.g. SYNCHRONIZE CACHE: not supported, like the real unit

    def _fail(self, key: int, asc: int, ascq: int) -> tuple[int, bytes]:
        self._sense = (key, asc, ascq)
        return 1, b""


class FakeUsb:
    """Stands in for usb_libusb.UsbDevice in device_main()."""

    def __init__(self, transport: FakeBotDevice) -> None:
        self.transport, self.taken, self.closed = transport, False, False

    def config_descriptor(self) -> bytes:
        return CONFIG_DESCRIPTOR

    def take_interface(self) -> None:
        self.taken = True

    def bulk_out(self, endpoint: int, data: bytes, timeout_ms: int) -> None:
        self.transport.bulk_out(endpoint, data, timeout_ms)

    def bulk_in(self, endpoint: int, length: int, timeout_ms: int) -> bytes:
        return self.transport.bulk_in(endpoint, length, timeout_ms)

    def clear_halt(self, endpoint: int) -> None:
        self.transport.clear_halt(endpoint)

    def __enter__(self) -> FakeUsb:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.closed = True
