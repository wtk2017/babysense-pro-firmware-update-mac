"""USB Mass Storage Bulk-Only Transport (BOT) with an explicit SCSI opcode allowlist.

Talks to any object implementing `Transport` (the libusb device, or a fake in
tests). Read-only sessions can only send read-only commands; write sessions add
exactly WRITE(10) and SYNCHRONIZE CACHE(10). Nothing else can ever be sent.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import NamedTuple, Protocol

CBW_SIGNATURE, CSW_SIGNATURE = 0x43425355, 0x53425355
CBW_LENGTH, CSW_LENGTH = 31, 13
DIRECTION_IN, DIRECTION_OUT = 0x80, 0x00

OP_TEST_UNIT_READY, OP_REQUEST_SENSE, OP_INQUIRY = 0x00, 0x03, 0x12
OP_MODE_SENSE6, OP_READ_CAPACITY10, OP_READ10 = 0x1A, 0x25, 0x28
OP_WRITE10, OP_SYNC_CACHE10 = 0x2A, 0x35
READ_ONLY_OPCODES = frozenset(
    {OP_TEST_UNIT_READY, OP_REQUEST_SENSE, OP_INQUIRY, OP_MODE_SENSE6, OP_READ_CAPACITY10, OP_READ10}
)
WRITE_OPCODES = frozenset({OP_WRITE10, OP_SYNC_CACHE10})

READ_TIMEOUT_MS = 10_000
WRITE_TIMEOUT_MS = 60_000  # the parent unit writes to flash at ~0.1 MB/s
SYNC_TIMEOUT_MS = 600_000


class TransportError(IOError):
    """USB transfer failed."""


class StallError(TransportError):
    """The device stalled an endpoint (it rejected the current phase)."""


class DeviceGone(TransportError):
    """The device disconnected (for example, it powered off)."""


class Transport(Protocol):
    def bulk_out(self, endpoint: int, data: bytes, timeout_ms: int) -> None: ...

    def bulk_in(self, endpoint: int, length: int, timeout_ms: int) -> bytes: ...

    def clear_halt(self, endpoint: int) -> None: ...


@dataclass(frozen=True)
class Sense:
    key: int
    asc: int
    ascq: int

    def __str__(self) -> str:
        return f"sense key={self.key:#x} ASC={self.asc:#04x} ASCQ={self.ascq:#04x}"


class Completion(NamedTuple):
    """Outcome of one command: SCSI status, data received, CSW residue, and whether the data phase stalled."""

    status: int
    data: bytes
    residue: int
    data_stalled: bool


class ScsiError(IOError):
    """A SCSI command completed with a failure status."""

    def __init__(self, opcode: int, status: int, sense: Sense | None) -> None:
        super().__init__(f"SCSI command {opcode:#04x} failed (status {status}; {sense or 'no sense data'})")
        self.opcode, self.status, self.sense = opcode, status, sense


class BulkOnlyScsi:
    """SCSI over USB Bulk-Only Transport, restricted to an opcode allowlist."""

    def __init__(self, transport: Transport, ep_in: int, ep_out: int, allow_writes: bool = False) -> None:
        self._transport, self._ep_in, self._ep_out = transport, ep_in, ep_out
        self._allowed = READ_ONLY_OPCODES | (WRITE_OPCODES if allow_writes else frozenset())
        self._tag = 0

    def command(
        self, cdb: bytes, data_in: int = 0, payload: bytes | None = None, timeout_ms: int = READ_TIMEOUT_MS
    ) -> Completion:
        """Run one command. Raises PermissionError for opcodes not allowed in this session."""
        if not cdb or cdb[0] not in self._allowed:
            raise PermissionError(f"SCSI opcode {cdb[0] if cdb else None!r} is not allowed in this session")
        if data_in and payload is not None:
            raise ValueError("a command cannot both read and write data")
        self._tag = (self._tag + 1) & 0xFFFFFFFF
        length = len(payload) if payload is not None else data_in
        direction = DIRECTION_IN if data_in else DIRECTION_OUT
        header = struct.pack("<IIIBBB", CBW_SIGNATURE, self._tag, length, direction, 0, len(cdb))
        self._transport.bulk_out(self._ep_out, header + bytes(cdb).ljust(16, b"\0"), timeout_ms)
        data, stalled = self._data_phase(data_in, payload, timeout_ms)
        status, residue = self._status(timeout_ms)
        return Completion(status, data, residue, stalled)

    def _data_phase(self, data_in: int, payload: bytes | None, timeout_ms: int) -> tuple[bytes, bool]:
        try:
            if payload is not None:
                self._transport.bulk_out(self._ep_out, payload, timeout_ms)
            elif data_in:
                return self._transport.bulk_in(self._ep_in, data_in, timeout_ms), False
        except StallError:
            self._transport.clear_halt(self._ep_out if payload is not None else self._ep_in)
            return b"", True
        return b"", False

    def _status(self, timeout_ms: int) -> tuple[int, int]:
        try:
            raw = self._transport.bulk_in(self._ep_in, CSW_LENGTH, timeout_ms)
        except StallError:
            self._transport.clear_halt(self._ep_in)
            raw = self._transport.bulk_in(self._ep_in, CSW_LENGTH, timeout_ms)
        if len(raw) != CSW_LENGTH:
            raise TransportError(f"status block has {len(raw)} bytes, expected {CSW_LENGTH}")
        signature, tag, residue, status = struct.unpack("<IIIB", raw)
        if signature != CSW_SIGNATURE or tag != self._tag:
            raise TransportError("status block out of sync with the command")
        return status, residue

    def _checked(
        self, cdb: bytes, data_in: int = 0, payload: bytes | None = None, timeout_ms: int = READ_TIMEOUT_MS
    ) -> Completion:
        done = self.command(cdb, data_in, payload, timeout_ms)
        if done.status != 0:
            raise ScsiError(cdb[0], done.status, self.request_sense())
        return done

    def request_sense(self) -> Sense | None:
        done = self.command(bytes([OP_REQUEST_SENSE, 0, 0, 0, 18, 0]), data_in=18)
        if done.status != 0 or len(done.data) < 14:
            return None
        return Sense(done.data[2] & 0x0F, done.data[12], done.data[13])

    def inquiry(self) -> bytes:
        return self._checked(bytes([OP_INQUIRY, 0, 0, 0, 36, 0]), data_in=36).data

    def test_unit_ready(self) -> bool:
        return self.command(bytes(6)).status == 0

    def read_capacity(self) -> tuple[int, int]:
        """(number of sectors, sector size)."""
        data = self._checked(bytes([OP_READ_CAPACITY10]) + bytes(9), data_in=8).data
        if len(data) != 8:
            raise TransportError("READ CAPACITY returned a short answer")
        last_lba, block = struct.unpack(">II", data)
        return last_lba + 1, block

    def write_protected(self) -> bool:
        data = self._checked(bytes([OP_MODE_SENSE6, 0, 0x3F, 0, 192, 0]), data_in=192).data
        return len(data) >= 3 and bool(data[2] & 0x80)

    def read10(self, lba: int, count: int, block: int = 512) -> bytes:
        cdb = bytes([OP_READ10, 0]) + struct.pack(">IBHB", lba, 0, count, 0)
        done = self._checked(cdb, data_in=count * block)
        if len(done.data) != count * block or done.residue:
            raise TransportError(f"short read at sector {lba} ({len(done.data)} of {count * block} bytes)")
        return done.data

    def write10(self, lba: int, data: bytes, block: int = 512) -> None:
        """Write whole sectors. Fails unless the device took every byte and reported success."""
        if not data or len(data) % block:
            raise ValueError("write length must be a positive multiple of the sector size")
        cdb = bytes([OP_WRITE10, 0]) + struct.pack(">IBHB", lba, 0, len(data) // block, 0)
        done = self._checked(cdb, payload=data, timeout_ms=WRITE_TIMEOUT_MS)
        if done.data_stalled or done.residue:
            raise TransportError(
                f"the parent unit did not accept all data at sector {lba} "
                f"(stalled: {done.data_stalled}, bytes not taken: {done.residue})"
            )

    def synchronize_cache(self) -> str:
        """Ask the device to commit cached writes. Many simple devices answer 'not supported'."""
        done = self.command(bytes([OP_SYNC_CACHE10]) + bytes(9), timeout_ms=SYNC_TIMEOUT_MS)
        return "ok" if done.status == 0 else f"not supported ({self.request_sense()})"
