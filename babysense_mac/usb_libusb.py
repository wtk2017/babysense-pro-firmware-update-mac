"""Minimal ctypes binding to libusb-1.0 (install with `brew install libusb`).

macOS attaches its own mass-storage driver to the parent unit, cannot use the
drive, and keeps it locked. Taking the interface back from that driver is only
allowed for root, which is why the device steps run under sudo.
"""

from __future__ import annotations

import ctypes
import os
import time
from typing import Any, Callable

from . import trust
from .scsi import DeviceGone, StallError, TransportError

LIBUSB_PATHS = (
    "/opt/homebrew/lib/libusb-1.0.dylib",  # Homebrew, Apple silicon
    "/usr/local/lib/libusb-1.0.dylib",  # Homebrew, Intel
    "/opt/local/lib/libusb-1.0.dylib",  # MacPorts
)
ERROR_ACCESS, ERROR_NO_DEVICE, ERROR_BUSY = -3, -4, -6
ERROR_OVERFLOW, ERROR_PIPE = -8, -9
DESCRIPTOR_CONFIGURATION, REQUEST_GET_DESCRIPTOR = 0x02, 0x06
CONTROL_TIMEOUT_MS = 1000

_U8P = ctypes.POINTER(ctypes.c_ubyte)
_SIGNATURES = {
    "libusb_init": ([ctypes.POINTER(ctypes.c_void_p)], ctypes.c_int),
    "libusb_exit": ([ctypes.c_void_p], None),
    "libusb_open_device_with_vid_pid": ([ctypes.c_void_p, ctypes.c_uint16, ctypes.c_uint16], ctypes.c_void_p),
    "libusb_close": ([ctypes.c_void_p], None),
    "libusb_kernel_driver_active": ([ctypes.c_void_p, ctypes.c_int], ctypes.c_int),
    "libusb_detach_kernel_driver": ([ctypes.c_void_p, ctypes.c_int], ctypes.c_int),
    "libusb_claim_interface": ([ctypes.c_void_p, ctypes.c_int], ctypes.c_int),
    "libusb_release_interface": ([ctypes.c_void_p, ctypes.c_int], ctypes.c_int),
    "libusb_clear_halt": ([ctypes.c_void_p, ctypes.c_ubyte], ctypes.c_int),
    "libusb_bulk_transfer": (
        [ctypes.c_void_p, ctypes.c_ubyte, _U8P, ctypes.c_int, ctypes.POINTER(ctypes.c_int), ctypes.c_uint],
        ctypes.c_int,
    ),
    "libusb_control_transfer": (
        [
            ctypes.c_void_p,
            ctypes.c_uint8,
            ctypes.c_uint8,
            ctypes.c_uint16,
            ctypes.c_uint16,
            _U8P,
            ctypes.c_uint16,
            ctypes.c_uint,
        ],
        ctypes.c_int,
    ),
    "libusb_error_name": ([ctypes.c_int], ctypes.c_char_p),
}


class LibusbMissing(RuntimeError):
    """libusb is not installed."""


def load_libusb(
    paths: tuple[str, ...] = LIBUSB_PATHS,
    loader: Callable[[str], Any] = ctypes.CDLL,
    exists: Callable[[str], bool] = os.path.exists,
    owners: set[int] | None = None,
) -> Any:
    """Load libusb. With `owners`, the real library file must belong to one of them and not be
    writable by other users (checked right before loading, because root loads it)."""
    for path in paths:
        if exists(path):
            lib = loader(trust.check_library(path, owners) if owners is not None else path)
            for name, (args, result) in _SIGNATURES.items():
                function = getattr(lib, name)
                function.argtypes, function.restype = args, result
            return lib
    raise LibusbMissing("libusb was not found. Install it with:  brew install libusb")


def parse_bulk_endpoints(config_descriptor: bytes, interface: int) -> tuple[int, int]:
    """(bulk IN, bulk OUT) endpoint addresses of `interface`, alternate setting 0."""
    pos, current, ep_in, ep_out = 0, None, 0, 0
    while pos + 2 <= len(config_descriptor) and config_descriptor[pos] >= 2:
        length, kind = config_descriptor[pos], config_descriptor[pos + 1]
        if kind == 0x04 and pos + 4 <= len(config_descriptor):
            current = (config_descriptor[pos + 2], config_descriptor[pos + 3])
        elif kind == 0x05 and current == (interface, 0) and pos + 4 <= len(config_descriptor):
            address, attributes = config_descriptor[pos + 2], config_descriptor[pos + 3]
            if attributes & 0x03 == 0x02:
                if address & 0x80:
                    ep_in = ep_in or address
                else:
                    ep_out = ep_out or address
        pos += length
    if not (ep_in and ep_out):
        raise TransportError("the device does not expose the expected bulk endpoints")
    return ep_in, ep_out


class UsbDevice:
    """One open libusb device handle; implements scsi.Transport."""

    def __init__(self, lib: Any, context: ctypes.c_void_p, handle: int, interface: int) -> None:
        self._lib, self._context, self._handle, self._interface = lib, context, handle, interface
        self._claimed = False

    @classmethod
    def open(
        cls,
        lib: Any,
        vendor_id: int,
        product_id: int,
        interface: int,
        wait_seconds: float,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> UsbDevice:
        """Wait (polling) until the device appears, then open it."""
        context = ctypes.c_void_p()
        if lib.libusb_init(ctypes.byref(context)) != 0:
            raise TransportError("could not initialise libusb")
        deadline = clock() + wait_seconds
        while True:
            handle = lib.libusb_open_device_with_vid_pid(context, vendor_id, product_id)
            if handle:
                return cls(lib, context, handle, interface)
            if clock() >= deadline:
                lib.libusb_exit(context)
                raise DeviceGone("the parent unit did not appear on USB")
            sleep(0.1)

    def _error(self, code: int) -> str:
        name = self._lib.libusb_error_name(code)
        return name.decode() if isinstance(name, bytes) else str(name)

    def config_descriptor(self) -> bytes:
        buffer = (ctypes.c_ubyte * 512)()
        result = self._lib.libusb_control_transfer(
            self._handle,
            0x80,
            REQUEST_GET_DESCRIPTOR,
            DESCRIPTOR_CONFIGURATION << 8,
            0,
            buffer,
            512,
            CONTROL_TIMEOUT_MS,
        )
        if result < 0:
            raise TransportError(f"could not read the USB configuration ({self._error(result)})")
        return bytes(buffer[:result])

    def take_interface(self) -> None:
        """Detach macOS's own storage driver (needs root) and claim the interface."""
        if self._lib.libusb_kernel_driver_active(self._handle, self._interface) == 1:
            result = self._lib.libusb_detach_kernel_driver(self._handle, self._interface)
            if result != 0:
                raise TransportError(
                    f"could not take the parent unit from macOS ({self._error(result)}); this step needs sudo"
                )
        result = self._lib.libusb_claim_interface(self._handle, self._interface)
        if result != 0:
            raise TransportError(f"could not claim the parent unit's USB interface ({self._error(result)})")
        self._claimed = True

    def _raise_for(self, code: int, what: str) -> None:
        if code == ERROR_PIPE:
            raise StallError(f"{what}: endpoint stalled")
        if code == ERROR_NO_DEVICE:
            raise DeviceGone("the parent unit disconnected")
        raise TransportError(f"{what} failed ({self._error(code)})")

    def bulk_out(self, endpoint: int, data: bytes, timeout_ms: int) -> None:
        buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        sent = ctypes.c_int(0)
        result = self._lib.libusb_bulk_transfer(
            self._handle, endpoint, buffer, len(data), ctypes.byref(sent), timeout_ms
        )
        if result != 0:
            self._raise_for(result, "USB send")
        if sent.value != len(data):
            raise TransportError(f"USB send was short ({sent.value} of {len(data)} bytes)")

    def bulk_in(self, endpoint: int, length: int, timeout_ms: int) -> bytes:
        buffer = (ctypes.c_ubyte * max(length, 1))()
        received = ctypes.c_int(0)
        result = self._lib.libusb_bulk_transfer(
            self._handle, endpoint, buffer, length, ctypes.byref(received), timeout_ms
        )
        if result not in (0, ERROR_OVERFLOW):
            self._raise_for(result, "USB receive")
        return bytes(buffer[: received.value])

    def clear_halt(self, endpoint: int) -> None:
        self._lib.libusb_clear_halt(self._handle, endpoint)

    def close(self) -> None:
        if self._claimed:
            self._lib.libusb_release_interface(self._handle, self._interface)
            self._claimed = False
        if self._handle:
            self._lib.libusb_close(self._handle)
            self._handle = 0
            self._lib.libusb_exit(self._context)

    def __enter__(self) -> UsbDevice:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
