import types

import pytest

from babysense_mac import usb_libusb as u
from babysense_mac.scsi import DeviceGone, StallError, TransportError
from tests.fakes import CONFIG_DESCRIPTOR

pytestmark = pytest.mark.unit


class FakeLib:
    """Pretends to be libusb-1.0 loaded through ctypes."""

    def __init__(self, appear_after=0, init_result=0):
        self.appear_after, self.init_result = appear_after, init_result
        self.calls, self.transfers = [], []
        self.driver_active, self.detach_result, self.claim_result, self.control_result = 1, 0, 0, None

    def libusb_init(self, context_ref):
        return self.init_result

    def libusb_exit(self, context):
        self.calls.append("exit")

    def libusb_open_device_with_vid_pid(self, context, vid, pid):
        self.appear_after -= 1
        return 1234 if self.appear_after < 0 else None

    def libusb_kernel_driver_active(self, handle, interface):
        return self.driver_active

    def libusb_detach_kernel_driver(self, handle, interface):
        self.calls.append("detach")
        return self.detach_result

    def libusb_claim_interface(self, handle, interface):
        self.calls.append("claim")
        return self.claim_result

    def libusb_release_interface(self, handle, interface):
        self.calls.append("release")

    def libusb_close(self, handle):
        self.calls.append("close")

    def libusb_clear_halt(self, handle, endpoint):
        self.calls.append(("clear", endpoint))

    def libusb_control_transfer(self, handle, rtype, request, value, index, buffer, length, timeout):
        if self.control_result is not None:
            return self.control_result
        for i, byte in enumerate(CONFIG_DESCRIPTOR):
            buffer[i] = byte
        return len(CONFIG_DESCRIPTOR)

    def libusb_bulk_transfer(self, handle, endpoint, buffer, length, done_ref, timeout):
        result, data = self.transfers.pop(0)
        for i, byte in enumerate(data):
            buffer[i] = byte
        done_ref._obj.value = len(data)
        return result

    def libusb_error_name(self, code):
        return f"LIBUSB_ERROR_{-code}".encode()


def opened(lib=None):
    lib = lib or FakeLib()
    return lib, u.UsbDevice.open(lib, 0x0C45, 0x8801, 0, 1.0, sleep=lambda s: None)


def test_load_libusb_reports_how_to_install_when_missing():
    with pytest.raises(u.LibusbMissing, match="brew install libusb"):
        u.load_libusb(paths=("/nope",), exists=lambda p: False)


def test_load_libusb_declares_every_signature():
    def function():
        return None

    fake = types.SimpleNamespace(**{name: types.FunctionType(function.__code__, {}) for name in u._SIGNATURES})
    lib = u.load_libusb(paths=("/a", "/b"), loader=lambda path: fake, exists=lambda p: p == "/b")
    assert lib is fake
    assert lib.libusb_bulk_transfer.restype is u.ctypes.c_int


def test_parses_the_real_parent_unit_descriptor():
    assert u.parse_bulk_endpoints(CONFIG_DESCRIPTOR, 0) == (0x8C, 0x0D)
    with pytest.raises(TransportError):
        u.parse_bulk_endpoints(CONFIG_DESCRIPTOR, 1)
    with pytest.raises(TransportError):
        u.parse_bulk_endpoints(b"", 0)


def test_open_waits_until_the_unit_appears():
    lib, dev = opened(FakeLib(appear_after=3))
    assert dev._handle == 1234


def test_open_times_out_cleanly():
    clock = iter([0.0, 0.5, 2.0, 3.0])
    lib = FakeLib(appear_after=99)
    with pytest.raises(DeviceGone):
        u.UsbDevice.open(lib, 1, 2, 0, 1.0, sleep=lambda s: None, clock=lambda: next(clock))
    assert lib.calls == ["exit"]
    with pytest.raises(TransportError, match="initialise"):
        u.UsbDevice.open(FakeLib(init_result=-1), 1, 2, 0, 1.0)


def test_take_interface_detaches_macos_driver_then_claims():
    lib, dev = opened()
    dev.take_interface()
    assert lib.calls == ["detach", "claim"]
    dev.close()
    assert lib.calls[-3:] == ["release", "close", "exit"]
    dev.close()
    assert lib.calls.count("close") == 1


def test_take_interface_explains_failures():
    lib, dev = opened()
    lib.detach_result = -3
    with pytest.raises(TransportError, match="needs sudo"):
        dev.take_interface()
    lib.driver_active, lib.claim_result = 0, -6
    with pytest.raises(TransportError, match="claim"):
        dev.take_interface()


def test_config_descriptor_read_and_failure():
    lib, dev = opened()
    assert dev.config_descriptor() == CONFIG_DESCRIPTOR
    lib.control_result = -4
    with pytest.raises(TransportError, match="configuration"):
        dev.config_descriptor()


def test_bulk_transfers_map_errors():
    lib, dev = opened()
    lib.transfers = [(0, b"abc"), (u.ERROR_OVERFLOW, b"xy"), (0, b"12")]
    assert dev.bulk_in(0x8C, 3, 100) == b"abc"
    assert dev.bulk_in(0x8C, 2, 100) == b"xy"
    dev.bulk_out(0x0D, b"12", 100)
    lib.transfers = [(0, b"1")]
    with pytest.raises(TransportError, match="short"):
        dev.bulk_out(0x0D, b"12", 100)
    for code, error in ((u.ERROR_PIPE, StallError), (u.ERROR_NO_DEVICE, DeviceGone), (-7, TransportError)):
        lib.transfers = [(code, b"")]
        with pytest.raises(error):
            dev.bulk_in(0x8C, 4, 100)
    dev.clear_halt(0x8C)
    assert ("clear", 0x8C) in lib.calls


def test_context_manager_closes():
    lib, dev = opened()
    with dev:
        pass
    assert "close" in lib.calls
