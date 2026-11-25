import hashlib
import io
import runpy
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from babysense_mac import cli, installer, package, simulate, store, trust
from babysense_mac import constants as C
from tests.fakes import FakeBotDevice, FakeUsb, VirtualDrive, make_firmware

pytestmark = pytest.mark.unit
FIRMWARE = make_firmware(200_000)
DIGEST = hashlib.sha256(FIRMWARE).hexdigest()
REPO = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def not_root(monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 501)


def firmware_record(tested=True):
    return package.Firmware(FIRMWARE, DIGEST, "x_V0207.bin", "V0207", tested, "1.0.74.0")


def test_parser_and_version(capsys):
    args = cli.build_parser().parse_args(["install", "--yes", "--allow-untested-firmware"])
    assert (args.command, args.yes, args.allow_untested_firmware) == ("install", True, True)
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["--version"])
    assert "babysense-update 1.0.0" in capsys.readouterr().out


def test_refuses_to_run_as_root(monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    assert cli.main(["fetch"]) == 1


def test_fetch_caches_the_verified_firmware_atomically(tmp_path, monkeypatch):
    warnings = []
    monkeypatch.setattr(cli.log, "warning", warnings.append)

    def fetcher(cache_dir, say):
        return b"msix bytes"

    firmware, path = cli.fetch_firmware(False, tmp_path, fetcher, lambda msix, allow: firmware_record())
    assert path.read_bytes() == FIRMWARE and path.name == f"firmware-{DIGEST}.bin"
    assert warnings == []
    path.write_bytes(FIRMWARE[:100])  # a truncated copy from an interrupted earlier run
    cli.fetch_firmware(False, tmp_path, fetcher, lambda msix, allow: firmware_record(tested=False))
    assert path.read_bytes() == FIRMWARE
    assert not list(tmp_path.glob("*.part"))
    assert warnings == [cli.UNTESTED_WARNING]


def test_install_requires_typed_confirmation(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "fetch_firmware", lambda allow: (firmware_record(), tmp_path / "fw.bin"))
    calls = []
    args = SimpleNamespace(allow_untested_firmware=False, yes=False, allow_untested_device=False)
    assert cli.cmd_install(args, ask=lambda prompt: "no", privileged=lambda *a: calls.append(a) or 0) == 1

    def closed_stdin(prompt):
        raise EOFError

    assert cli.cmd_install(args, ask=closed_stdin, privileged=lambda *a: calls.append(a) or 0) == 1
    assert calls == []
    assert cli.cmd_install(args, ask=lambda prompt: " UPDATE ", privileged=lambda *a: calls.append(a) or 0) == 0
    device_args, label = calls[0]
    assert label == "install" and device_args[:2] == ["install", "--firmware"]
    assert device_args[3:5] == ["--sha256", DIGEST]
    args.yes, args.allow_untested_device = True, True
    monkeypatch.setattr(cli, "fetch_firmware", lambda allow: (firmware_record(tested=False), tmp_path / "fw.bin"))
    assert cli.cmd_install(args, privileged=lambda *a: calls.append(a) or 2) == 2
    assert calls[-1][0][-2:] == ["--allow-untested-device", "--allow-untested-firmware"]


class FakeProcess:
    seen: dict = {}
    code = 0

    def __init__(self, command, **kwargs):
        FakeProcess.seen["command"] = command
        self.stdout = io.StringIO("line one\nSUCCESS\n")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def wait(self):
        return FakeProcess.code


def test_run_privileged_uses_fixed_sudo_and_apples_python(tmp_path):
    FakeProcess.code = 0
    assert cli.run_privileged(["check"], "check", popen=FakeProcess, log_dir=tmp_path) == 0
    command = FakeProcess.seen["command"]
    assert command[:5] == ["/usr/bin/sudo", "/usr/bin/python3", "-I", "-B", str(cli.LAUNCHER)]
    assert command[5:] == ["_device", "check"]
    log_file = next(tmp_path.glob("check-*.log"))
    assert "SUCCESS" in log_file.read_text()
    assert tmp_path.stat().st_mode & 0o777 in (0o700, 0o755)  # pytest's tmp dir already existed


def test_run_privileged_reports_a_killed_child(tmp_path, caplog):
    FakeProcess.code = -9
    assert cli.run_privileged(["install"], "install", popen=FakeProcess, log_dir=tmp_path / "logs") == 1
    assert (tmp_path / "logs").stat().st_mode & 0o777 == 0o700


def test_prepare_privileged_checks_python_files_and_libusb(monkeypatch):
    seen = []
    cli.prepare_privileged(libusb_loader=lambda owners: seen.append(owners))
    assert seen == [{0, cli.os.getuid()}]
    monkeypatch.setattr(C, "ROOT_PYTHON", "/nonexistent/python3")
    with pytest.raises(OSError, match="xcode-select --install"):
        cli.prepare_privileged(libusb_loader=lambda owners: None)


def device_run(argv, drive=None, **bot):
    usb = FakeUsb(FakeBotDevice(drive or VirtualDrive(), **bot))
    code = cli.device_main(argv, loader=lambda owners=None: object(), opener=lambda *a: usb, require_root=False)
    return code, usb


def test_device_check():
    code, usb = device_run(["check"])
    assert code == 0 and usb.taken and usb.closed


def test_device_install_success_and_refusals(tmp_path, monkeypatch):
    path = tmp_path / "fw.bin"
    path.write_bytes(FIRMWARE)
    monkeypatch.setitem(C.TESTED_FIRMWARE, DIGEST, "test")
    monkeypatch.setattr(C, "MAX_PLAUSIBLE_CAPTURE_MB_PER_S", 1e12)  # the fake unit stores instantly
    drive = VirtualDrive()
    code, _ = device_run(["install", "--firmware", str(path), "--sha256", DIGEST], drive)
    assert code == 0 and drive.received() == FIRMWARE
    monkeypatch.setattr(C, "MAX_PLAUSIBLE_CAPTURE_MB_PER_S", 1.0)
    assert device_run(["install", "--firmware", str(path), "--sha256", DIGEST])[0] == 2  # too fast: stop
    assert device_run(["install", "--firmware", str(path), "--sha256", "0" * 64])[0] == 1


def test_root_side_enforces_the_tested_firmware_list(tmp_path):
    path = tmp_path / "fw.bin"
    path.write_bytes(FIRMWARE)
    assert device_run(["install", "--firmware", str(path), "--sha256", DIGEST])[0] == 1
    with pytest.raises(SystemExit):
        cli.device_main(["install"], require_root=False)


def test_device_main_requires_root_and_libusb():
    assert cli.device_main(["check"], require_root=True) == 1

    def missing(owners=None):
        raise cli.LibusbMissing("brew install libusb")

    assert cli.device_main(["check"], loader=missing, require_root=False) == 1


def test_main_dispatch(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "prepare_privileged", lambda: None)
    monkeypatch.setattr(cli, "run_privileged", lambda args, label: 0 if args == ["check"] else 9)
    assert cli.main(["check"]) == 0
    monkeypatch.setattr(cli, "fetch_firmware", lambda allow: (firmware_record(), tmp_path / "x"))
    assert cli.main(["fetch"]) == 0
    monkeypatch.setattr(cli, "cmd_install", lambda args: 0)
    assert cli.main(["install"]) == 0
    monkeypatch.setattr(cli, "fetch_firmware", lambda allow: (_ for _ in ()).throw(store.StoreError("offline")))
    assert cli.main(["fetch"]) == 1
    monkeypatch.setattr(cli, "fetch_firmware", lambda allow: (_ for _ in ()).throw(KeyboardInterrupt()))
    assert cli.main(["fetch"]) == 130
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli, "fetch_firmware", lambda allow: (firmware_record(), tmp_path / "x"))
    assert cli.main(["fetch"]) == 0
    monkeypatch.setattr(cli, "device_main", lambda argv: 42)
    assert cli.main(["_device", "check"]) == 42


def test_main_stops_when_files_are_not_trustworthy(monkeypatch):
    def untrusted():
        raise trust.UntrustedFile("babysense_mac/cli.py can be changed by other users")

    monkeypatch.setattr(cli, "prepare_privileged", untrusted)
    assert cli.main(["install"]) == 1


def test_simulate_end_to_end_on_an_image(tmp_path):
    firmware_file, image = tmp_path / "fw.bin", tmp_path / "drive.img"
    firmware_file.write_bytes(FIRMWARE)
    assert cli.main(["simulate", "--image", str(image), "--firmware", str(firmware_file)]) == 0
    with simulate.ImageDevice(image) as dev:
        assert dev.read10(520, 2) == FIRMWARE[:1024]
    assert cli.main(["simulate", "--image", str(image), "--firmware", str(firmware_file)]) == 1  # already there


def test_simulate_never_touches_other_disk_images(tmp_path):
    other, firmware_file = tmp_path / "other.img", tmp_path / "fw.bin"
    other.write_bytes(b"\0" * 4096)
    firmware_file.write_bytes(FIRMWARE)
    assert cli.main(["simulate", "--image", str(other), "--firmware", str(firmware_file)]) == 1
    assert other.read_bytes() == b"\0" * 4096
    relabelled = tmp_path / "relabelled.img"
    simulate.create_device_image(relabelled)
    with open(relabelled, "r+b") as handle:
        handle.seek(488 * 512)
        handle.write(b"SOMETHING  ")
    assert not simulate.looks_like_device_image(relabelled)


def test_simulate_can_fetch_the_official_firmware(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "fetch_firmware", lambda allow: (firmware_record(), tmp_path / "x"))
    assert cli.main(["simulate", "--image", str(tmp_path / "d.img")]) == 0


def test_image_device_bounds(tmp_path):
    image = tmp_path / "d.img"
    simulate.create_device_image(image)
    with simulate.ImageDevice(image) as dev:
        assert dev.read_capacity() == (C.TESTED_DEVICE_SECTORS, 512) and not dev.write_protected()
        assert dev.synchronize_cache() == "ok"
        with pytest.raises(OSError):
            dev.read10(C.TESTED_DEVICE_SECTORS, 1)


def test_entry_points(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["babysense-update", "--version"])
    with pytest.raises(SystemExit):
        runpy.run_module("babysense_mac", run_name="__main__")
    result = subprocess.run(
        [sys.executable, str(REPO / "babysense-update"), "--version"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0 and "1.0.0" in result.stdout


def test_install_aborted_is_reported(monkeypatch):
    monkeypatch.setattr(cli, "prepare_privileged", lambda: None)
    monkeypatch.setattr(cli, "cmd_install", lambda args: (_ for _ in ()).throw(installer.InstallAborted("x")))
    assert cli.main(["install"]) == 1
