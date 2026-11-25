"""End-to-end on a disk image, checked with macOS's own FAT tools (fsck_msdos, hdiutil)."""

import hashlib
import shutil
import subprocess
import sys

import pytest

from babysense_mac import cli
from tests.fakes import make_firmware

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "darwin" or not shutil.which("hdiutil"), reason="needs macOS disk tools"),
]


def attach(image, *extra):
    out = subprocess.run(
        ["hdiutil", "attach", "-readonly", "-imagekey", "diskimage-class=CRawDiskImage", *extra, str(image)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return out.splitlines()[0].split()[0], out


def test_simulated_install_is_a_valid_fat_volume_with_the_exact_file(tmp_path):
    firmware = make_firmware(2_000_000)
    firmware_file, image = tmp_path / "fw.bin", tmp_path / "drive.img"
    firmware_file.write_bytes(firmware)
    assert cli.main(["simulate", "--image", str(image), "--firmware", str(firmware_file)]) == 0

    device, _ = attach(image, "-nomount")
    try:
        check = subprocess.run(["fsck_msdos", "-n", device.replace("disk", "rdisk")], capture_output=True, text=True)
        assert check.returncode == 0, check.stdout + check.stderr
    finally:
        subprocess.run(["hdiutil", "detach", device], capture_output=True, check=False)

    device, out = attach(image)
    try:
        mount = next(line.split("\t")[-1].strip() for line in out.splitlines() if "/Volumes/" in line)
        copied = tmp_path / "mounted.bin"
        shutil.copyfile(f"{mount}/firmware.bin", copied)
        assert hashlib.sha256(copied.read_bytes()).hexdigest() == hashlib.sha256(firmware).hexdigest()
    finally:
        subprocess.run(["hdiutil", "detach", device], capture_output=True, check=False)
