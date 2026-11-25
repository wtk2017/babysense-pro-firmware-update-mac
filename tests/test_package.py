import hashlib
import io
import os
import zipfile

import pytest

from babysense_mac import constants as C
from babysense_mac import package
from tests.builders import build_msix, build_pe, manifest, pin_for
from tests.fakes import make_firmware

pytestmark = pytest.mark.unit
IMAGE = make_firmware(50_000)


def msix_bytes(tmp_path, image=IMAGE, **kwargs):
    return build_msix(tmp_path / "u.msix", image, **kwargs).read_bytes()


def test_extracts_and_verifies_the_firmware(tmp_path):
    firmware = package.extract_firmware(msix_bytes(tmp_path), allow_untested=True)
    assert firmware.data == IMAGE
    assert firmware.sha256 == hashlib.sha256(IMAGE).hexdigest()
    assert (firmware.version, firmware.tested, firmware.updater_version) == ("V0207", False, "1.0.74.0")


def test_untested_firmware_needs_the_explicit_flag(tmp_path, monkeypatch):
    data = msix_bytes(tmp_path)
    with pytest.raises(package.UntestedFirmware, match="--allow-untested-firmware"):
        package.extract_firmware(data)
    monkeypatch.setitem(C.TESTED_FIRMWARE, hashlib.sha256(IMAGE).hexdigest(), "V0207")
    assert package.extract_firmware(data).tested is True


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"manifest_xml": manifest(publisher="CN=Someone Else")}, "not Babysense's updater"),
        (
            {"manifest_xml": b"<Package xmlns='http://schemas.microsoft.com/appx/manifest/foundation/windows10'/>"},
            "no identity",
        ),
        ({"manifest_xml": b"<Package><unclosed></Package>"}, "damaged"),
        ({"marker": False}, "no longer uses firmware.bin"),
        ({"resources": [IMAGE, pin_for(b"different")]}, "does not match its checksum"),
        ({"resources": [IMAGE, IMAGE, pin_for(IMAGE)]}, "one embedded firmware image, found 2"),
        ({"resources": [IMAGE]}, "one firmware checksum pin, found 0"),
        ({"resources": [pin_for(IMAGE)]}, "one embedded firmware image, found 0"),
        ({"resources": [b"x"] * 65}, "implausible number of resources"),
    ],
)
def test_rejects_anything_unexpected(tmp_path, kwargs, message):
    with pytest.raises(package.PackageError, match=message):
        package.extract_firmware(msix_bytes(tmp_path, **kwargs), allow_untested=True)


def test_rejects_damaged_packages():
    with pytest.raises(package.PackageError, match="damaged"):
        package.extract_firmware(b"this is not a zip file")


def test_unknown_version_name(tmp_path):
    data = msix_bytes(tmp_path, resources=[IMAGE, pin_for(IMAGE, "image.bin")])
    assert package.extract_firmware(data, allow_untested=True).version == "unknown"


def test_missing_and_oversized_members(tmp_path, monkeypatch):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("AppxManifest.xml", manifest())
    with pytest.raises(package.PackageError, match="has no"):
        package.extract_firmware(buffer.getvalue())
    monkeypatch.setattr(package, "MAX_MEMBER_BYTES", 10)
    with pytest.raises(package.PackageError, match="unexpectedly large"):
        package.extract_firmware(msix_bytes(tmp_path))


def test_clr_resources_parsing_and_bounds():
    assert package.clr_resources(build_pe([b"one", b"two"])) == [b"one", b"two"]
    assert package.clr_resources(build_pe([b"pe32"], magic=0x10B)) == [b"pe32"]
    assert package.clr_resources(build_pe([])) == []
    with pytest.raises(package.PackageError, match="not a PE"):
        package.clr_resources(b"MZ" + bytes(62) + b"\x00" * 64)
    with pytest.raises(package.PackageError, match="truncated"):
        package.clr_resources(b"MZ")
    with pytest.raises(package.PackageError, match="optional header"):
        package.clr_resources(build_pe([b"x"], magic=0x1234))
    pe = bytearray(build_pe([b"abc"]))
    pe[0x400 + 72 : 0x400 + 76] = (10**6).to_bytes(4, "little")  # resource length runs past its block
    assert package.clr_resources(bytes(pe)) == []
    truncated = build_pe([b"abcdef" * 100])[:-200]
    with pytest.raises(package.PackageError, match="past the end"):
        package.clr_resources(truncated)


def test_clr_header_pointing_outside_sections_is_rejected():
    pe = bytearray(build_pe([b"x"]))
    offset = 0x80 + 24 + 112 + 14 * 8
    pe[offset : offset + 4] = (0x9000).to_bytes(4, "little")
    with pytest.raises(package.PackageError, match="outside its own sections"):
        package.clr_resources(bytes(pe))


def test_load_verified_rechecks_the_file(tmp_path, monkeypatch):
    path = tmp_path / "fw.bin"
    path.write_bytes(IMAGE)
    digest = hashlib.sha256(IMAGE).hexdigest()
    assert package.load_verified(path, digest) == IMAGE
    assert package.load_verified(path, digest, owners={os.getuid()}) == IMAGE
    with pytest.raises(package.PackageError, match="another user"):
        package.load_verified(path, digest, owners={12345})
    with pytest.raises(package.PackageError, match="checksum on disk|does not match"):
        package.load_verified(path, "0" * 64)
    with pytest.raises(package.PackageError, match="malformed"):
        package.load_verified(path, "not-a-hash")
    monkeypatch.setattr(C, "MAX_FIRMWARE_BYTES", 10)
    with pytest.raises(package.PackageError, match="plausible size"):
        package.load_verified(path, digest)


def test_load_verified_refuses_links_folders_and_wrong_headers(tmp_path):
    target = tmp_path / "fw.bin"
    target.write_bytes(IMAGE)
    digest = hashlib.sha256(IMAGE).hexdigest()
    link = tmp_path / "link.bin"
    link.symlink_to(target)
    with pytest.raises(package.PackageError, match="cannot open"):
        package.load_verified(link, digest)
    with pytest.raises(package.PackageError, match="plausible size"):
        package.load_verified(tmp_path, digest)
    target.write_bytes(b"no header")
    with pytest.raises(package.PackageError, match="SONiX header"):
        package.load_verified(target, hashlib.sha256(b"no header").hexdigest())
