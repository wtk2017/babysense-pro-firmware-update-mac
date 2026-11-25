import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from babysense_mac import trust

pytestmark = pytest.mark.unit
REPO = Path(__file__).resolve().parent.parent
ME = {0, os.getuid()}


def fake_stat(mode, uid=None):
    return lambda path: SimpleNamespace(st_mode=mode, st_uid=os.getuid() if uid is None else uid)


def test_this_repository_passes_its_own_check():
    trust.check_tree(REPO, ME)


@pytest.mark.parametrize(
    "info, message",
    [
        (fake_stat(stat.S_IFREG | 0o644, uid=12345), "belongs to another user"),
        (fake_stat(stat.S_IFREG | 0o664), "can be changed by other users"),
        (fake_stat(stat.S_IFREG | 0o646), "can be changed by other users"),
        (fake_stat(stat.S_IFLNK | 0o755), "symbolic link"),
    ],
)
def test_check_file_refuses_unsafe_files(info, message):
    with pytest.raises(trust.UntrustedFile, match=message):
        trust.check_file(Path("/x"), ME, lstat=info)


def test_check_file_accepts_root_or_own_read_only_files():
    trust.check_file(Path("/x"), ME, lstat=fake_stat(stat.S_IFREG | 0o644, uid=0))
    trust.check_file(Path("/x"), ME, lstat=fake_stat(stat.S_IFREG | 0o444))


def test_check_library_resolves_links_to_the_real_file(tmp_path):
    real = tmp_path / "libusb-1.0.0.dylib"
    real.write_bytes(b"lib")
    real.chmod(0o444)
    link = tmp_path / "libusb-1.0.dylib"
    link.symlink_to(real)
    assert trust.check_library(str(link), ME) == str(real.resolve())
    real.chmod(0o666)
    with pytest.raises(trust.UntrustedFile):
        trust.check_library(str(link), ME)


def test_invoking_owners_uses_the_sudo_user(monkeypatch):
    monkeypatch.setenv("SUDO_UID", "4242")
    assert trust.invoking_owners() == {0, 4242}
    monkeypatch.delenv("SUDO_UID")
    assert trust.invoking_owners() == {0, os.getuid()}
