"""Refuse to hand root anything that another user could have modified.

The USB step runs this tool's code and Homebrew's libusb as root (via sudo).
These checks make sure those files belong to you (or root) and are not writable
by other users. They cannot protect against malware already running as you;
the README says so plainly.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Callable

GROUP_OR_OTHER_WRITABLE = stat.S_IWGRP | stat.S_IWOTH


class UntrustedFile(RuntimeError):
    """A file root would use is owned by someone else or writable by other users."""


def invoking_owners() -> set[int]:
    """Root plus the real user (also when running under sudo)."""
    return {0, int(os.environ.get("SUDO_UID", os.getuid()))}


def check_file(path: Path, owners: set[int], lstat: Callable[[Path], os.stat_result] = os.lstat) -> None:
    info = lstat(path)
    if stat.S_ISLNK(info.st_mode):
        raise UntrustedFile(f"{path} is a symbolic link")
    if info.st_uid not in owners:
        raise UntrustedFile(f"{path} belongs to another user (uid {info.st_uid})")
    if info.st_mode & GROUP_OR_OTHER_WRITABLE:
        raise UntrustedFile(f"{path} can be changed by other users; fix with: chmod go-w '{path}'")


def check_tree(root: Path, owners: set[int]) -> None:
    """The launcher, the package folder and every file in it (what root will import)."""
    package = root / "babysense_mac"
    for path in [root, root / "babysense-update", package, *sorted(package.rglob("*"))]:
        check_file(path, owners)


def check_library(path: str, owners: set[int]) -> str:
    """Resolve a shared library and check the real file before root loads it."""
    real = Path(os.path.realpath(path))
    check_file(real, owners)
    return str(real)
