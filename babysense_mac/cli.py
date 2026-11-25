"""Command line: check, fetch, install, simulate.

Run as your normal user. The only step that needs administrator rights (taking
the parent unit's USB interface back from macOS) runs as a `sudo` child process
using Apple's root-owned Python. Before elevating, the tool checks that its own
files and libusb belong to you and can't be changed by other users. The child is
given a firmware file path plus its SHA-256 and re-verifies everything itself.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import subprocess  # noqa: S404 - only used to re-run this same tool under sudo
import sys
import time
from pathlib import Path
from typing import Any, Callable, Sequence

from . import __version__, device, fat16, installer, package, simulate, store, trust
from . import constants as C
from .scsi import BulkOnlyScsi, ScsiError, TransportError
from .usb_libusb import LibusbMissing, UsbDevice, load_libusb, parse_bulk_endpoints

APP_NAME = "babysense-pro-firmware-update-mac"
REPO_DIR = Path(__file__).resolve().parent.parent
LAUNCHER = REPO_DIR / "babysense-update"
CACHE_DIR = Path.home() / "Library" / "Caches" / APP_NAME
LOG_DIR = Path.home() / "Library" / "Logs" / APP_NAME
log = logging.getLogger("babysense_mac")

SAFETY_CHECKLIST = """\
Before updating, please confirm:
  1. The parent unit's battery is not swollen (the case is flat and the screen is not lifting),
     it is not hot, and the unit has not been dropped or damaged.
  2. It is connected directly to this Mac with a USB-C *data* cable (not a charge-only cable).
  3. You understand this is an unofficial tool. It is not made, endorsed or supported by Babysense.
     Babysense's own routes are their Windows updater and their support team."""

NEXT_STEPS = """\
The firmware has been handed to the parent unit. Finish exactly as Babysense's updater instructs:
  1. Unplug the USB-C cable from the parent unit.
  2. Press the RESET button on the back of the parent unit (the pinhole near the antenna) with a pin.
  3. Turn the parent unit on and let it finish. Don't press anything if the screen stays blank for a while.
  4. Re-pair your camera(s); the update clears the pairing:
       Menu > Camera Settings > Pair Camera > choose the camera (1-4) > confirm.
     Keep each camera plugged in and close to the parent unit while pairing.
  5. Fully charge the parent unit with the Babysense power adapter (the light turns green when full)."""

NOTHING_SENT = "No firmware was sent, so nothing needs undoing. Do NOT press RESET."
UNTESTED_WARNING = (
    "WARNING: this firmware has not been tested with this tool. Its authenticity rests only on "
    "Microsoft's download checksum. Continue only if you accept that risk."
)


def configure_logging() -> None:
    if not log.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        log.addHandler(handler)
    log.setLevel(logging.INFO)
    log.propagate = False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="babysense-update",
        description="Install Babysense's official Babysense Pro parent-unit firmware from a Mac (unofficial tool).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check", help="find the parent unit and show its update drive (read-only)")
    fetch = commands.add_parser("fetch", help="download Babysense's updater from Microsoft and extract the firmware")
    install = commands.add_parser("install", help="install the firmware on the parent unit")
    install.add_argument("--yes", action="store_true", help="skip the typed confirmation")
    install.add_argument("--allow-untested-device", action="store_true", help=argparse.SUPPRESS)
    rehearse = commands.add_parser("simulate", help="rehearse the install on a disk image (no hardware, no sudo)")
    rehearse.add_argument("--image", type=Path, required=True, help="image file (created if missing)")
    rehearse.add_argument("--firmware", type=Path, help="firmware file to use instead of the official one")
    for sub in (fetch, install, rehearse):
        sub.add_argument(
            "--allow-untested-firmware",
            action="store_true",
            help="accept newer Babysense firmware this tool hasn't been tested with (weaker checks: see README)",
        )
    return parser


def _write_cache(path: Path, data: bytes) -> None:
    """Atomically (re)write a cache file unless an identical copy is already there."""
    if path.exists() and hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256(data).digest():
        return
    temporary = path.with_name(f"{path.name}.{os.getpid()}.part")
    temporary.write_bytes(data)
    temporary.replace(path)


def fetch_firmware(
    allow_untested: bool,
    cache_dir: Path = CACHE_DIR,
    fetcher: Callable[..., bytes] = store.fetch_updater_package,
    extractor: Callable[..., package.Firmware] = package.extract_firmware,
) -> tuple[package.Firmware, Path]:
    """Download (or reuse) the official package, extract and verify the firmware, cache it."""
    firmware = extractor(fetcher(cache_dir, log.info), allow_untested)
    cache_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = cache_dir / f"firmware-{firmware.sha256}.bin"
    _write_cache(path, firmware.data)
    tested = "tested with this tool" if firmware.tested else "NOT yet tested with this tool"
    log.info(
        f"Firmware {firmware.version} ({len(firmware.data) / 1e6:.1f} MB) from Babysense updater "
        f"{firmware.updater_version}: matches Babysense's own checksum; {tested}."
    )
    if not firmware.tested:
        log.warning(UNTESTED_WARNING)
    return firmware, path


def prepare_privileged(libusb_loader: Callable[..., Any] = load_libusb) -> None:
    """Checks before asking for sudo: Apple's Python exists; our files and libusb are only yours to change."""
    if not os.path.exists(C.ROOT_PYTHON):
        raise OSError(f"{C.ROOT_PYTHON} is missing. Install Apple's Command Line Tools with: xcode-select --install")
    owners = {0, os.getuid()}
    trust.check_tree(REPO_DIR, owners)
    libusb_loader(owners=owners)


def run_privileged(
    device_args: list[str], label: str, popen: Callable[..., Any] = subprocess.Popen, log_dir: Path = LOG_DIR
) -> int:
    """Run `babysense-update _device ...` under sudo with Apple's Python, echoing and saving its output."""
    log_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    log_path = log_dir / f"{label}-{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}.log"
    command = [C.SUDO, C.ROOT_PYTHON, "-I", "-B", str(LAUNCHER), "_device", *device_args]
    log.info("Talking to the parent unit over USB needs administrator rights: enter your Mac password if asked.")
    with (
        open(log_path, "w", encoding="utf-8") as transcript,
        popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1) as process,
    ):
        for line in process.stdout:
            log.info(line.rstrip("\n"))
            transcript.write(line)
        code = process.wait()
    if code < 0:
        log.error(f"The administrator step was stopped (signal {-code}). Do NOT press RESET.")
        code = 1
    log.info(f"(A log of this run is saved at {log_path})")
    return code


def cmd_install(
    args: argparse.Namespace, ask: Callable[[str], str] = input, privileged: Callable[..., int] = run_privileged
) -> int:
    firmware, path = fetch_firmware(args.allow_untested_firmware)
    log.info("")
    log.info(SAFETY_CHECKLIST)
    try:
        confirmed = args.yes or ask("\nType UPDATE to continue: ").strip() == "UPDATE"
    except EOFError:
        confirmed = False
    if not confirmed:
        log.info("Cancelled. Nothing was changed.")
        return 1
    extra = ["--allow-untested-device"] if args.allow_untested_device else []
    extra += [] if firmware.tested else ["--allow-untested-firmware"]
    code = privileged(["install", "--firmware", str(path), "--sha256", firmware.sha256, *extra], "install")
    if code == 0:
        log.info("")
        log.info(NEXT_STEPS)
    return code


def cmd_simulate(args: argparse.Namespace) -> int:
    data = args.firmware.read_bytes() if args.firmware else fetch_firmware(args.allow_untested_firmware)[0].data
    if not args.image.exists():
        simulate.create_device_image(args.image)
        log.info(f"Created a fresh copy of the parent unit's drive layout at {args.image}")
    elif not simulate.looks_like_device_image(args.image):
        raise fat16.FatError(f"{args.image} is not a parent-unit image made by this tool; give a new file path")
    with simulate.ImageDevice(args.image) as image:
        result = installer.install(image, data, log.info, expect_capture=False)
    log.info(
        f"Simulation complete: firmware.bin is in clusters {result.first_cluster}-"
        f"{result.first_cluster + result.clusters - 1} of {args.image}. Open the image in Finder to look."
    )
    return 0


def _device_check(scsi: BulkOnlyScsi) -> int:
    info = device.identify(scsi)
    summary = device.summarize(scsi, info)
    log.info(
        f"Parent unit found: {info.vendor} {info.product} ({info.revision}), "
        f"{info.megabytes:.1f} MB update drive labelled {summary.volume_label!r}."
    )
    log.info(f"Entries on the drive: {', '.join(summary.files) or '(none)'}")
    try:
        device.check_supported(info)
        log.info("This unit matches the tested hardware and is ready to update.")
    except device.UnsupportedDevice as exc:
        log.info(f"Note: {exc}")
    return 0


def _device_install(scsi: BulkOnlyScsi, firmware: bytes, allow_untested_device: bool) -> int:
    result = installer.install(scsi, firmware, log.info, allow_untested_device=allow_untested_device)
    log.info(
        f"All {len(firmware) / 1e6:.1f} MB were accepted at {result.megabytes_per_second:.2f} MB/s, the speed at "
        f"which the parent unit stores data, in {result.seconds / 60:.1f} minutes (flush: {result.flush})."
    )
    log.info("SUCCESS")
    return 0


def _device_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="babysense-update _device")
    parser.add_argument("action", choices=["check", "install"])
    parser.add_argument("--firmware", type=Path)
    parser.add_argument("--sha256", default="")
    parser.add_argument("--allow-untested-device", action="store_true")
    parser.add_argument("--allow-untested-firmware", action="store_true")
    return parser


def _load_firmware_as_root(args: argparse.Namespace) -> bytes:
    if args.action != "install":
        return b""
    if args.sha256 not in C.TESTED_FIRMWARE and not args.allow_untested_firmware:
        raise package.UntestedFirmware("this firmware has not been tested with this tool")
    return package.load_verified(args.firmware, args.sha256, trust.invoking_owners())


def device_main(
    argv: Sequence[str],
    loader: Callable[..., Any] = load_libusb,
    opener: Callable[..., Any] = UsbDevice.open,
    require_root: bool = True,
) -> int:
    """The privileged part. Run only via sudo by run_privileged()."""
    parser = _device_parser()
    args = parser.parse_args(list(argv))
    if args.action == "install" and (args.firmware is None or not args.sha256):
        parser.error("install needs --firmware and --sha256")
    configure_logging()
    sys.dont_write_bytecode = True
    if require_root and os.geteuid() != 0:
        log.error("This step must run through sudo.")
        return 1
    try:
        firmware = _load_firmware_as_root(args)
        lib = loader(owners=trust.invoking_owners())
        log.info("Waiting for the parent unit: connect it with the USB-C data cable and turn it on...")
        with opener(lib, C.USB_VENDOR_ID, C.USB_PRODUCT_ID, C.USB_INTERFACE, C.DEVICE_WAIT_SECONDS) as usb:
            ep_in, ep_out = parse_bulk_endpoints(usb.config_descriptor(), C.USB_INTERFACE)
            usb.take_interface()
            scsi = BulkOnlyScsi(usb, ep_in, ep_out, allow_writes=args.action == "install")
            if args.action == "check":
                return _device_check(scsi)
            return _device_install(scsi, firmware, args.allow_untested_device)
    except installer.InstallAborted as exc:
        log.error(f"STOPPED: {exc}")
        return 2
    except (
        LibusbMissing,
        TransportError,
        ScsiError,
        device.UnsupportedDevice,
        fat16.FatError,
        package.PackageError,
        trust.UntrustedFile,
        OSError,
    ) as exc:
        log.error(f"Error: {exc}")
        if args.action == "install":
            log.error(NOTHING_SENT)
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    configure_logging()
    if arguments[:1] == ["_device"]:
        return device_main(arguments[1:])
    args = build_parser().parse_args(arguments)
    if sys.platform != "darwin":
        log.warning("Note: this tool is made and tested for macOS.")
    if os.geteuid() == 0:
        log.error("Please run this without sudo; it asks for your password only for the USB step.")
        return 1
    try:
        if args.command in ("check", "install"):
            prepare_privileged()
        if args.command == "check":
            return run_privileged(["check"], "check")
        if args.command == "fetch":
            fetch_firmware(args.allow_untested_firmware)
            return 0
        if args.command == "install":
            return cmd_install(args)
        return cmd_simulate(args)
    except KeyboardInterrupt:
        log.error("Interrupted. Do NOT press RESET unless the tool printed SUCCESS.")
        return 130
    except (
        store.StoreError,
        package.PackageError,
        installer.InstallAborted,
        device.UnsupportedDevice,
        fat16.FatError,
        LibusbMissing,
        trust.UntrustedFile,
        OSError,
    ) as exc:
        log.error(f"Error: {exc}")
        return 1
