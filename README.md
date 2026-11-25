# Babysense Pro firmware update on a Mac (fixes the "Battery Condition Warning")

Install Babysense's **official** firmware update on a **Babysense Pro (MaxView Pro)** baby monitor
parent unit from a **Mac**. You don't need a Windows PC, a virtual machine or Babysense's app.

[![tests](https://github.com/wtk2017/babysense-pro-firmware-update-mac/actions/workflows/tests.yml/badge.svg)](https://github.com/wtk2017/babysense-pro-firmware-update-mac/actions/workflows/tests.yml)

> **Is your parent unit showing this?**
>
> **BATTERY CONDITION WARNING.** *The Battery In The Parent Unit Is In Poor Condition. Disconnect
> Your Power Adapter. The Unit Will Power OFF Automatically.* (with a "Scan For Support" QR code)
>
> The monitor beeps, shows this screen and switches itself off, whether or not it's plugged in,
> and pressing RESET doesn't make it go away.

When we contacted Babysense support about this warning, they explained it comes from an overly
cautious battery check in the parent unit's software, and that the fix is their firmware update.
Their updater only runs on a Windows PC, though, and their FAQ says a Mac can't be used. This
tool installs the **same official update** from a Mac.

**Unofficial project.** It isn't made, endorsed or supported by Babysense. Babysense's own
options are their Windows updater and their support team.

## Contents

- [What this tool does](#what-this-tool-does)
- [Safety first](#safety-first)
- [Security and what runs as root](#security-and-what-runs-as-root)
- [What you need](#what-you-need)
- [Update your parent unit step by step](#update-your-parent-unit-step-by-step)
- [How to tell it worked](#how-to-tell-it-worked)
- [If something goes wrong](#if-something-goes-wrong)
- [FAQ](#faq)
- [Tested with](#tested-with)
- [How it works](#how-it-works)
- [For developers](#for-developers)
- [Disclaimer](#disclaimer)

## What this tool does

1. It downloads Babysense's own updater, "Babysense Pro - Firmware Update", from Microsoft's
   official Store servers and checks it. Then it takes the firmware file out. **It never runs
   Babysense's app** and never changes the firmware.
2. It copies that firmware onto the parent unit over USB, exactly as Babysense's Windows updater
   does, as a file named `firmware.bin`.
3. You then unplug the cable and press RESET, as Babysense's updater instructs, and the parent
   unit installs the update itself.

It doesn't switch off or bypass the battery check. The check stays in Babysense's firmware, so if
the battery really is failing, the monitor will still warn you.

## Safety first

These points follow Babysense's own guidance:

- **Don't update if the battery looks swollen** (the case bulges or the screen is lifting), if the
  unit gets hot, or if it has been dropped or damaged. Contact Babysense support instead.
- Use a **USB-C data cable** (one that can transfer files, not a charge-only cable) plugged
  straight into your Mac.
- **Never press RESET unless the tool printed `SUCCESS`.** If anything stops early, turn the
  parent unit off and on again and run the install again.
- If the battery warning comes back **after** the update, the battery itself may be worn out.
  Contact Babysense support.
- This tool is provided as is, with no warranty. You use it at your own risk.

## Security and what runs as root

- **Your Mac password gives this tool's code administrator (root) rights for the USB step.**
  macOS only lets an administrator take the parent unit away from its own disk driver. That step
  runs this folder's Python code with Apple's built-in Python, and loads Homebrew's libusb.
- **Only run a copy you downloaded from this page, kept in your own user folder.** Before asking
  for your password, the tool checks that its files and libusb belong to you and can't be changed
  by other users, and stops if they can. It can't protect against malware already running as you.
- **The download uses plain HTTP, like Windows Update.** Microsoft's download servers don't offer
  working HTTPS. The tool accepts the package only if it matches the size and checksum Microsoft's
  update service sends over a secure connection that trusts only Microsoft's own root certificate.
  The firmware inside must also match the exact SHA-256 this tool was tested with.
- **`--allow-untested-firmware` is weaker.** It lets you use newer Babysense firmware this tool
  hasn't been tested with; then only Microsoft's checksum vouches for it. The tool warns you when
  you use it.

The full details are in [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md).

## What you need

- A Mac (Apple silicon or Intel) with your admin password
- [Homebrew](https://brew.sh) and libusb (step 1 below)
- A USB-C data cable
- About 15 minutes. The transfer itself takes about 5.

## Update your parent unit step by step

**1. Install libusb (once).** If you don't have Homebrew, install it from [brew.sh](https://brew.sh)
first. Then, in Terminal:

```bash
brew install libusb
```

**2. Download this tool.**

```bash
git clone https://github.com/wtk2017/babysense-pro-firmware-update-mac.git
```

```bash
cd babysense-pro-firmware-update-mac
```

(Or click **Code → Download ZIP**, unzip it, and `cd` into the folder.)

**3. Optional: check that your Mac can see the parent unit.** This step only reads.

```bash
./babysense-update check
```

Enter your Mac password when asked. Then connect the parent unit with the USB-C data cable and turn
it on. You should see `Parent unit found: SONiXTek 510PF` and `ready to update`.

**4. Install the update.**

```bash
./babysense-update install
```

The tool downloads Babysense's updater from Microsoft (65 MB) and verifies the firmware. It then
shows a short safety checklist and asks you to type `UPDATE`. Enter your Mac password, then connect
and turn on the parent unit when asked. The tool copies the firmware in four steps; the last one
takes about 5 minutes. The parent unit's screen may show lines or look distorted while it's
connected. Babysense says this is normal. **Leave the cable connected until you see `SUCCESS`.**

**5. Finish the update as Babysense's updater instructs.**

1. Unplug the USB-C cable from the parent unit.
2. Press the **RESET** button on the back of the parent unit (a pinhole on the back of the antenna)
   with a pin.
3. Turn the parent unit on and let it finish. Don't press anything if the screen stays blank for a
   while.

**6. Re-pair your cameras.** The update clears the pairing. On the parent unit, go to
**Menu → Camera Settings → Pair Camera**, choose the camera (1 to 4) and confirm. Keep the camera
plugged in and close to the parent unit while pairing. See Babysense's guide:
[Pairing & Unpairing Cameras](https://helpcenter.babysensemonitors.com/hc/en-us/articles/28621279077148-Babysense-Pro-Pairing-Unpairing-Cameras-Steps).

**7. Charge it fully** with the Babysense power adapter. This takes about 8 hours, and the light
turns green when it's full. See
[Charging Your Babysense Pro Parent Unit](https://helpcenter.babysensemonitors.com/hc/en-us/articles/28611445517340-Charging-Your-Babysense-Pro-Parent-Unit-and-Understanding-Battery-Life).

## How to tell it worked

- The battery warning no longer appears when you turn the parent unit on.
- Your cameras show live video again after re-pairing.
- Babysense says this update adds new features "such as LED control", so look for it in the menu.

Before you rely on the monitor, leave it running on battery for a few hours. Babysense rates the
battery at up to 12 hours of continuous video, or up to 20 with VOX mode on.

## If something goes wrong

| The tool says | What it means | What to do |
|---|---|---|
| `libusb was not found` | libusb isn't installed | Run `brew install libusb` |
| `the parent unit did not appear on USB` | Nothing was detected within 10 minutes | Use a data cable, plug it straight into the Mac, and turn the parent unit on |
| `this is not a Babysense Pro parent unit drive` | A different device answered | This tool only supports the Babysense Pro parent unit |
| `this unit's drive has … sectors; the tested unit has 990400` | Your unit differs from the one tested | Nothing was written. Please [open an issue](../../issues/new/choose) with the output of `check` |
| `The parent unit did not register firmware.bin` | The unit didn't accept the new file | **Don't press RESET.** Turn it off and on and run `install` again |
| `accepted the data at … MB/s … discarded it` | The unit took the data too fast to have stored it | **Don't press RESET.** Turn it off and on and run `install` again |
| `The transfer stopped after … MB` | The cable came out or the unit switched off | **Don't press RESET.** Turn it off and on and run `install` again |
| `firmware Vxxxx … has not been tested` | Babysense has released newer firmware | Wait for this tool to be updated, or open an issue |

Each run's log is saved in `~/Library/Logs/babysense-pro-firmware-update-mac/`.

## FAQ

### Can I update a Babysense Pro baby monitor on a Mac?

Yes, with this tool. Babysense's own updater is a Windows-only Microsoft Store app, and Babysense's
FAQ says the update needs a Windows computer. This tool does the same update from macOS.

### Why does the update need a computer at all?

Babysense delivers this update by copying a file onto the parent unit over a USB-C data cable.
The monitor installs it after you press RESET. There's no over-the-air update.

### Why doesn't my parent unit show up in Finder when I plug it into my Mac?

The parent unit's update drive isn't a normal disk. Its firmware generates it on the fly, and
macOS's disk driver gives up on it after a few seconds, so nothing appears in Finder or Disk
Utility. This tool skips that driver and talks to the parent unit directly over USB. That's why it
needs your password (`sudo`).

### Does this bypass or disable the battery warning?

No. It installs Babysense's unmodified official firmware, which is the fix Babysense support
recommends for this warning. The battery check stays in place.

### Where does the firmware come from? Does it download anything from third parties?

Only from Microsoft's official Store servers, the same place the Microsoft Store app gets
Babysense's updater. The tool checks the download against Microsoft's checksum. It also confirms
the package is Babysense's, and checks the firmware against Babysense's own SHA-256 checksum and the
value this tool was tested with. The firmware itself isn't stored in this repository. See
[Security and what runs as root](#security-and-what-runs-as-root).

### Which models does it work with?

It has only been tested on the **Babysense Pro (MaxView Pro)** parent unit with the 5.5" HD 1080p
screen. The tool identifies the unit by its USB ID and refuses anything else. Other Babysense
monitors such as the MaxView, HD S2 or V43 use different hardware and aren't supported.

### Do I need to re-pair my cameras?

Yes. The update clears the pairing. Go to **Menu → Camera Settings → Pair Camera**, then choose the
camera and confirm.

### How long does it take?

About 15 minutes in total. The transfer itself takes about 5 minutes, because the parent unit
writes the 32 MB firmware to its memory slowly.

### Is this supported by Babysense?

No. It's an independent, open-source project. If you'd rather not use it, Babysense's support
team can help, and their FAQ says to contact them if you don't have a Windows computer.

## Tested with

| | |
|---|---|
| Parent unit | Babysense Pro (MaxView Pro), 5.5" HD 1080p, 2-camera kit |
| USB device | `0c45:8801`, "SN93701PU" (SONiX), drive "SONiXTek 510PF" |
| Firmware | `V0207`, SHA-256 `a7254a99579aff09157b724817b5adb5565ab5f53f4724d92dce38b0bf9c2ad1` |
| Babysense updater | "Babysense Pro - Firmware Update" 1.0.74.0 (Microsoft Store `9PNMTNWPRKL5`) |
| Mac | macOS 26 on Apple silicon; Python 3.9 (built into macOS) and 3.12 |

Result on the test unit: the battery warning cleared after the update, and the cameras needed
re-pairing.

## How it works

The parent unit's USB drive is generated by its firmware. It only keeps data written into a file
it already knows about, so the copy has to happen in the same order Windows Explorer uses. The
tool also checks that the unit registered the file, and watches the transfer speed to confirm the
data is really being stored. For the full story, see [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md).

## For developers

No dependencies beyond the Python standard library and libusb (loaded with `ctypes`).

```bash
python3 -m pytest --cov=babysense_mac
```

```bash
./babysense-update simulate --image /tmp/parent-unit.img --firmware some-file.bin
```

`simulate` runs the whole install against a disk image laid out like the parent unit's drive, with
no hardware and no `sudo`. You can open the result in Finder. The tests include a model of the
parent unit's observed behavior, and an end-to-end check with macOS's own `fsck_msdos` and
`hdiutil`.

| Module | Role |
|---|---|
| `store.py` | Fetches Babysense's package from Microsoft's Store servers and verifies it |
| `package.py` | Extracts and verifies the firmware inside the package |
| `usb_libusb.py`, `scsi.py` | Talk to the parent unit over USB mass storage (with a command allowlist) |
| `fat16.py`, `installer.py` | Plan and perform the copy, guarded to only the planned sectors |
| `cli.py` | `check`, `fetch`, `install`, `simulate` |

## Disclaimer

"Babysense", "Babysense Pro" and "MaxView" are trademarks of their owners. They're used here only
to describe compatibility. This project isn't affiliated with Babysense, SONiX or Microsoft. Babysense's firmware and updater aren't included in or redistributed by this
repository: each user's Mac downloads them directly from Microsoft's official servers. No
warranty: see [LICENSE](LICENSE) (MIT).
