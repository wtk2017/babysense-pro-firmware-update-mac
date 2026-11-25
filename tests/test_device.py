import pytest

from babysense_mac import device
from babysense_mac.scsi import BulkOnlyScsi
from tests.fakes import FakeBotDevice, VirtualDrive

pytestmark = pytest.mark.unit


def scsi_for(**kwargs):
    return BulkOnlyScsi(FakeBotDevice(VirtualDrive(), **kwargs), 0x8C, 0x0D)


def test_identify_reads_the_parent_unit():
    info = device.identify(scsi_for(ready_after=2), sleep=lambda s: None)
    assert (info.vendor, info.product, info.revision, info.removable) == ("SONiXTek", "510PF", "rev1", True)
    assert (info.sectors, info.sector_size, info.write_protected) == (990_400, 512, False)
    assert round(info.megabytes, 1) == 507.1


def test_identify_rejects_other_drives_and_never_ready():
    with pytest.raises(device.UnsupportedDevice, match="not a Babysense"):
        device.identify(scsi_for(vendor=b"SanDisk "))
    with pytest.raises(device.UnsupportedDevice, match="never became ready"):
        device.identify(scsi_for(ready_after=50), attempts=3, sleep=lambda s: None)

    class Short:
        def inquiry(self):
            return b"short"

    with pytest.raises(device.UnsupportedDevice, match="short"):
        device.identify(Short())


def test_check_supported():
    tested = device.identify(scsi_for())
    assert device.check_supported(tested) == []
    other = device.identify(scsi_for(sectors=1_000_000))
    with pytest.raises(device.UnsupportedDevice, match="Stopping to be safe"):
        device.check_supported(other)
    assert "1000000 sectors" in device.check_supported(other, allow_untested=True)[0]
    with pytest.raises(device.UnsupportedDevice, match="write-protected"):
        device.check_supported(device.identify(scsi_for(write_protected=True)))
    with pytest.raises(device.UnsupportedDevice, match="removable"):
        device.check_supported(device.identify(scsi_for(removable=False)))
    odd = device.DriveInfo("SONiXTek", "510PF", "rev1", True, 990_400, 4096, False)
    with pytest.raises(device.UnsupportedDevice, match="sector size"):
        device.check_supported(odd)


def test_summarize_lists_label_and_marker():
    s = scsi_for()
    summary = device.summarize(s, device.identify(s))
    assert summary.volume_label == "SN93701PU"
    assert summary.files == ("01.00.01.051",)
    assert summary.geometry.first_data_sector == 520


def test_short_reads_are_errors():
    class Truncating:
        def read10(self, lba, count, block=512):
            return bytes(100)

    with pytest.raises(OSError, match="short read"):
        device.read_sectors(Truncating(), 0, 1)
