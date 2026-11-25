"""Live checks against Microsoft's servers. Not run by default: `pytest -m network`.

They resolve Babysense's package and its download link (a HEAD request) but download nothing.
"""

import pytest

from babysense_mac import store

pytestmark = pytest.mark.network


def test_microsoft_still_serves_babysense_updater():
    http = store.Http()
    package = store.catalog_lookup(http)
    assert package.full_name.startswith("Babysense.BabysensePro-FirmwareUpdate_")
    files = store.sync_package_files(http, store.get_cookie(http), package.category_id)
    target = next(f for f in files if f.name.endswith(".msix"))
    url = store.choose_url(http, store.file_urls(http, target.update_id, target.revision), target.size)
    assert store.is_download_url(url)
