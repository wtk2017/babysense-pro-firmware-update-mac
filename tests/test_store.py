import base64
import hashlib
import html
import io
import json
import ssl
import urllib.request

import pytest

from babysense_mac import store

pytestmark = pytest.mark.unit
IDENTITY = "Babysense.BabysensePro-FirmwareUpdate_1.0.74.0_x64__sm2jydt73ezre"
PAYLOAD = b"msix-bytes" * 1000
SHA1 = base64.b64encode(hashlib.sha1(PAYLOAD).digest()).decode()  # noqa: S324 - mirrors Microsoft's digest format
LINK = "http://tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/abc?P1=1&P2=2"
TARGET = store.PackageFile("x.msix", len(PAYLOAD), SHA1, "pkg", "7")


def catalog(**changes):
    package = {
        "PackageFamilyName": "Babysense.BabysensePro-FirmwareUpdate_sm2jydt73ezre",
        "PackageFullName": IDENTITY,
        "PackageFormat": "Msix",
        "MaxDownloadSizeInBytes": len(PAYLOAD),
        "FulfillmentData": json.dumps({"WuCategoryId": "f2d4ce0a-e949-4283-a7b9-497909976559"}),
    }
    package.update(changes)
    packages = [{"PackageFamilyName": "Other_123", "PackageFullName": "Other"}, package]
    return {"Products": [{"DisplaySkuAvailabilities": [{"Sku": {"Properties": {"Packages": packages}}}]}]}


def update_info(number, update_id, revision):
    identity = html.escape(f'<UpdateIdentity UpdateID="{update_id}" RevisionNumber="{revision}"/>')
    return f"<UpdateInfo><ID>{number}</ID><Xml>{identity}</Xml></UpdateInfo>"


def sync_response(update_ids, package=False, file_name="abc.msix"):
    infos = "".join(update_info(number, f"u{number}", 1) for number in update_ids)
    updates = ""
    if package:
        infos += update_info(900, "pkg", 7)
        files = (
            f'<Files><File FileName="{file_name}" Size="{len(PAYLOAD)}" Digest="{SHA1}" '
            f'InstallerSpecificIdentifier="{IDENTITY}"/></Files>'
        )
        updates = f"<Update><ID>900</ID><Xml>{html.escape(files)}</Xml></Update>"
    return (
        f"<Envelope><Body><SyncUpdatesResponse><NewUpdates>{infos}</NewUpdates>"
        f"<ExtendedUpdateInfo><Updates>{updates}</Updates></ExtendedUpdateInfo></SyncUpdatesResponse></Body></Envelope>"
    )


URLS_RESPONSE = (
    "<Envelope><Body><FileLocations>"
    "<FileLocation><Url>http://evil.example.com/x</Url></FileLocation>"
    f"<FileLocation><Url>{html.escape(LINK)}</Url></FileLocation>"
    "</FileLocations></Body></Envelope>"
)
COOKIE = "<Envelope><Body><GetCookieResult><EncryptedData>c00kie==</EncryptedData></GetCookieResult></Body></Envelope>"


class FakeHttp:
    def __init__(self, soap=None, lengths=None, payload=PAYLOAD, catalog_doc=None):
        self.soap, self.bodies = list(soap or []), []
        self.lengths = lengths if lengths is not None else {LINK: len(PAYLOAD)}
        self.payload, self.catalog = payload, catalog_doc or catalog()

    def get_json(self, url):
        return self.catalog

    def post_soap(self, url, body):
        self.bodies.append(body)
        return self.soap.pop(0)

    def head_length(self, url):
        return self.lengths.get(url, -1)

    def stream(self, url):
        yield self.payload[:5000]
        yield self.payload[5000:]


def test_catalog_lookup_finds_babysense_package():
    package = store.catalog_lookup(FakeHttp())
    assert (package.full_name, package.size, package.package_format) == (IDENTITY, len(PAYLOAD), "Msix")
    assert package.category_id == "f2d4ce0a-e949-4283-a7b9-497909976559"


@pytest.mark.parametrize(
    "change, message",
    [
        ({"PackageFormat": "EMsix"}, "encrypted"),
        ({"FulfillmentData": {"WuCategoryId": "nope"}}, "no update category"),
        ({"FulfillmentData": "{not json"}, "expected format"),
        ({"MaxDownloadSizeInBytes": "lots"}, "expected format"),
        ({"PackageFamilyName": "Unrelated_1"}, "not found"),
    ],
)
def test_catalog_lookup_refuses_unusable_entries(change, message):
    with pytest.raises(store.StoreError, match=message):
        store.catalog_lookup(FakeHttp(catalog_doc=catalog(**change)))


def test_catalog_lookup_handles_odd_shapes_and_names():
    with pytest.raises(store.StoreError, match="expected format"):
        store.catalog_lookup(FakeHttp(catalog_doc={"Products": "nope"}))
    package = store.catalog_lookup(FakeHttp(catalog_doc=catalog(PackageFullName="../../evil name")))
    assert package.full_name == "babysense-updater"


def test_cookie_and_iterative_sync_like_windows_update():
    http = FakeHttp(soap=[COOKIE, sync_response([11, 12]), sync_response([13]), sync_response([], True)])
    cookie = store.get_cookie(http)
    files = store.sync_package_files(http, cookie, "cat")
    assert cookie == "c00kie=="
    assert files == [store.PackageFile(f"{IDENTITY}_abc.msix", len(PAYLOAD), SHA1, "pkg", "7")]
    assert "<int>11</int><int>12</int>" in http.bodies[2] and "<int>13</int>" in http.bodies[3]
    assert "<InstalledNonLeafUpdateIDs></InstalledNonLeafUpdateIDs>" in http.bodies[1]


def test_sync_gives_up_when_nothing_new_and_errors_are_clear():
    with pytest.raises(store.StoreError, match="did not return Babysense's package"):
        store.sync_package_files(FakeHttp(soap=[sync_response([1]), sync_response([1])]), "c", "cat")
    with pytest.raises(store.StoreError, match="cookie"):
        store.get_cookie(FakeHttp(soap=["<Envelope/>"]))
    with pytest.raises(store.StoreError, match="unexpected response"):
        store.sync_package_files(FakeHttp(soap=["<not xml"]), "c", "cat")


def test_file_urls_keep_query_strings_and_choose_url_filters_hosts():
    http = FakeHttp(soap=[URLS_RESPONSE])
    urls = store.file_urls(http, "pkg", "7")
    assert urls == ["http://evil.example.com/x", LINK]
    assert store.choose_url(http, urls, len(PAYLOAD)) == LINK
    with pytest.raises(store.StoreError, match="no matching"):
        store.choose_url(FakeHttp(lengths={}), urls, len(PAYLOAD))


def test_download_verifies_size_and_digest(tmp_path):
    said = []
    store.download(FakeHttp(), LINK, tmp_path / "x.msix", TARGET, said.append)
    assert (tmp_path / "x.msix").read_bytes() == PAYLOAD
    with pytest.raises(store.StoreError, match="did not match"):
        store.download(FakeHttp(payload=b"tampered" * 10), LINK, tmp_path / "y.msix", TARGET, said.append)
    assert not (tmp_path / "y.msix").exists() and not (tmp_path / "y.msix.part").exists()


def test_download_stops_early_when_too_big_or_too_slow(tmp_path):
    with pytest.raises(store.StoreError, match="larger"):
        store.download(FakeHttp(payload=PAYLOAD * 3), LINK, tmp_path / "big.msix", TARGET, print)
    ticks = iter([0, store.DOWNLOAD_DEADLINE_SECONDS + 1, store.DOWNLOAD_DEADLINE_SECONDS + 2])
    with pytest.raises(store.StoreError, match="too long"):
        store.download(FakeHttp(), LINK, tmp_path / "slow.msix", TARGET, print, clock=lambda: next(ticks))
    assert list(tmp_path.iterdir()) == []


def test_fetch_returns_verified_bytes_and_reuses_the_cache(tmp_path):
    soap = [COOKIE, sync_response([], True), URLS_RESPONSE]
    said = []
    assert store.fetch_updater_package(tmp_path, said.append, FakeHttp(soap=list(soap))) == PAYLOAD
    assert any("Downloading" in s for s in said)
    said.clear()
    assert store.fetch_updater_package(tmp_path, said.append, FakeHttp(soap=list(soap))) == PAYLOAD
    assert any("downloaded earlier" in s for s in said)


def test_fetch_refuses_a_package_that_changed_on_disk(tmp_path, monkeypatch):
    def sloppy_download(http, url, destination, expected, say):
        destination.write_bytes(b"swapped")

    monkeypatch.setattr(store, "download", sloppy_download)
    with pytest.raises(store.StoreError, match="changed on disk"):
        store.fetch_updater_package(tmp_path, print, FakeHttp(soap=[COOKIE, sync_response([], True), URLS_RESPONSE]))


def test_fetch_refuses_when_no_msix_is_listed(tmp_path):
    no_msix = sync_response([], True, file_name="abc.blockmap")
    with pytest.raises(store.StoreError, match="no .msix"):
        store.fetch_updater_package(tmp_path, print, FakeHttp(soap=[COOKIE, no_msix]))


def test_url_policies():
    assert store.is_download_url(LINK)
    assert store.is_download_url("http://dl.delivery.mp.microsoft.com/filestreamingservice/files/x")
    for bad in (
        "ftp://tlu.dl.delivery.mp.microsoft.com/x",
        "http://delivery.mp.microsoft.com.evil.com/x",
        "https://fe3.delivery.mp.microsoft.com/x",
        "http://evil.example.com/?x=.dl.delivery.mp.microsoft.com",
    ):
        assert not store.is_download_url(bad)
    assert store.check_fe3(store.FE3_URL) == store.FE3_URL
    for check, url in (
        (store.check_catalog, "http://displaycatalog.mp.microsoft.com/x"),
        (store.check_catalog, "https://example.com/x"),
        (store.check_fe3, "https://example.com/x"),
        (store.check_download, "https://example.com/x"),
    ):
        with pytest.raises(store.StoreError, match="refusing"):
            check(url)


def test_redirects_must_stay_on_allowed_hosts():
    guard = store.RedirectGuard(store.check_download)
    request = urllib.request.Request(LINK)
    with pytest.raises(store.StoreError):
        guard.redirect_request(request, None, 302, "Found", {}, "https://evil.example.com/x")
    moved = guard.redirect_request(request, None, 302, "Found", {}, "http://dl.delivery.mp.microsoft.com/y")
    assert moved.full_url == "http://dl.delivery.mp.microsoft.com/y"


def test_tls_contexts():
    pinned = store.microsoft_update_tls_context()
    assert pinned.verify_mode == ssl.CERT_REQUIRED and pinned.check_hostname
    assert [c["subject"] for c in pinned.get_ca_certs()] == [
        c["subject"] for c in pinned.get_ca_certs() if "Microsoft Root Certificate Authority 2011" in str(c)
    ]
    assert len(pinned.get_ca_certs()) == 1
    assert isinstance(store.public_tls_context(), ssl.SSLContext)
    assert "ClientWebService/SyncUpdates</a:Action>" in store.soap_envelope("SyncUpdates", store.FE3_URL, "<x/>")


class FakeResponse(io.BytesIO):
    headers = {"Content-Length": "123"}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_http_client_uses_the_right_trust_and_guards(monkeypatch):
    seen = []

    class FakeOpener:
        def __init__(self, handlers):
            self.handlers = handlers

        def open(self, request, timeout):
            seen.append((request.get_method(), request.full_url, self.handlers))
            return FakeResponse(b"not json" if "bad" in request.full_url else b'{"ok": true}')

    monkeypatch.setattr(store.urllib.request, "build_opener", lambda *handlers: FakeOpener(handlers))
    public, pinned = ssl.create_default_context(), store.microsoft_update_tls_context()
    http = store.Http(public=public, pinned=pinned)
    assert http.get_json(store.CATALOG_URL.format(product="x")) == {"ok": True}
    assert http.post_soap(store.FE3_URL, "<x/>") == '{"ok": true}'
    assert http.head_length(LINK) == 123
    assert b"".join(http.stream(LINK)) == b'{"ok": true}'
    assert [m for m, _, _ in seen] == ["GET", "POST", "HEAD", "GET"]
    assert seen[1][2][0]._context is pinned and seen[0][2][0]._context is public
    assert all(isinstance(handlers[1], store.RedirectGuard) for _, _, handlers in seen)
    with pytest.raises(store.StoreError, match="unexpected"):
        http.get_json("https://displaycatalog.mp.microsoft.com/bad")
    with pytest.raises(store.StoreError, match="refusing"):
        http.post_soap("https://example.com/", "<x/>")
