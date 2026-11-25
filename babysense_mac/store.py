"""Download Babysense's official updater package from Microsoft's Store servers.

Uses the same public services the Microsoft Store app uses:
  1. displaycatalog.mp.microsoft.com  - product details (package name, size, update category)
  2. fe3.delivery.mp.microsoft.com    - Windows Update sync, which returns the download link
  3. *.dl.delivery.mp.microsoft.com   - the package itself
Nothing is installed or run; the package is only unpacked later to read the firmware.

Trust: connections to the Windows Update service accept only Microsoft Root
Certificate Authority 2011 (certificate pinning). That service supplies the
package's size and SHA-1 digest. Like Windows Update, Microsoft serves the
package itself over plain HTTP (its download hosts don't offer working HTTPS),
so the download is accepted only if it matches that size and digest. Redirects
are refused unless they stay on an allowed host. Later, the firmware's SHA-256
must also match the tested list in constants.TESTED_FIRMWARE.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import re
import ssl
import time
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator
from xml.dom import minidom
from xml.parsers.expat import ExpatError

from . import constants as C

CATALOG_URL = "https://displaycatalog.mp.microsoft.com/v7.0/products?bigIds={product}&market=US&languages=en-US"
CATALOG_HOST = "displaycatalog.mp.microsoft.com"
FE3_HOST = "fe3.delivery.mp.microsoft.com"
FE3_URL = f"https://{FE3_HOST}/ClientWebService/client.asmx"
FE3_SECURED_URL = FE3_URL + "/secured"
DOWNLOAD_HOST, DOWNLOAD_HOST_SUFFIX = "dl.delivery.mp.microsoft.com", ".dl.delivery.mp.microsoft.com"
MAX_SYNC_ROUNDS = 6
HTTP_TIMEOUT_SECONDS = 60
DOWNLOAD_DEADLINE_SECONDS = 30 * 60
DOWNLOAD_CHUNK = 1 << 20
REPORT_STEP = 8 << 20
SAFE_NAME = re.compile(r"[A-Za-z0-9._-]{1,200}")
CERT_FILE = Path(__file__).resolve().parent / "certs" / "microsoft-root-ca-2011.pem"
SYSTEM_CERTS = "/etc/ssl/cert.pem"
DEVICE_ATTRIBUTES = (
    "E:App=WU&AppVer=10.0.19041.1&DeviceFamily=Windows.Desktop&FlightRing=Retail&InstallationType=Client"
    "&IsFlightingEnabled=0&OSArchitecture=AMD64&OSVersion=10.0.19041.1"
)
NS_ADDRESSING = "http://www.w3.org/2005/08/addressing"
NS_SOAP = "http://www.w3.org/2003/05/soap-envelope"
NS_SECURITY = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
NS_UTILITY = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
NS_WU_AUTH = "http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization"
NS_CLIENT = "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService"

Say = Callable[[str], None]


class StoreError(RuntimeError):
    """The official package could not be located or downloaded safely."""


@dataclass(frozen=True)
class CatalogPackage:
    full_name: str
    category_id: str
    size: int
    package_format: str


@dataclass(frozen=True)
class PackageFile:
    name: str
    size: int
    sha1_base64: str
    update_id: str
    revision: str


def public_tls_context() -> ssl.SSLContext:
    """The system trust store (for the public product catalog)."""
    context = ssl.create_default_context()
    if os.path.exists(SYSTEM_CERTS):
        context.load_verify_locations(cafile=SYSTEM_CERTS)
    return context


def microsoft_update_tls_context() -> ssl.SSLContext:
    """Only Microsoft Root Certificate Authority 2011, for the Windows Update service (pinned)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # verifies the certificate and the host name
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=str(CERT_FILE))
    return context


def _host(url: str) -> str:
    return urllib.parse.urlparse(url).hostname or ""


def _require(condition: bool, url: str) -> str:
    if not condition:
        raise StoreError(f"refusing to contact {urllib.parse.urlparse(url).scheme}://{_host(url)}/")
    return url


def check_catalog(url: str) -> str:
    return _require(urllib.parse.urlparse(url).scheme == "https" and _host(url) == CATALOG_HOST, url)


def check_fe3(url: str) -> str:
    return _require(urllib.parse.urlparse(url).scheme == "https" and _host(url) == FE3_HOST, url)


def is_download_url(url: str) -> bool:
    """Only Microsoft's package download hosts, over HTTP(S)."""
    host = _host(url)
    scheme_ok = urllib.parse.urlparse(url).scheme in ("http", "https")
    return scheme_ok and (host == DOWNLOAD_HOST or host.endswith(DOWNLOAD_HOST_SUFFIX))


def check_download(url: str) -> str:
    return _require(is_download_url(url), url)


class RedirectGuard(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only if the new URL passes the same allowlist as the original."""

    def __init__(self, check: Callable[[str], str]) -> None:
        super().__init__()
        self._check = check

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        self._check(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Http:
    """Tiny HTTP client; tests replace it with a fake that has the same methods."""

    def __init__(self, public: ssl.SSLContext | None = None, pinned: ssl.SSLContext | None = None) -> None:
        self._public = public or public_tls_context()
        self._pinned = pinned or microsoft_update_tls_context()

    def _open(self, url: str, check: Callable[[str], str], context: ssl.SSLContext, **options: Any) -> Any:
        """The only place this tool opens a URL; `check` enforces the allowlist, also on redirects."""
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), RedirectGuard(check))
        request = urllib.request.Request(check(url), **options)  # noqa: S310 - validated by `check`
        return opener.open(request, timeout=HTTP_TIMEOUT_SECONDS)

    def get_json(self, url: str) -> dict:
        with self._open(url, check_catalog, self._public) as response:
            try:
                return json.loads(response.read().decode("utf-8"))
            except ValueError as exc:
                raise StoreError("the Microsoft Store catalog returned something unexpected") from exc

    def post_soap(self, url: str, body: str) -> str:
        headers = {"Content-Type": "application/soap+xml; charset=utf-8"}
        with self._open(url, check_fe3, self._pinned, data=body.encode("utf-8"), headers=headers) as response:
            return response.read().decode("utf-8")

    def head_length(self, url: str) -> int:
        with self._open(url, check_download, self._public, method="HEAD") as response:
            return int(response.headers.get("Content-Length", "-1"))

    def stream(self, url: str) -> Iterator[bytes]:
        with self._open(url, check_download, self._public) as response:
            while True:
                chunk = response.read(DOWNLOAD_CHUNK)
                if not chunk:
                    return
                yield chunk


def catalog_lookup(http: Http) -> CatalogPackage:
    doc = http.get_json(CATALOG_URL.format(product=C.STORE_PRODUCT_ID))
    try:
        for product in doc.get("Products", []):
            for availability in product.get("DisplaySkuAvailabilities", []):
                properties = availability.get("Sku", {}).get("Properties", {})
                for package in properties.get("Packages") or []:
                    if package.get("PackageFamilyName", "").startswith(C.STORE_PACKAGE_IDENTITY + "_"):
                        return _catalog_package(package)
    except (AttributeError, TypeError, ValueError) as exc:
        raise StoreError("the Microsoft Store catalog entry is not in the expected format") from exc
    raise StoreError("Babysense's updater was not found in the Microsoft Store catalog")


def _catalog_package(package: dict) -> CatalogPackage:
    package_format = package.get("PackageFormat", "")
    if package_format.lower().startswith("e"):
        raise StoreError(f"the package is encrypted ({package_format}); this tool cannot read it")
    fulfillment = package.get("FulfillmentData") or {}
    if isinstance(fulfillment, str):
        fulfillment = json.loads(fulfillment)
    category = fulfillment.get("WuCategoryId", "")
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", category):
        raise StoreError("the catalog entry has no update category")
    full_name = package.get("PackageFullName", "")
    name = full_name if SAFE_NAME.fullmatch(full_name) else "babysense-updater"
    return CatalogPackage(name, category, int(package.get("MaxDownloadSizeInBytes", 0)), package_format)


def soap_envelope(action: str, to: str, body: str, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    created, expires = (t.strftime("%Y-%m-%dT%H:%M:%S.000Z") for t in (now, now + timedelta(minutes=5)))
    return (
        f'<s:Envelope xmlns:a="{NS_ADDRESSING}" xmlns:s="{NS_SOAP}"><s:Header>'
        f'<a:Action s:mustUnderstand="1">{NS_CLIENT}/{action}</a:Action>'
        f'<a:MessageID>urn:uuid:{uuid.uuid4()}</a:MessageID><a:To s:mustUnderstand="1">{to}</a:To>'
        f'<o:Security s:mustUnderstand="1" xmlns:o="{NS_SECURITY}"><Timestamp xmlns="{NS_UTILITY}">'
        f"<Created>{created}</Created><Expires>{expires}</Expires></Timestamp>"
        f'<wuws:WindowsUpdateTicketsToken wsu:id="ClientMSA" xmlns:wsu="{NS_UTILITY}" xmlns:wuws="{NS_WU_AUTH}">'
        '<TicketType Name="MSA" Version="1.0" Policy="MBI_SSL"><User/></TicketType>'
        f"</wuws:WindowsUpdateTicketsToken></o:Security></s:Header><s:Body>{body}</s:Body></s:Envelope>"
    )


def get_cookie(http: Http) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    body = (
        f'<GetCookie xmlns="{NS_CLIENT}"><oldCookie/><lastChange>2015-10-21T17:01:07.1472913Z</lastChange>'
        f"<currentTime>{now}</currentTime><protocolVersion>1.40</protocolVersion></GetCookie>"
    )
    response = http.post_soap(FE3_URL, soap_envelope("GetCookie", FE3_URL, body))
    match = re.search(r"<EncryptedData>([^<]+)</EncryptedData>", response)
    if not match:
        raise StoreError("Microsoft's update service did not return a session cookie")
    return match.group(1)


def _sync_body(cookie: str, category_id: str, installed: list[str]) -> str:
    ids = "".join(f"<int>{i}</int>" for i in installed)
    return (
        f'<SyncUpdates xmlns="{NS_CLIENT}"><cookie><Expiration>2045-03-11T02:02:48Z</Expiration>'
        f"<EncryptedData>{html.escape(cookie)}</EncryptedData></cookie><parameters><ExpressQuery>false</ExpressQuery>"
        f"<InstalledNonLeafUpdateIDs>{ids}</InstalledNonLeafUpdateIDs><OtherCachedUpdateIDs/>"
        "<SkipSoftwareSync>false</SkipSoftwareSync><NeedTwoGroupOutOfScopeUpdates>true</NeedTwoGroupOutOfScopeUpdates>"
        f"<FilterAppCategoryIds><CategoryIdentifier><Id>{category_id}</Id></CategoryIdentifier></FilterAppCategoryIds>"
        "<TreatAppCategoryIdsAsInstalled>true</TreatAppCategoryIdsAsInstalled><AlsoPerformRegularSync>false"
        "</AlsoPerformRegularSync><ComputerSpec/><ExtendedUpdateInfoParameters><XmlUpdateFragmentTypes>"
        "<XmlUpdateFragmentType>Extended</XmlUpdateFragmentType></XmlUpdateFragmentTypes><Locales><string>en-US"
        "</string></Locales></ExtendedUpdateInfoParameters><ClientPreferredLanguages><string>en-US</string>"
        "</ClientPreferredLanguages><ProductsParameters><SyncCurrentVersionOnly>false</SyncCurrentVersionOnly>"
        f"<DeviceAttributes>{html.escape(DEVICE_ATTRIBUTES)}</DeviceAttributes>"
        "<CallerAttributes>Interactive=1;IsSeeker=0;</CallerAttributes><Products/></ProductsParameters>"
        "</parameters></SyncUpdates>"
    )


def _parse(raw: str, nested_xml: bool = False) -> minidom.Document:
    """Parse a SOAP response. SyncUpdates nests escaped XML documents, so those are unescaped first."""
    try:
        # Only Microsoft's responses over the pinned connection; expat caps entity expansion.
        return minidom.parseString(html.unescape(raw) if nested_xml else raw)  # noqa: S318
    except ExpatError as exc:
        raise StoreError(f"unexpected response from Microsoft's update service ({exc})") from exc


def _text(node: minidom.Element, tag: str) -> str:
    found = node.getElementsByTagName(tag)
    return found[0].firstChild.nodeValue if found and found[0].firstChild else ""


def _package_files(doc: minidom.Document) -> list[PackageFile]:
    files: dict[str, tuple[str, int, str]] = {}
    for update in doc.getElementsByTagName("Update"):
        for item in update.getElementsByTagName("File"):
            identifier = item.getAttribute("InstallerSpecificIdentifier")
            if identifier.startswith(C.STORE_PACKAGE_IDENTITY + "_"):
                size = item.getAttribute("Size")
                files[_text(update, "ID")] = (
                    f"{identifier}_{item.getAttribute('FileName')}",
                    int(size) if size.isdigit() else 0,
                    item.getAttribute("Digest"),
                )
    out = []
    for info in doc.getElementsByTagName("UpdateInfo"):
        key = _text(info, "ID")
        identities = info.getElementsByTagName("UpdateIdentity")
        if key in files and identities:
            name, size, digest = files[key]
            identity = identities[0]
            out.append(
                PackageFile(
                    name, size, digest, identity.getAttribute("UpdateID"), identity.getAttribute("RevisionNumber")
                )
            )
    return out


def sync_package_files(http: Http, cookie: str, category_id: str) -> list[PackageFile]:
    """Iterate like a Windows Update client: report prerequisites as installed until the package appears."""
    installed: list[str] = []
    for _ in range(MAX_SYNC_ROUNDS):
        body = soap_envelope("SyncUpdates", FE3_URL, _sync_body(cookie, category_id, installed))
        doc = _parse(http.post_soap(FE3_URL, body), nested_xml=True)
        files = _package_files(doc)
        if files:
            return files
        new = [n for n in (_text(i, "ID") for i in doc.getElementsByTagName("UpdateInfo")) if n and n not in installed]
        if not new:
            break
        installed += new
    raise StoreError("Microsoft's update service did not return Babysense's package")


def file_urls(http: Http, update_id: str, revision: str) -> list[str]:
    body = (
        f'<GetExtendedUpdateInfo2 xmlns="{NS_CLIENT}"><updateIDs><UpdateIdentity><UpdateID>{html.escape(update_id)}'
        f"</UpdateID><RevisionNumber>{html.escape(revision)}</RevisionNumber></UpdateIdentity></updateIDs>"
        "<infoTypes><XmlUpdateFragmentType>FileUrl</XmlUpdateFragmentType></infoTypes>"
        f"<deviceAttributes>{html.escape(DEVICE_ATTRIBUTES)}</deviceAttributes></GetExtendedUpdateInfo2>"
    )
    doc = _parse(http.post_soap(FE3_SECURED_URL, soap_envelope("GetExtendedUpdateInfo2", FE3_SECURED_URL, body)))
    return [_text(location, "Url") for location in doc.getElementsByTagName("FileLocation") if _text(location, "Url")]


def choose_url(http: Http, urls: list[str], expected_size: int) -> str:
    """The link on Microsoft's download servers whose size matches the package (not the block map)."""
    for url in urls:
        if is_download_url(url) and http.head_length(url) == expected_size:
            return url
    raise StoreError("no matching download link on Microsoft's servers")


def sha1_base64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha1(data).digest()).decode()  # noqa: S324 - Microsoft's published digest


def download(
    http: Http,
    url: str,
    destination: Path,
    expected: PackageFile,
    say: Say,
    clock: Callable[[], float] = time.monotonic,
) -> None:
    """Stream to a .part file, stopping as soon as it's larger or slower than allowed; keep it only if it matches."""
    partial = destination.with_name(destination.name + ".part")
    digest = hashlib.sha1()  # noqa: S324 - compared with Microsoft's published digest
    received, next_report, deadline = 0, REPORT_STEP, clock() + DOWNLOAD_DEADLINE_SECONDS
    try:
        with open(partial, "wb") as handle:
            for chunk in http.stream(url):
                received += len(chunk)
                if received > expected.size:
                    raise StoreError("the download is larger than Microsoft says it should be; stopped")
                if clock() > deadline:
                    raise StoreError("the download is taking too long; stopped")
                digest.update(chunk)
                handle.write(chunk)
                if received >= next_report:
                    say(f"  downloaded {received / 1e6:.0f} of {expected.size / 1e6:.0f} MB")
                    next_report += REPORT_STEP
        if received != expected.size or base64.b64encode(digest.digest()).decode() != expected.sha1_base64:
            raise StoreError("the download did not match Microsoft's published size/checksum; it was deleted")
        partial.replace(destination)
    finally:
        if partial.exists():
            partial.unlink()


def fetch_updater_package(cache_dir: Path, say: Say, http: Http | None = None) -> bytes:
    """Babysense's official updater package (.msix), as bytes verified against Microsoft's checksum."""
    http = http or Http()
    package = catalog_lookup(http)
    say(f"Babysense's official updater: {package.full_name} ({package.size / 1e6:.0f} MB)")
    files = sync_package_files(http, get_cookie(http), package.category_id)
    target = next((f for f in files if f.name.lower().endswith(".msix")), None)
    if target is None:
        raise StoreError("Microsoft's update service listed no .msix package for Babysense's updater")
    cache_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    cached = cache_dir / f"{package.full_name}.msix"
    if cached.exists() and sha1_base64(cached.read_bytes()) == target.sha1_base64:
        say("Using the copy downloaded earlier (checksum verified).")
    else:
        say("Downloading it from Microsoft (checked against Microsoft's checksum)...")
        url = choose_url(http, file_urls(http, target.update_id, target.revision), target.size)
        download(http, url, cached, target, say)
    data = cached.read_bytes()
    if len(data) != target.size or sha1_base64(data) != target.sha1_base64:
        raise StoreError(f"the downloaded package changed on disk; delete {cached} and try again")
    return data
