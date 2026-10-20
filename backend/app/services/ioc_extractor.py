import re
from urllib.parse import urlsplit

from app.schemas import IOC
from app.services.header_parser import ParsedEmail
from app.utils.ip import find_ips

_URL_RE = re.compile(r"\bhttps?://[^\s<>\"'\]\)]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"(?<![\w@.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}(?![\w.-])"
)
_EMAIL_RE = re.compile(r"(?<![\w.-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,24}", re.IGNORECASE)
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_FILE_EXTENSIONS = {
    "png",
    "jpg",
    "jpeg",
    "gif",
    "webp",
    "svg",
    "ico",
    "css",
    "js",
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "zip",
    "rar",
    "7z",
    "gz",
    "txt",
    "eml",
    "msg",
    "html",
    "htm",
    "exe",
    "dll",
}
_MAX_IOCS = 200


class _Collector:
    def __init__(self) -> None:
        self.items: list[IOC] = []
        self._seen: set[tuple[str, str]] = set()

    def add(self, ioc_type: str, value: str, context: str) -> None:
        value = value.strip().strip(".,;:!?)\"'")
        if not value:
            return
        key = (ioc_type, value.lower())
        if key in self._seen:
            return
        self._seen.add(key)
        self.items.append(IOC(type=ioc_type, value=value, context=context))


def _trim_url(value: str) -> str:
    return value.rstrip(".,;:!?)]}\"'")


def _domain_from_url(value: str) -> str | None:
    try:
        host = urlsplit(value).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def _add_domain(collector: _Collector, domain: str, context: str) -> None:
    domain = domain.strip().lower().strip(".")
    if not domain or "." not in domain:
        return
    tld = domain.rsplit(".", 1)[-1]
    if tld in _FILE_EXTENSIONS:
        return
    collector.add("domain", domain, context)


def extract_iocs(parsed: ParsedEmail) -> list[IOC]:
    collector = _Collector()
    meta = parsed.message

    for header in ("From", "Reply-To", "Return-Path", "Sender"):
        for value in meta.get_all(header, []):
            for _, address in _address_pairs(str(value)):
                if "@" in address:
                    collector.add("email", address.lower(), f"header:{header.lower()}")
                    _add_domain(collector, address.rsplit("@", 1)[-1], f"header:{header.lower()}")

    received_join = "\n".join(parsed.received_headers)
    for ip in find_ips(received_join):
        collector.add("ip", ip, "header:received")

    for address in _EMAIL_RE.findall(parsed.body_text):
        collector.add("email", address.lower(), "body")
    for address in _EMAIL_RE.findall(parsed.body_html):
        collector.add("email", address.lower(), "body:html")

    urls: list[str] = []
    for match in _URL_RE.finditer(parsed.body_text):
        urls.append(_trim_url(match.group(0)))
    for match in _URL_RE.finditer(parsed.body_html):
        urls.append(_trim_url(match.group(0)))

    for url in urls:
        collector.add("url", url, "body")
        host = _domain_from_url(url)
        if host:
            _add_domain(collector, host, "url")
            for ip in find_ips(host):
                collector.add("ip", ip, "url")

    for domain in _DOMAIN_RE.findall(parsed.body_text):
        _add_domain(collector, domain, "body")
    for domain in _DOMAIN_RE.findall(parsed.body_html):
        _add_domain(collector, domain, "body:html")

    for ip in find_ips(parsed.body_text):
        collector.add("ip", ip, "body")

    for pattern, ioc_type in (
        (_SHA256_RE, "sha256"),
        (_SHA1_RE, "sha1"),
        (_MD5_RE, "md5"),
    ):
        for match in pattern.findall(parsed.body_text):
            collector.add(ioc_type, match.lower(), "body")

    for attachment in parsed.attachments:
        if attachment.sha256:
            collector.add("sha256", attachment.sha256, f"attachment:{attachment.filename}")

    return collector.items[:_MAX_IOCS]


def _address_pairs(value: str) -> list[tuple[str, str]]:
    from email.utils import getaddresses

    return getaddresses([value])
