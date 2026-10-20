import ipaddress
from urllib.parse import urlsplit

from app.enrichers.common import SourceTracker
from app.enrichers.domain_enrich import find_lookalike
from app.schemas import UrlIntel

SUSPICIOUS_TLDS = {
    "bar",
    "buzz",
    "cam",
    "cfd",
    "click",
    "fit",
    "gq",
    "hair",
    "icu",
    "link",
    "live",
    "lol",
    "makeup",
    "ml",
    "monster",
    "mov",
    "quest",
    "rest",
    "ru",
    "sbs",
    "shop",
    "skin",
    "support",
    "tk",
    "top",
    "work",
    "xyz",
    "zip",
}

SHORTENERS = {
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rb.gy",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "tinyurl.com",
}


class UrlEnricher:
    def lookup(self, value: str) -> UrlIntel:
        url = value.strip()
        try:
            parsed = urlsplit(url)
        except ValueError:
            return UrlIntel(
                url=url,
                suspicious=True,
                notes=["URL could not be parsed"],
                sources=["passive"],
            )

        host = (parsed.hostname or "").lower().rstrip(".")
        scheme = parsed.scheme.lower() if parsed.scheme else None
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        ip_literal = _is_ip_literal(host)
        punycode = host.startswith("xn--") or ".xn--" in host
        userinfo = parsed.username is not None or parsed.password is not None
        shortened = host in SHORTENERS
        suspicious_tld = tld in SUSPICIOUS_TLDS
        lookalike_of, distance = find_lookalike(host) if host else (None, None)
        https = scheme == "https"
        suspicious = (
            ip_literal
            or punycode
            or userinfo
            or shortened
            or suspicious_tld
            or lookalike_of is not None
        )

        notes: list[str] = []
        if not host:
            notes.append("URL has no hostname")
        if ip_literal:
            notes.append("Host is an IP literal")
        if punycode:
            notes.append("Host uses punycode encoding")
        if userinfo:
            notes.append("URL embeds credentials or userinfo")
        if shortened:
            notes.append("Known URL shortener hides the final destination")
        if suspicious_tld:
            notes.append(f"Host uses a high-risk TLD (.{tld})")
        if lookalike_of:
            notes.append(f"Host is a lookalike of {lookalike_of} (edit distance {distance})")
        if host and not https:
            notes.append("URL does not use HTTPS")
        notes.append("URL content was not fetched; passive heuristics only")

        sources = ["passive"]
        if lookalike_of:
            sources.append("lookalike")
        return UrlIntel(
            url=url,
            host=host or None,
            scheme=scheme,
            https=https,
            ip_literal=ip_literal,
            punycode=punycode,
            userinfo=userinfo,
            shortened=shortened,
            suspicious_tld=suspicious_tld,
            lookalike_of=lookalike_of,
            distance=distance,
            suspicious=suspicious,
            reputation="not_checked",
            available=bool(host),
            sources=sources,
            notes=notes,
        )

    def mark_source(self, tracker: SourceTracker) -> None:
        tracker.mark("url_passive", "ok")


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True
