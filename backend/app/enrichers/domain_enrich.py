import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import dns.exception
import dns.resolver

from app.enrichers.common import SourceTracker
from app.schemas import DomainIntel
from app.utils.budget import RequestBudget
from app.utils.cache import TTLCache
from app.utils.http import BudgetExceeded, HttpClient, SourceUnavailable

RDAP_URL = "https://rdap.org/domain/{domain}"

RESERVED_SUFFIXES = (".invalid", ".test", ".example", ".localhost", ".local")

BRANDS: dict[str, tuple[str, ...]] = {
    "adobe": ("adobe.com",),
    "amazon": ("amazon.com", "amazon.in", "amazon.co.uk"),
    "apple": ("apple.com", "icloud.com"),
    "axis": ("axisbank.com",),
    "bankofamerica": ("bankofamerica.com",),
    "binance": ("binance.com",),
    "chase": ("chase.com",),
    "coinbase": ("coinbase.com",),
    "dhl": ("dhl.com", "dhl.de"),
    "docusign": ("docusign.com",),
    "dropbox": ("dropbox.com",),
    "facebook": ("facebook.com", "fb.com", "messenger.com"),
    "fedex": ("fedex.com",),
    "github": ("github.com",),
    "gmail": ("gmail.com",),
    "google": ("google.com", "google.co.uk", "youtube.com"),
    "hdfc": ("hdfcbank.com",),
    "hsbc": ("hsbc.com", "hsbc.co.uk", "hsbc.in"),
    "icici": ("icicibank.com",),
    "linkedin": ("linkedin.com",),
    "metamask": ("metamask.io",),
    "microsoft": ("microsoft.com", "microsoftonline.com", "office.com", "outlook.com"),
    "netflix": ("netflix.com",),
    "paypal": ("paypal.com", "paypal.me"),
    "paytm": ("paytm.com",),
    "phonepe": ("phonepe.com",),
    "sbi": ("onlinesbi.sbi", "sbi.co.in", "onlinesbi.com"),
    "slack": ("slack.com",),
    "ups": ("ups.com",),
    "wellsfargo": ("wellsfargo.com",),
    "whatsapp": ("whatsapp.com",),
    "zoom": ("zoom.us",),
}
OFFICIAL_DOMAINS = {domain for domains in BRANDS.values() for domain in domains}

HOMOGLYPHS = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "ӏ": "l",
        "ԁ": "d",
        "ԛ": "q",
        "ԝ": "w",
        "ɡ": "g",
    }
)


@dataclass
class DnsResult:
    records: list[str]
    error: str | None = None


class DnsResolver:
    def __init__(self, timeout_seconds: float = 3.0, resolver: Any | None = None) -> None:
        self.timeout_seconds = timeout_seconds
        self.resolver = resolver
        self.init_error: str | None = None
        if self.resolver is None:
            try:
                self.resolver = dns.resolver.Resolver(configure=True)
            except Exception as exc:
                self.init_error = str(exc)
        if self.resolver is not None:
            self.resolver.lifetime = timeout_seconds
            self.resolver.timeout = timeout_seconds

    def query(self, name: str, rdtype: str) -> DnsResult:
        if self.resolver is None:
            return DnsResult([], self.init_error or "DNS resolver unavailable")
        try:
            answers = self.resolver.resolve(name, rdtype, lifetime=self.timeout_seconds)
        except dns.resolver.NXDOMAIN:
            return DnsResult([], "NXDOMAIN")
        except dns.resolver.NoAnswer:
            return DnsResult([], None)
        except (
            dns.resolver.NoNameservers,
            dns.resolver.Timeout,
            dns.exception.DNSException,
        ) as exc:
            return DnsResult([], type(exc).__name__)
        records = [self._record_text(rdtype, record) for record in answers]
        return DnsResult([record for record in records if record], None)

    @staticmethod
    def _record_text(rdtype: str, record: Any) -> str:
        if rdtype == "A":
            return str(getattr(record, "address", record)).strip().lower()
        if rdtype == "MX":
            exchange = getattr(record, "exchange", None)
            return str(exchange.to_text(omit_final_dot=True) if exchange else record).lower()
        if rdtype == "NS":
            target = getattr(record, "target", None)
            return str(target.to_text(omit_final_dot=True) if target else record).lower()
        if rdtype == "TXT":
            strings = getattr(record, "strings", None)
            if strings:
                return b"".join(strings).decode("utf-8", "replace").strip()
            return str(record).strip().strip('"')
        return str(record).strip()


class RdapLookup:
    def __init__(
        self,
        http: HttpClient,
        cache: TTLCache,
        budget: RequestBudget,
        offline: bool,
        enabled: bool,
    ) -> None:
        self.http = http
        self.cache = cache
        self.budget = budget
        self.offline = offline
        self.enabled = enabled

    def lookup(self, domain: str, tracker: SourceTracker) -> dict[str, Any]:
        if not self.enabled:
            tracker.mark("rdap", "disabled")
            return {}
        if self.offline:
            tracker.mark("rdap", "offline")
            return {}
        cache_key = f"rdap:{domain}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            tracker.mark("rdap", "ok")
            return cached
        try:
            payload = self.http.get_json(
                RDAP_URL.format(domain=quote(domain, safe="")),
                "rdap",
                self.budget,
                allow_404=True,
            )
        except BudgetExceeded:
            tracker.mark("rdap", "budget_exceeded")
            return {}
        except SourceUnavailable as exc:
            tracker.mark("rdap", "unavailable", exc.reason)
            return {}
        if payload is None:
            tracker.mark("rdap", "unavailable", "no RDAP record")
            return {}
        parsed = parse_rdap(payload)
        tracker.mark("rdap", "ok")
        self.cache.set(cache_key, parsed, 30 * 24 * 60 * 60)
        return parsed


class DomainEnricher:
    def __init__(
        self,
        dns: DnsResolver,
        rdap: RdapLookup,
        cache: TTLCache,
        offline: bool,
        now: Callable[[], datetime] | None = None,
        cache_ttl_seconds: int = 60 * 60,
    ) -> None:
        self.dns = dns
        self.rdap = rdap
        self.cache = cache
        self.offline = offline
        self._now = now or (lambda: datetime.now(UTC))
        self.cache_ttl_seconds = cache_ttl_seconds

    def lookup(self, value: str, tracker: SourceTracker) -> tuple[DomainIntel, bool]:
        domain = normalize_domain(value)
        if domain is None:
            return DomainIntel(domain=value, notes=["Invalid domain name"]), False

        lookalike_of, distance = find_lookalike(domain)
        if domain.endswith(RESERVED_SUFFIXES):
            notes = ["Reserved domain suffix; external DNS and RDAP skipped"]
            if lookalike_of:
                notes.append(f"Lookalike of {lookalike_of} (edit distance {distance})")
            return (
                DomainIntel(
                    domain=domain,
                    available=lookalike_of is not None,
                    lookalike_of=lookalike_of,
                    distance=distance,
                    sources=["lookalike"] if lookalike_of else [],
                    notes=notes,
                ),
                False,
            )

        cache_key = f"domain:{domain}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            intel = DomainIntel.model_validate(cached)
            if "dns" in intel.sources:
                tracker.mark("dns", "ok")
            if "rdap" in intel.sources:
                tracker.mark("rdap", "ok")
            return intel, True

        dns_ok = False
        dns_error: str | None = None
        a_records: list[str] = []
        mx: list[str] = []
        ns: list[str] = []
        spf: str | None = None
        dmarc: str | None = None

        if self.offline:
            tracker.mark("dns", "offline")
        else:
            a_result = self.dns.query(domain, "A")
            dns_ok, dns_error = self._dns_state(a_result, dns_ok, dns_error)
            a_records = a_result.records
            if a_result.error not in {"Timeout", "LifetimeTimeout", "NoNameservers"}:
                mx_result = self.dns.query(domain, "MX")
                dns_ok, dns_error = self._dns_state(mx_result, dns_ok, dns_error)
                mx = mx_result.records
                ns_result = self.dns.query(domain, "NS")
                dns_ok, dns_error = self._dns_state(ns_result, dns_ok, dns_error)
                ns = ns_result.records
                txt_result = self.dns.query(domain, "TXT")
                dns_ok, dns_error = self._dns_state(txt_result, dns_ok, dns_error)
                spf = next(
                    (
                        record
                        for record in txt_result.records
                        if record.lower().startswith("v=spf1")
                    ),
                    None,
                )
                dmarc_result = self.dns.query(f"_dmarc.{domain}", "TXT")
                dns_ok, dns_error = self._dns_state(dmarc_result, dns_ok, dns_error)
                dmarc = next(
                    (
                        record
                        for record in dmarc_result.records
                        if record.lower().startswith("v=dmarc1")
                    ),
                    None,
                )
            tracker.mark("dns", "ok" if dns_ok else "unavailable", dns_error)

        rdap_data = self.rdap.lookup(domain, tracker)
        created_at = rdap_data.get("created_at")
        age_days = age_in_days(created_at, self._now())

        sources: list[str] = []
        if dns_ok:
            sources.append("dns")
        if rdap_data:
            sources.append("rdap")
        if lookalike_of:
            sources.append("lookalike")

        notes: list[str] = []
        if self.offline:
            notes.append("Offline mode: DNS and RDAP lookups skipped")
        elif not dns_ok and dns_error:
            notes.append(f"DNS lookup failed: {dns_error}")
        if age_days is not None:
            notes.append(f"Registered {age_days} day{'s' if age_days != 1 else ''} ago")
        if spf is None and not self.offline:
            notes.append("No SPF record found")
        if dmarc is None and not self.offline:
            notes.append("No DMARC record found")
        if lookalike_of:
            notes.append(f"Lookalike of {lookalike_of} (edit distance {distance})")
        if domain.startswith("xn--") or ".xn--" in domain:
            notes.append("Internationalized domain uses punycode")

        intel = DomainIntel(
            domain=domain,
            available=bool(sources),
            age_days=age_days,
            created_at=created_at,
            updated_at=rdap_data.get("updated_at"),
            expires_at=rdap_data.get("expires_at"),
            registrar=rdap_data.get("registrar"),
            statuses=rdap_data.get("statuses", []),
            resolved=(bool(a_records) if dns_ok else None),
            a_records=a_records,
            mx=mx,
            ns=ns,
            spf=spf,
            dmarc=dmarc,
            lookalike_of=lookalike_of,
            distance=distance,
            sources=sources,
            notes=notes,
        )
        if not self.offline:
            self.cache.set(cache_key, intel.model_dump(mode="json"), self.cache_ttl_seconds)
        return intel, False

    @staticmethod
    def _dns_state(
        result: DnsResult, ok: bool, previous_error: str | None
    ) -> tuple[bool, str | None]:
        if result.error in {None, "NXDOMAIN"}:
            return True, previous_error
        return ok, result.error


def normalize_domain(value: str) -> str | None:
    candidate = value.strip().lower().rstrip(".")
    if not candidate or "@" in candidate or any(char in candidate for char in "/: \t\r\n"):
        return None
    if "." not in candidate:
        return None
    try:
        ascii_domain = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(ascii_domain) > 253:
        return None
    labels = ascii_domain.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        return None
    if any(len(label) > 63 for label in labels):
        return None
    if not re.fullmatch(r"[a-z0-9.-]+", ascii_domain):
        return None
    return ascii_domain


def find_lookalike(domain: str) -> tuple[str | None, int | None]:
    if _is_official(domain):
        return None, None
    labels = domain.split(".")
    best_brand: str | None = None
    best_distance: int | None = None
    for label in labels:
        decoded = _decode_idna(label)
        for token in re.split(r"[-_]", decoded):
            token = token.strip()
            if len(token) < 3:
                continue
            normalized = token.lower().translate(HOMOGLYPHS)
            variants = {normalized}
            if normalized.startswith("rn"):
                variants.add("m" + normalized[2:])
            for brand in BRANDS:
                if len(brand) < 3:
                    continue
                if normalized[0] != brand[0]:
                    continue
                for variant in variants:
                    if variant == brand and len(brand) < 5:
                        distance = 0
                    elif len(variant) >= 5 and len(brand) >= 5:
                        distance = _levenshtein(variant, brand)
                    else:
                        continue
                    if distance > 1:
                        continue
                    if best_distance is None or distance < best_distance:
                        best_brand = brand
                        best_distance = distance
    if best_brand is None:
        return None, None
    return BRANDS[best_brand][0], best_distance


def _is_official(domain: str) -> bool:
    return any(
        domain == official or domain.endswith(f".{official}") for official in OFFICIAL_DOMAINS
    )


def _decode_idna(label: str) -> str:
    if not label.startswith("xn--"):
        return label
    try:
        return label.encode("ascii").decode("idna")
    except UnicodeError:
        return label


def _levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if len(left) < len(right):
        left, right = right, left
    previous = list(range(len(right) + 1))
    for index, left_char in enumerate(left, start=1):
        current = [index]
        for offset, right_char in enumerate(right, start=1):
            insert = current[offset - 1] + 1
            delete = previous[offset] + 1
            replace = previous[offset - 1] + (left_char != right_char)
            current.append(min(insert, delete, replace))
        previous = current
    return previous[-1]


def parse_rdap(payload: dict[str, Any]) -> dict[str, Any]:
    events: dict[str, str] = {}
    for event in payload.get("events", []):
        if not isinstance(event, dict):
            continue
        action = event.get("eventAction")
        date = event.get("eventDate")
        if isinstance(action, str) and isinstance(date, str):
            events[action] = date
    registrar = None
    for entity in payload.get("entities", []):
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles") or entity.get("role") or []
        if "registrar" not in roles:
            continue
        registrar = _vcard_name(entity.get("vcardArray"))
        if registrar:
            break
    statuses = payload.get("status", [])
    return {
        "created_at": events.get("registration"),
        "updated_at": events.get("last changed"),
        "expires_at": events.get("expiration"),
        "registrar": registrar,
        "statuses": [str(status) for status in statuses] if isinstance(statuses, list) else [],
    }


def _vcard_name(vcard: Any) -> str | None:
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return None
    for entry in vcard[1]:
        if isinstance(entry, list) and len(entry) >= 4 and entry[0] == "fn":
            return str(entry[3])
    return None


def age_in_days(created_at: str | None, now: datetime) -> int | None:
    if not created_at:
        return None
    try:
        created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)
    return max(0, (now - created).days)
