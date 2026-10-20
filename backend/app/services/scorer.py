import re
from dataclasses import dataclass, field

from app.core.config import Settings
from app.enrichers.domain_enrich import BRANDS
from app.schemas import (
    AuthReport,
    EmailMeta,
    EnrichmentReport,
    RoutingReport,
    ScoreReport,
)

FREEMAIL_DOMAINS = {
    "aol.com",
    "gmail.com",
    "hotmail.com",
    "icloud.com",
    "live.com",
    "outlook.com",
    "proton.me",
    "protonmail.com",
    "yahoo.com",
}

URGENCY_RE = re.compile(
    r"\b(urgent(?:ly)?|immediately|within \d+ hours?|today|before \d|final notice|"
    r"final warning|act now|last chance|expires?)\b",
    re.IGNORECASE,
)
THREAT_RE = re.compile(
    r"\b(suspend(?:ed|sion)?|terminat(?:e|ed|ion)|locked|disabled|deactiv(?:e|ated)|"
    r"legal action|failure to|avoid (?:suspension|closure))\b",
    re.IGNORECASE,
)
CREDENTIAL_RE = re.compile(
    r"\b(verify (?:your|the)|confirm (?:your )?identity|sign in|log in|login|"
    r"password|credentials|reset (?:your )?password)\b",
    re.IGNORECASE,
)
PAYMENT_RE = re.compile(
    r"\b(wire transfer|bank (?:details|account)|beneficiary|payment|invoice|"
    r"gift cards?|bitcoin|crypto(?:currency)?|remittance|routing number)\b",
    re.IGNORECASE,
)
PAYMENT_CHANGE_RE = re.compile(
    r"\b(new bank (?:details|account)|updated (?:bank|payment)|change (?:the )?(?:bank|payment)|"
    r"beneficiary|wire transfer)\b",
    re.IGNORECASE,
)
SECRECY_RE = re.compile(
    r"\b(confidential|do not (?:call|tell|discuss)|ceo|chief executive|acquisition|"
    r"merger|secret)\b",
    re.IGNORECASE,
)
GREETING_RE = re.compile(r"\b(dear (?:customer|user|client|account holder|sir/madam))\b", re.I)
MESSAGE_ID_DOMAIN_RE = re.compile(r"@([^>\s]+)", re.IGNORECASE)


@dataclass
class _Family:
    name: str
    maximum: int
    available: bool = True
    raw: int = 0
    points: int = 0
    reasons: list[tuple[int, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, points: int, reason: str) -> None:
        if points <= 0:
            return
        self.raw += int(points)
        self.reasons.append((int(points), reason))

    def scale(self, factor: float) -> None:
        if factor < 1.0 and self.raw:
            self.raw = int(round(self.raw * factor))

    def finish(self) -> None:
        self.points = min(self.raw, self.maximum)


def score_analysis(
    email: EmailMeta,
    auth: AuthReport,
    routing: RoutingReport,
    enrichment: EnrichmentReport,
    settings: Settings,
) -> ScoreReport:
    if not settings.scoring_enabled:
        return ScoreReport(
            available=False,
            label="unscored",
            version=settings.scoring_version,
            notes=["Scoring is disabled in configuration"],
        )

    families = {
        "auth": _score_auth(email, auth, settings),
        "domain": _score_domain(email, auth, enrichment, settings),
        "ip": _score_ip(routing, enrichment, settings),
        "content": _score_content(email, enrichment, settings),
        "header": _score_header(email, auth, routing, settings),
    }
    for family in families.values():
        family.finish()

    max_signals = {name: family.maximum for name, family in families.items()}
    max_total = sum(max_signals.values()) or 1
    signals = {name: family.points for name, family in families.items()}
    raw_total = sum(signals.values())
    total = min(100, raw_total)
    available_weight = sum(
        family.maximum for family in families.values() if family.available
    )
    coverage = round(available_weight / max_total, 2)
    families_above = sum(
        1 for points in signals.values() if points >= settings.family_min_points
    )

    label = _label(total, families_above, settings)
    notes = [note for family in families.values() for note in family.notes]
    if label == "malicious" and total >= settings.malicious_threshold and families_above < 2:
        label = "suspicious"
        notes.append(
            "Malicious threshold reached without two independent signal families; "
            "capped at suspicious"
        )
    if coverage < 0.6:
        notes.append("Limited evidence coverage; confidence is reduced")
    if enrichment.offline_mode:
        notes.append("Offline mode: domain and IP scoring use cache/local data only")
    if email.list_id or email.list_unsubscribe:
        notes.append("Mailing-list/forwarding adjustments were applied")

    reasons = _top_reasons(families)
    if not reasons:
        reasons = _baseline_reasons(email, auth, enrichment)
    confidence = _confidence(
        total,
        label,
        coverage,
        families_above,
        settings,
    )
    return ScoreReport(
        available=True,
        total=total,
        label=label,
        confidence=confidence,
        signals=signals,
        max_signals=max_signals,
        families_above_threshold=families_above,
        coverage=coverage,
        top_reasons=reasons,
        version=settings.scoring_version,
        notes=_dedupe(notes),
    )


def _score_auth(email: EmailMeta, auth: AuthReport, settings: Settings) -> _Family:
    family = _Family("auth", settings.auth_signal_max)
    if not auth.alignment.from_domain:
        family.available = False
        family.notes.append("No visible From domain; authentication scoring unavailable")
        return family

    forwarding = bool(email.list_id or email.list_unsubscribe)
    dkim_results = [entry.result.lower() for entry in auth.dkim]
    dkim_passed = any(result == "pass" for result in dkim_results)
    dkim_failed = bool(dkim_results) and all(
        result not in {"pass", "none"} for result in dkim_results
    )
    spf = auth.spf.result.lower()
    dmarc = auth.dmarc.result.lower()

    spf_points = {"fail": 8, "softfail": 5, "permerror": 5, "none": 4}.get(spf, 0)
    if spf_points:
        if forwarding and dkim_passed and spf in {"fail", "softfail"}:
            family.notes.append(
                "SPF failure discounted because the message is a mailing list "
                "with an aligned DKIM pass"
            )
            family.reasons.append(
                (0, "SPF failure discounted for mailing-list forwarding with DKIM pass")
            )
        else:
            labels = {
                "fail": "SPF failed",
                "softfail": "SPF softfailed",
                "permerror": "SPF permanent error",
                "none": "No SPF result was available",
            }
            family.add(spf_points, labels.get(spf, "SPF did not pass"))

    if dkim_passed:
        pass
    elif dkim_failed:
        family.add(7, "All DKIM signatures failed")
    else:
        points = 2 if dmarc == "pass" else 5
        family.add(points, "No DKIM signature passed validation")

    if dmarc == "fail":
        family.add(8, "DMARC failed for the visible From domain")
    elif dmarc == "none":
        family.add(4, "No DMARC result was available")

    if spf == "pass" and auth.alignment.spf_aligned is False:
        family.add(3, "SPF passed but was not aligned with the From domain")
    if dkim_passed and auth.alignment.dkim_aligned is False:
        family.add(3, "DKIM passed but was not aligned with the From domain")
    if spf == "none" and dmarc == "none":
        family.add(2, "From domain had neither SPF nor DMARC evidence")

    if family.raw == 0:
        family.reasons.append((0, "Sender authentication passed for the visible From domain"))
    return family


def _score_domain(
    email: EmailMeta,
    auth: AuthReport,
    enrichment: EnrichmentReport,
    settings: Settings,
) -> _Family:
    family = _Family("domain", settings.domain_signal_max)
    domains = list(enrichment.domain.values())
    urls = list(enrichment.url.values())
    family.available = bool(domains or urls)
    if not family.available:
        family.notes.append("Domain enrichment was unavailable")
        return family

    lookalikes = [domain for domain in domains if domain.lookalike_of]
    lookalikes.extend(url for url in urls if url.lookalike_of)
    if lookalikes:
        best = min(lookalikes, key=lambda item: item.distance if item.distance is not None else 9)
        points = 14 if best.distance == 0 else 12
        family.add(points, f"Domain resembles {best.lookalike_of} (edit distance {best.distance})")

    ages = [domain.age_days for domain in domains if domain.age_days is not None]
    if ages:
        age = min(ages)
        if age <= 7:
            family.add(8, f"Domain was registered {age} day(s) ago")
        elif age <= 30:
            family.add(5, f"Domain is only {age} days old")
        elif age <= 90:
            family.add(2, f"Domain is less than 90 days old ({age} days)")

    if any(
        "dns" in domain.sources and not domain.spf and not domain.dmarc
        for domain in domains
    ) and auth.dmarc.result.lower() != "pass":
        family.add(2, "Sender domain lacks both SPF and DMARC records")

    if (
        email.reply_to
        and email.reply_to.domain
        and email.sender.domain
        and not _aligned(email.reply_to.domain, email.sender.domain)
    ):
        family.add(6, "Reply-To uses a domain outside the sender's domain")

    if (
        email.sender.domain in FREEMAIL_DOMAINS
        and _brand_claim(email.sender.name)
    ):
        family.add(8, "Freemail sender claims a well-known brand in its display name")

    if any(
        domain.domain.startswith("xn--") or ".xn--" in domain.domain for domain in domains
    ) or any(url.punycode for url in urls):
        family.add(4, "An internationalized/punycode domain is present")
    if any(url.suspicious_tld for url in urls):
        family.add(3, "A URL uses a high-risk top-level domain")

    return family


def _score_ip(routing: RoutingReport, enrichment: EnrichmentReport, settings: Settings) -> _Family:
    family = _Family("ip", settings.ip_signal_max)
    public = [intel for intel in enrichment.ip.values() if intel.scope == "public"]
    family.available = any(intel.available for intel in public)
    if not public:
        family.notes.append("No public origin IP was available for reputation scoring")
        return family

    origin = next(
        (intel for intel in public if intel.ip == routing.origin_ip),
        public[0],
    )
    if origin.tor is True:
        family.add(20, "Origin IP is a Tor exit node")
    elif any(intel.tor is True for intel in public):
        family.add(12, "A relay IP is a Tor exit node")

    if origin.vpn is True or any(intel.vpn is True for intel in public):
        family.add(5, "Origin IP is associated with a VPN service")
    if origin.abuse_score is not None:
        if origin.abuse_score >= 75:
            family.add(12, f"Origin IP has a high abuse score ({origin.abuse_score})")
        elif origin.abuse_score >= 50:
            family.add(8, f"Origin IP has an elevated abuse score ({origin.abuse_score})")
        elif origin.abuse_score >= 25:
            family.add(4, f"Origin IP has a moderate abuse score ({origin.abuse_score})")
    if origin.hosting is True:
        family.add(5, "Origin IP belongs to a hosting or data-center network")
    elif any(intel.hosting is True for intel in public):
        family.add(3, "A relay IP belongs to a hosting or data-center network")
    return family


def _score_content(email: EmailMeta, enrichment: EnrichmentReport, settings: Settings) -> _Family:
    family = _Family("content", settings.content_signal_max)
    text = f"{email.subject}\n{email.body_excerpt}".strip()
    family.available = bool(text)
    if not family.available:
        family.notes.append("Message had no textual content for content scoring")
        return family

    if URGENCY_RE.search(text):
        family.add(3, "Message uses urgency or a deadline")
    if THREAT_RE.search(text):
        family.add(3, "Message threatens account suspension or another consequence")
    if CREDENTIAL_RE.search(text):
        family.add(3, "Message requests credential verification or a password reset")
    if PAYMENT_RE.search(text):
        family.add(8, "Message requests a payment, invoice, or bank action")
    if PAYMENT_CHANGE_RE.search(text):
        family.add(4, "Message asks the recipient to use new bank or payment details")
    if SECRECY_RE.search(text):
        family.add(4, "Message invokes confidentiality, authority, or secrecy")
    if GREETING_RE.search(text):
        family.add(2, "Message uses a generic greeting")
    if any(
        email.sender.domain and url.host and not _aligned(url.host, email.sender.domain)
        for url in enrichment.url.values()
    ):
        family.add(2, "A link host differs from the sender domain")
    if any(url.suspicious for url in enrichment.url.values()):
        family.add(3, "A link matches a suspicious URL pattern")
    if email.attachments and PAYMENT_RE.search(text):
        family.add(2, "A payment request includes an attachment")

    if email.list_id or email.list_unsubscribe:
        family.scale(0.4)
        family.notes.append("Content cues discounted for mailing-list/forwarded mail")
    return family


def _score_header(
    email: EmailMeta,
    auth: AuthReport,
    routing: RoutingReport,
    settings: Settings,
) -> _Family:
    family = _Family("header", settings.header_signal_max)
    family.available = bool(email.headers_excerpt or routing.hops)
    if auth.alignment.reply_to_mismatch:
        family.add(8, "Reply-To domain differs from the From domain")
    if (
        email.reply_to
        and email.reply_to.domain
        and email.sender.domain
        and not _aligned(email.reply_to.domain, email.sender.domain)
    ):
        family.add(4, "Reply-To points outside the sender's organizational domain")
    if email.attachments:
        family.add(2, "Message includes an attachment")
    if "private_ip_in_chain" in routing.anomalies:
        family.add(3, "Relay chain contains a private or reserved IP address")
    if "timestamp_regression" in routing.anomalies:
        family.add(4, "Relay timestamps move backwards")
    if "high_hop_count" in routing.anomalies:
        family.add(2, "Relay chain has an unusually high hop count")
    if "missing_hop_timestamp" in routing.anomalies:
        family.add(1, "One or more relay hops have no timestamp")
    if "no_received_headers" in routing.anomalies:
        family.add(2, "No Received headers were available")
    if "origin_undetermined" in routing.anomalies:
        family.add(2, "Probable origin could not be determined")
    if not email.sender.address:
        family.add(2, "From header is missing or invalid")
    if not email.date:
        family.add(1, "Date header is missing")
    if not email.message_id:
        family.add(1, "Message-ID header is missing")
    if email.message_id and email.sender.domain:
        match = MESSAGE_ID_DOMAIN_RE.search(email.message_id)
        if match and not _aligned(match.group(1).rstrip(">"), email.sender.domain):
            family.add(2, "Message-ID domain differs from the From domain")
    return family


def _label(total: int, families_above: int, settings: Settings) -> str:
    if total >= settings.malicious_threshold and families_above >= 2:
        return "malicious"
    if total >= settings.suspicious_threshold:
        return "suspicious"
    return "likely_legitimate"


def _confidence(
    total: int,
    label: str,
    coverage: float,
    families_above: int,
    settings: Settings,
) -> float:
    if label == "malicious":
        margin = (total - settings.malicious_threshold) / max(
            1, 100 - settings.malicious_threshold
        )
        base = 0.65 + 0.30 * margin
    elif label == "suspicious":
        margin = (total - settings.suspicious_threshold) / max(
            1, settings.malicious_threshold - settings.suspicious_threshold
        )
        base = 0.45 + 0.25 * margin
    else:
        margin = (settings.suspicious_threshold - total) / max(
            1, settings.suspicious_threshold
        )
        base = 0.60 + 0.30 * margin
    coverage_factor = 0.65 + 0.35 * coverage
    agreement_factor = 0.90 + 0.10 * min(1.0, families_above / 2)
    return round(min(0.95, max(0.15, base * coverage_factor * agreement_factor)), 2)


def _top_reasons(families: dict[str, _Family]) -> list[str]:
    ranked: list[tuple[int, int, str]] = []
    for order, (_name, family) in enumerate(families.items()):
        for points, reason in family.reasons:
            if points > 0 and reason:
                ranked.append((points, order, reason))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return _dedupe([reason for _, _, reason in ranked])[:5]


def _baseline_reasons(
    email: EmailMeta, auth: AuthReport, enrichment: EnrichmentReport
) -> list[str]:
    reasons: list[str] = []
    if auth.alignment.from_domain:
        reasons.append("Sender authentication did not expose a strong failure")
    else:
        reasons.append("No sender-authentication evidence was available")
    reasons.append("No high-risk domain, IP, content, or header indicator was found")
    if enrichment.offline_mode:
        reasons.append("Domain and IP checks were limited to local/cached data")
    return reasons


def _brand_claim(display_name: str) -> bool:
    lowered = display_name.lower()
    return any(
        len(brand) >= 4 and re.search(rf"\b{re.escape(brand)}\b", lowered)
        for brand in BRANDS
    )


def _aligned(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return False
    a = left.strip().lower().strip(".")
    b = right.strip().lower().strip(".")
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result
