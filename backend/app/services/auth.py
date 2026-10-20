import re

from app.schemas import AlignmentReport, AuthReport, AuthResult, DkimResult
from app.services.header_parser import ParsedEmail

_MECHANISM_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)")
_DOMAIN_PATTERNS = (
    re.compile(r"header\.d\s*=\s*([^\s;]+)", re.IGNORECASE),
    re.compile(r"header\.from\s*=\s*([^\s;]+)", re.IGNORECASE),
    re.compile(r"smtp\.mailfrom\s*=\s*([^\s;]+)", re.IGNORECASE),
    re.compile(r"header\.i\s*=\s*@?([^\s;]+)", re.IGNORECASE),
    re.compile(r"envelope-from\s*=\s*<?([^\s;>]+)", re.IGNORECASE),
)
_CLIENT_IP_RE = re.compile(r"client-ip\s*=\s*([0-9a-fA-F:.]+)", re.IGNORECASE)
_SELECTOR_RE = re.compile(r"header\.s\s*=\s*([^\s;]+)", re.IGNORECASE)


def _domain_from_value(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip().strip("<>").lower()
    if "@" in value:
        value = value.rsplit("@", 1)[-1]
    return value or None


def _extract_domain(segment: str) -> str | None:
    for pattern in _DOMAIN_PATTERNS:
        match = pattern.search(segment)
        if match:
            return _domain_from_value(match.group(1))
    return None


def _extract_client_ip(segment: str) -> str | None:
    match = _CLIENT_IP_RE.search(segment)
    return match.group(1) if match else None


def _segments(header: str) -> list[str]:
    return [segment.strip() for segment in re.split(r";", header) if segment.strip()]


def _aligned(domain_a: str | None, domain_b: str | None) -> bool | None:
    if not domain_a or not domain_b:
        return None
    a = domain_a.strip().lower().strip(".")
    b = domain_b.strip().lower().strip(".")
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def build_auth_report(parsed: ParsedEmail) -> AuthReport:
    message = parsed.message
    from_domain = _domain_from_value(str(message.get("From", "")) or None)
    return_path_domain = _domain_from_value(str(message.get("Return-Path", "")) or None)
    reply_to_domain = _domain_from_value(str(message.get("Reply-To", "")) or None)

    spf = AuthResult(result="none", source="absent")
    dmarc = AuthResult(result="none", source="absent")
    dkim: list[DkimResult] = []
    notes: list[str] = []

    ar_headers = [str(value) for value in message.get_all("Authentication-Results", [])]
    spf_seen = False
    dmarc_seen = False

    for header in ar_headers:
        for segment in _segments(header):
            match = _MECHANISM_RE.search(segment)
            if not match:
                continue
            mechanism = match.group(1).lower()
            result = match.group(2).lower()
            domain = _extract_domain(segment)
            client_ip = _extract_client_ip(segment)

            if mechanism == "spf" and not spf_seen:
                spf = AuthResult(
                    result=result,
                    domain=domain,
                    client_ip=client_ip,
                    source="Authentication-Results",
                    detail=segment,
                )
                spf_seen = True
            elif mechanism == "dmarc" and not dmarc_seen:
                dmarc = AuthResult(
                    result=result,
                    domain=domain,
                    source="Authentication-Results",
                    detail=segment,
                )
                dmarc_seen = True
            elif mechanism == "dkim":
                selector_match = _SELECTOR_RE.search(segment)
                dkim.append(
                    DkimResult(
                        result=result,
                        domain=domain,
                        source="Authentication-Results",
                        detail=segment,
                        selector=selector_match.group(1) if selector_match else None,
                    )
                )

    if not spf_seen:
        received_spf = [str(value) for value in message.get_all("Received-SPF", [])]
        for header in received_spf:
            match = re.match(r"\s*([a-zA-Z]+)", header)
            if not match:
                continue
            envelope = re.search(
                r"envelope-from\s*=\s*<?([^\s;>]+)", header, re.IGNORECASE
            )
            spf = AuthResult(
                result=match.group(1).lower(),
                domain=_domain_from_value(envelope.group(1) if envelope else None),
                client_ip=_extract_client_ip(header),
                source="Received-SPF",
                detail=header,
            )
            break

    if not ar_headers and not message.get_all("Received-SPF", []):
        notes.append("No SPF, DKIM, or DMARC validation headers were found")

    passing_aligned_dkim = any(
        entry.result == "pass" and _aligned(entry.domain, from_domain) for entry in dkim
    )

    spf_aligned = _aligned(return_path_domain, from_domain)
    dkim_aligned = (
        any(_aligned(entry.domain, from_domain) for entry in dkim if entry.result == "pass")
        if dkim
        else None
    )

    if spf.result in {"fail", "softfail"} and passing_aligned_dkim:
        notes.append("SPF did not pass but an aligned DKIM signature passed; common in forwarding")
    if dmarc.result in {"fail"}:
        notes.append("DMARC failed for the visible From domain")
    if dkim and all(entry.result != "pass" for entry in dkim):
        notes.append("No DKIM signature passed validation")
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        notes.append("Reply-To domain differs from the From domain")

    results = {spf.result, dmarc.result}
    results.update(entry.result for entry in dkim)

    has_failure = any(result in {"fail", "softfail", "permerror"} for result in results)
    has_pass = any(result == "pass" for result in results)
    has_unknown = all(result in {"none", "neutral", "temperror"} for result in results)

    if has_unknown:
        verdict = "unknown"
    elif dmarc.result == "fail":
        verdict = "fail"
    elif spf.result in {"fail", "softfail"} and not passing_aligned_dkim:
        verdict = "fail"
    elif has_failure or (has_pass and any(result == "none" for result in results)):
        verdict = "partial"
    elif has_pass:
        verdict = "pass"
    else:
        verdict = "unknown"

    return AuthReport(
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        alignment=AlignmentReport(
            from_domain=from_domain or "",
            return_path_domain=return_path_domain,
            reply_to_domain=reply_to_domain,
            spf_aligned=spf_aligned,
            dkim_aligned=dkim_aligned,
            reply_to_mismatch=bool(
                reply_to_domain and from_domain and reply_to_domain != from_domain
            ),
        ),
        verdict=verdict,
        notes=notes,
    )
