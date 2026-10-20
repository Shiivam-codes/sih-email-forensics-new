import re
from datetime import datetime

from app.schemas import AuthReport, ReceivedHop, RoutingReport
from app.services.header_parser import ParsedEmail, parse_datetime
from app.utils.ip import find_ips, is_public_ip

_FROM_RE = re.compile(r"\bfrom\s+([^\s;()]+)", re.IGNORECASE)
_BY_RE = re.compile(r"\bby\s+([^\s;()]+)", re.IGNORECASE)


def _parse_received(raw: str, index: int) -> ReceivedHop:
    from_match = _FROM_RE.search(raw)
    by_match = _BY_RE.search(raw)
    ips = find_ips(raw)
    timestamp = None
    parsed_date = None
    if ";" in raw:
        candidate = raw.rsplit(";", 1)[-1].strip()
        parsed_date = parse_datetime(candidate)
        if parsed_date is not None:
            timestamp = parsed_date.isoformat()
    return ReceivedHop(
        index=index,
        from_host=from_match.group(1) if from_match else None,
        by_host=by_match.group(1) if by_match else None,
        ip=ips[0] if ips else None,
        timestamp=timestamp,
        raw=raw.strip(),
    )


def _delay_seconds(previous: datetime | None, current: datetime | None) -> int | None:
    if previous is None or current is None:
        return None
    if (previous.tzinfo is None) != (current.tzinfo is None):
        return None
    delta = int((current - previous).total_seconds())
    return delta


def resolve_origin(parsed: ParsedEmail, auth: AuthReport) -> RoutingReport:
    raw_headers = list(reversed(parsed.received_headers))
    hops = [_parse_received(raw, index) for index, raw in enumerate(raw_headers)]

    anomalies: list[str] = []
    if not hops:
        anomalies.append("no_received_headers")

    private_ip_present = False
    missing_timestamp = False
    regression = False
    previous_date: datetime | None = None

    for hop in hops:
        if hop.ip and not is_public_ip(hop.ip):
            private_ip_present = True
        hop_date = None
        if ";" in hop.raw:
            hop_date = parse_datetime(hop.raw.rsplit(";", 1)[-1].strip())
        if hop_date is None:
            missing_timestamp = True
        hop.delay_seconds = _delay_seconds(previous_date, hop_date)
        if hop.delay_seconds is not None and hop.delay_seconds < 0:
            regression = True
        if hop_date is not None:
            previous_date = hop_date

    if private_ip_present:
        anomalies.append("private_ip_in_chain")
    if missing_timestamp:
        anomalies.append("missing_hop_timestamp")
    if regression:
        anomalies.append("timestamp_regression")
    if len(hops) > 5:
        anomalies.append("high_hop_count")

    public_hops = [hop for hop in hops if hop.ip and is_public_ip(hop.ip)]
    origin_ip = public_hops[0].ip if public_hops else None
    confidence = 0.55 if origin_ip else 0.0
    method = "earliest_public_received_ip" if origin_ip else "unavailable"

    if origin_ip is None and auth.spf.client_ip and is_public_ip(auth.spf.client_ip):
        origin_ip = auth.spf.client_ip
        confidence = 0.4
        method = "authentication_results_client_ip"

    if not origin_ip:
        anomalies.append("origin_undetermined")

    return RoutingReport(
        hops=hops,
        origin_ip=origin_ip,
        origin_confidence=confidence,
        origin_method=method,
        anomalies=anomalies,
        public_ip_count=len(public_hops),
    )
