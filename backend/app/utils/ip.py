import ipaddress
import re

_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6_RE = re.compile(r"\[([0-9a-fA-F:]{3,39})\]")
_IPV6_BARE_RE = re.compile(r"(?<![\w:])([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![\w:])")


def normalize_ip(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip().strip("[](),;")
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return str(addr)


def is_public_ip(value: str | None) -> bool:
    candidate = normalize_ip(value)
    if candidate is None:
        return False
    addr = ipaddress.ip_address(candidate)
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    )


def find_ips(text: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()

    for match in _IPV4_RE.finditer(text):
        normalized = normalize_ip(match.group(0))
        if normalized and normalized not in seen:
            seen.add(normalized)
            found.append(normalized)

    for match in _IPV6_RE.finditer(text):
        normalized = normalize_ip(match.group(1))
        if normalized and normalized not in seen:
            seen.add(normalized)
            found.append(normalized)

    for match in _IPV6_BARE_RE.finditer(text):
        normalized = normalize_ip(match.group(1))
        if normalized and ":" in normalized and normalized not in seen:
            seen.add(normalized)
            found.append(normalized)

    return found
