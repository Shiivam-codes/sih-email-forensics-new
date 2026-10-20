from typing import Any

from app.enrichers.common import SourceTracker
from app.enrichers.geoip import GeoIpDatabase
from app.schemas import IpIntel
from app.utils.budget import RequestBudget
from app.utils.cache import TTLCache
from app.utils.http import BudgetExceeded, HttpClient, SourceUnavailable
from app.utils.ip import ip_scope, normalize_ip

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"

HOSTING_KEYWORDS = (
    "hosting",
    "datacenter",
    "data center",
    "server",
    "vps",
    "colocation",
    "colo",
    "dedicated",
)
VPN_KEYWORDS = (
    "vpn",
    "nordvpn",
    "expressvpn",
    "surfshark",
    "mullvad",
    "ipvanish",
    "private internet access",
    "proton",
)
CLOUD_KEYWORDS = (
    "amazon",
    "google",
    "microsoft",
    "oracle",
    "alibaba",
    "digitalocean",
    "cloudflare",
    "akamai",
    "linode",
    "vultr",
    "hetzner",
)


class TorExitList:
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
        self.status = "not_queried"
        self.detail: str | None = None
        self._exits: set[str] | None = None

    def lookup(self, ip: str) -> bool | None:
        if not self.enabled:
            self.status = "disabled"
            return None
        if self.offline:
            self.status = "offline"
            return None
        exits = self._load()
        if exits is None:
            return None
        return ip in exits

    def _load(self) -> set[str] | None:
        if self._exits is not None:
            return self._exits
        cached = self.cache.get("feed:tor_exit_list")
        if cached is not None:
            self._exits = set(cached)
            self.status = "ok"
            return self._exits
        try:
            text = self.http.get_text(TOR_EXIT_LIST_URL, "tor_exit_list", self.budget)
        except BudgetExceeded:
            self.status = "budget_exceeded"
            self.detail = "daily external request budget exhausted"
            return None
        except SourceUnavailable as exc:
            self.status = "unavailable"
            self.detail = exc.reason
            return None
        if text is None:
            self.status = "unavailable"
            self.detail = "empty Tor exit list"
            return None
        exits: set[str] = set()
        for line in text.splitlines():
            value = normalize_ip(line.strip())
            if value is not None:
                exits.add(value)
        if not exits:
            self.status = "unavailable"
            self.detail = "Tor exit list contained no usable addresses"
            return None
        self.cache.set("feed:tor_exit_list", sorted(exits), 24 * 60 * 60)
        self._exits = exits
        self.status = "ok"
        return exits


class IpEnricher:
    def __init__(
        self,
        geoip: GeoIpDatabase,
        http: HttpClient,
        cache: TTLCache,
        budget: RequestBudget,
        tor: TorExitList,
        offline: bool,
        internetdb_enabled: bool,
        cache_ttl_seconds: int = 7 * 24 * 60 * 60,
    ) -> None:
        self.geoip = geoip
        self.http = http
        self.cache = cache
        self.budget = budget
        self.tor = tor
        self.offline = offline
        self.internetdb_enabled = internetdb_enabled
        self.cache_ttl_seconds = cache_ttl_seconds

    def lookup(self, value: str, tracker: SourceTracker) -> tuple[IpIntel, bool]:
        ip = normalize_ip(value)
        if ip is None:
            return IpIntel(ip=value, scope="invalid", notes=["Invalid IP address"]), False

        scope = ip_scope(ip)
        if scope != "public":
            return (
                IpIntel(
                    ip=ip,
                    scope=scope,
                    notes=["External geolocation and reputation lookup skipped"],
                ),
                False,
            )

        cache_key = f"ip:{ip}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            intel = IpIntel.model_validate(cached)
            if "geoip" in intel.sources:
                tracker.mark("geoip", "ok")
            if "internetdb" in intel.sources:
                tracker.mark("internetdb", "ok")
            if "tor_exit_list" in intel.sources:
                tracker.mark("tor_exit_list", "ok")
            return intel, True

        geo = self.geoip.lookup(ip)
        if self.geoip.available:
            tracker.mark("geoip", "ok")
        else:
            tracker.mark("geoip", "unavailable", self.geoip.detail)

        internetdb: dict[str, Any] | None = None
        if self.internetdb_enabled:
            if self.offline:
                tracker.mark("internetdb", "offline")
            else:
                try:
                    internetdb = self.http.get_json(
                        INTERNETDB_URL.format(ip=ip),
                        "internetdb",
                        self.budget,
                        allow_404=True,
                    )
                except BudgetExceeded:
                    tracker.mark("internetdb", "budget_exceeded")
                except SourceUnavailable as exc:
                    tracker.mark("internetdb", "unavailable", exc.reason)
                else:
                    if internetdb is None:
                        tracker.mark("internetdb", "unavailable", "no InternetDB record")
                    else:
                        tracker.mark("internetdb", "ok")
        else:
            tracker.mark("internetdb", "disabled")

        tor = self.tor.lookup(ip)
        tracker.mark("tor_exit_list", self.tor.status, self.tor.detail)

        tags = self._string_list(internetdb, "tags") if internetdb else []
        ports = self._int_list(internetdb, "ports") if internetdb else []
        vulns = self._vulns(internetdb)
        as_org = geo.get("as_org")
        org_lower = (as_org or "").lower()

        hosting_tag = "hosting" in tags
        hosting_org = any(keyword in org_lower for keyword in HOSTING_KEYWORDS)
        vpn_tag = "vpn" in tags
        vpn_org = any(keyword in org_lower for keyword in VPN_KEYWORDS)
        cloud_tag = "cloud" in tags
        cloud_org = any(keyword in org_lower for keyword in CLOUD_KEYWORDS)
        tor_tag = "tor" in tags

        hosting = True if hosting_tag or hosting_org else (False if internetdb else None)
        vpn = True if vpn_tag or vpn_org else (False if internetdb else None)
        cloud = True if cloud_tag or cloud_org else (False if internetdb else None)
        tor_value = True if tor is True or tor_tag else (False if tor is not None else None)

        sources: list[str] = []
        if geo:
            sources.append("geoip")
        if internetdb:
            sources.append("internetdb")
        if tor is not None:
            sources.append("tor_exit_list")
        if hosting_org or vpn_org or cloud_org:
            sources.append("asn_heuristics")

        notes: list[str] = []
        if not geo:
            notes.append("No city/ASN record for this address")
        if self.internetdb_enabled and internetdb is None and not self.offline:
            notes.append("InternetDB details unavailable")
        if self.tor.status in {"unavailable", "budget_exceeded"}:
            notes.append("Tor exit status unavailable")

        intel = IpIntel(
            ip=ip,
            scope=scope,
            country=geo.get("country"),
            country_code=geo.get("country_code"),
            city=geo.get("city"),
            region=geo.get("region"),
            latitude=geo.get("latitude"),
            longitude=geo.get("longitude"),
            timezone=geo.get("timezone"),
            asn=geo.get("asn"),
            isp=as_org,
            as_org=as_org,
            hosting=hosting,
            vpn=vpn,
            tor=tor_value,
            cloud=cloud,
            tags=tags,
            ports=ports,
            vulns=vulns,
            available=bool(sources),
            sources=sources,
            notes=notes,
        )
        ttl = self.cache_ttl_seconds if internetdb or tor is not None else 60 * 60
        self.cache.set(cache_key, intel.model_dump(mode="json"), ttl)
        return intel, False

    @staticmethod
    def _string_list(payload: dict[str, Any] | None, key: str) -> list[str]:
        if not payload:
            return []
        values = payload.get(key, [])
        if not isinstance(values, list):
            return []
        return [str(value) for value in values]

    @staticmethod
    def _int_list(payload: dict[str, Any] | None, key: str) -> list[int]:
        if not payload:
            return []
        values = payload.get(key, [])
        if not isinstance(values, list):
            return []
        result: list[int] = []
        for value in values:
            try:
                result.append(int(value))
            except (TypeError, ValueError):
                continue
        return result

    @staticmethod
    def _vulns(payload: dict[str, Any] | None) -> list[str]:
        if not payload:
            return []
        values = payload.get("vulns", {})
        if isinstance(values, dict):
            return sorted(str(value) for value in values)
        if isinstance(values, list):
            return sorted(str(value) for value in values)
        return []
