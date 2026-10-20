from collections.abc import Callable
from datetime import datetime

from app.core.config import Settings
from app.enrichers.common import SourceTracker
from app.enrichers.domain_enrich import (
    DnsResolver,
    DomainEnricher,
    RdapLookup,
    normalize_domain,
)
from app.enrichers.geoip import GeoIpDatabase
from app.enrichers.ip_enrich import IpEnricher, TorExitList
from app.enrichers.url_enrich import UrlEnricher
from app.schemas import IOC, EnrichmentReport, RoutingReport, SourceStatus
from app.utils.budget import RequestBudget
from app.utils.cache import TTLCache
from app.utils.http import HttpClient
from app.utils.ip import normalize_ip

SOURCE_NAMES = (
    "geoip",
    "internetdb",
    "tor_exit_list",
    "dns",
    "rdap",
    "lookalike",
    "url_passive",
)


class EnrichmentService:
    def __init__(
        self,
        settings: Settings,
        cache: TTLCache | None = None,
        http: HttpClient | None = None,
        geoip: GeoIpDatabase | None = None,
        dns: DnsResolver | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings
        self.offline_mode = settings.offline_mode
        self._owns_cache = cache is None
        self._owns_http = http is None
        self._owns_geoip = geoip is None
        self.cache = cache or TTLCache(settings.cache_path)
        self.budget = RequestBudget(self.cache, settings.daily_external_request_limit)
        self.http = http or HttpClient(
            timeout_seconds=settings.http_timeout_seconds,
            offline=settings.offline_mode,
        )
        self.geoip = geoip or GeoIpDatabase(settings.geoip_city_path, settings.geoip_asn_path)
        self.dns = dns or DnsResolver(settings.dns_timeout_seconds)
        self.tor = TorExitList(
            self.http,
            self.cache,
            self.budget,
            settings.offline_mode,
            settings.tor_exit_list_enabled,
        )
        self.ip = IpEnricher(
            self.geoip,
            self.http,
            self.cache,
            self.budget,
            self.tor,
            settings.offline_mode,
            settings.internetdb_enabled,
        )
        rdap = RdapLookup(
            self.http,
            self.cache,
            self.budget,
            settings.offline_mode,
            settings.rdap_enabled,
        )
        self.domain = DomainEnricher(
            self.dns,
            rdap,
            self.cache,
            settings.offline_mode,
            now=now,
        )
        self.url = UrlEnricher()

    def enrich(
        self,
        routing: RoutingReport,
        iocs: list[IOC],
    ) -> EnrichmentReport:
        tracker = SourceTracker()
        report = EnrichmentReport(offline_mode=self.offline_mode, status="not_queried")
        if not self.settings.internetdb_enabled:
            tracker.mark("internetdb", "disabled")
        if not self.settings.tor_exit_list_enabled:
            tracker.mark("tor_exit_list", "disabled")
        if not self.settings.rdap_enabled:
            tracker.mark("rdap", "disabled")
        if self.offline_mode:
            report.notes.append(
                "Offline mode: external DNS, RDAP, InternetDB, and Tor exit-list lookups skipped"
            )

        ip_candidates = _candidate_ips(routing, iocs)
        public_lookups = 0
        capped = False
        for candidate in ip_candidates:
            if public_lookups >= self.settings.max_ip_lookups:
                capped = True
                break
            intel, cache_hit = self.ip.lookup(candidate, tracker)
            report.ip[intel.ip] = intel
            if intel.scope == "public":
                public_lookups += 1
                if cache_hit:
                    report.cache_hits += 1
                else:
                    report.cache_misses += 1
        if capped:
            report.notes.append(
                f"IP enrichment capped at {self.settings.max_ip_lookups} public addresses"
            )

        domain_candidates = _candidate_domains(iocs)
        if domain_candidates:
            for candidate in domain_candidates[: self.settings.max_domain_lookups]:
                intel, cache_hit = self.domain.lookup(candidate, tracker)
                report.domain[intel.domain] = intel
                if cache_hit:
                    report.cache_hits += 1
                else:
                    report.cache_misses += 1
            if len(domain_candidates) > self.settings.max_domain_lookups:
                report.notes.append(
                    f"Domain enrichment capped at {self.settings.max_domain_lookups} domains"
                )
            tracker.mark("lookalike", "ok")

        url_candidates = _candidate_urls(iocs)
        if url_candidates:
            for candidate in url_candidates[: self.settings.max_url_lookups]:
                intel = self.url.lookup(candidate)
                report.url[intel.url] = intel
            self.url.mark_source(tracker)
            if any("lookalike" in intel.sources for intel in report.url.values()):
                tracker.mark("lookalike", "ok")
            if len(url_candidates) > self.settings.max_url_lookups:
                report.notes.append(
                    f"URL enrichment capped at {self.settings.max_url_lookups} URLs"
                )

        for source in SOURCE_NAMES:
            if source not in tracker.as_dict():
                tracker.mark(source, "not_queried")
        report.sources = tracker.as_dict()
        report.status = _report_status(report)

        if not self.geoip.available:
            report.notes.append("GeoIP database unavailable; no city or ASN context")
        if not self.settings.enrichment_enabled:
            report.notes.append("Enrichment is disabled in configuration")
        report.notes.append(
            "Geolocation is approximate and does not prove the physical sender location"
        )
        return report

    def health(self) -> dict[str, object]:
        return {
            "enabled": self.settings.enrichment_enabled,
            "offline_mode": self.offline_mode,
            "cache_backend": self.cache.backend,
            "geoip_ready": self.geoip.available,
            "daily_request_limit": self.settings.daily_external_request_limit,
            "daily_requests_remaining": self.budget.remaining(),
        }

    def close(self) -> None:
        if self._owns_http:
            self.http.close()
        if self._owns_geoip:
            self.geoip.close()
        if self._owns_cache:
            self.cache.close()


def disabled_report(offline_mode: bool = False) -> EnrichmentReport:
    return EnrichmentReport(
        offline_mode=offline_mode,
        status="disabled",
        sources={source: SourceStatus(source=source, status="disabled") for source in SOURCE_NAMES},
        notes=["Enrichment is disabled"],
    )


def _candidate_ips(routing: RoutingReport, iocs: list[IOC]) -> list[str]:
    ordered: list[str] = []
    if routing.origin_ip:
        ordered.append(routing.origin_ip)
    ordered.extend(hop.ip for hop in routing.hops if hop.ip)
    ordered.extend(ioc.value for ioc in iocs if ioc.type == "ip")
    return _dedupe(ordered, normalize_ip)


def _candidate_domains(iocs: list[IOC]) -> list[str]:
    ordered: list[str] = []
    for ioc in iocs:
        if ioc.type == "domain":
            ordered.append(ioc.value)
    return _dedupe(ordered, normalize_domain)


def _candidate_urls(iocs: list[IOC]) -> list[str]:
    return _dedupe((ioc.value for ioc in iocs if ioc.type == "url"), lambda value: value.strip())


def _dedupe(values, normalizer) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        normalized = normalizer(value)
        if normalized is None or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result


def _report_status(report: EnrichmentReport) -> str:
    statuses = [status.status for status in report.sources.values()]
    queried = [status for status in statuses if status != "not_queried"]
    if not queried:
        return "not_queried"
    if all(status in {"ok", "disabled"} for status in queried):
        return "complete"
    if any(status in {"ok", "partial"} for status in queried):
        return "partial"
    if report.offline_mode:
        return "offline"
    return "unavailable"
