from datetime import UTC, datetime
from types import SimpleNamespace

import httpx
import pytest

from app.core.config import Settings
from app.enrichers.domain_enrich import DnsResolver
from app.enrichers.service import EnrichmentService
from app.schemas import IOC, ReceivedHop, RoutingReport
from app.utils.budget import RequestBudget
from app.utils.cache import TTLCache
from app.utils.http import HttpClient, SourceUnavailable


class FakeGeoIp:
    def __init__(self) -> None:
        self.available = True
        self.detail = None

    def lookup(self, ip: str) -> dict[str, object]:
        if ip == "8.8.8.8":
            return {
                "country": "United States",
                "country_code": "US",
                "city": "Mountain View",
                "region": "California",
                "latitude": 37.4,
                "longitude": -122.1,
                "timezone": "America/Los_Angeles",
                "asn": 15169,
                "as_org": "Google LLC",
            }
        return {}

    def close(self) -> None:
        return None


class FakeName:
    def __init__(self, value: str) -> None:
        self.value = value

    def to_text(self, omit_final_dot: bool = False) -> str:
        return self.value.rstrip(".") if omit_final_dot else self.value


class FakeResolver:
    def __init__(self) -> None:
        self.queries: list[tuple[str, str]] = []

    def resolve(self, name: str, rdtype: str, lifetime: float | None = None):
        self.queries.append((name, rdtype))
        if rdtype == "A":
            return [SimpleNamespace(address="203.0.113.10")]
        if rdtype == "MX":
            return [SimpleNamespace(exchange=FakeName("mail.micros0ft-verify.com."))]
        if rdtype == "NS":
            return [SimpleNamespace(target=FakeName("ns1.example.net."))]
        if rdtype == "TXT" and name.startswith("_dmarc."):
            return [SimpleNamespace(strings=[b"v=DMARC1; p=reject"])]
        if rdtype == "TXT":
            return [SimpleNamespace(strings=[b"v=spf1 include:example.net -all"])]
        return []


class ExplodingResolver:
    lifetime = 1.0
    timeout = 1.0

    def resolve(self, name: str, rdtype: str, lifetime: float | None = None):
        raise AssertionError("DNS must not be called in offline mode")


def settings_for(tmp_path, **overrides) -> Settings:
    values = {
        "database_path": str(tmp_path / "test.db"),
        "cache_path": str(tmp_path / "cache"),
        "geoip_city_path": str(tmp_path / "missing-city.mmdb"),
        "geoip_asn_path": str(tmp_path / "missing-asn.mmdb"),
        "internetdb_enabled": False,
        "tor_exit_list_enabled": False,
        "rdap_enabled": True,
        "offline_mode": False,
        "daily_external_request_limit": 10,
        "max_ip_lookups": 3,
        "max_domain_lookups": 4,
        "max_url_lookups": 5,
    }
    values.update(overrides)
    return Settings(**values)


def rdap_transport(calls: list[str]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(
            200,
            json={
                "events": [
                    {"eventAction": "registration", "eventDate": "2026-10-10T00:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2027-10-10T00:00:00Z"},
                ],
                "status": ["client transfer prohibited"],
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": [
                            "vcard",
                            [["fn", {}, "text", "Example Registrar, Inc."]],
                        ],
                    }
                ],
            },
        )

    return httpx.MockTransport(handler)


def test_ip_enrichment_public_private_and_cache(tmp_path):
    settings = settings_for(
        tmp_path,
        internetdb_enabled=True,
        daily_external_request_limit=1,
    )
    cache = TTLCache(settings.cache_path)
    http = HttpClient(
        offline=False,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={"tags": ["hosting", "cloud"], "ports": [443], "vulns": {"CVE-2026-0001": {}}},
            )
        ),
    )
    service = EnrichmentService(
        settings,
        cache=cache,
        http=http,
        geoip=FakeGeoIp(),
        dns=DnsResolver(resolver=FakeResolver()),
    )
    routing = RoutingReport(
        origin_ip="8.8.8.8",
        public_ip_count=1,
        hops=[
            ReceivedHop(index=1, ip="192.168.1.10"),
            ReceivedHop(index=2, ip="8.8.8.8"),
        ],
    )

    report = service.enrich(routing, [])
    public = report.ip["8.8.8.8"]
    private = report.ip["192.168.1.10"]

    assert public.country == "United States"
    assert public.asn == 15169
    assert public.hosting is True
    assert public.cloud is True
    assert public.tor is None
    assert public.ports == [443]
    assert public.vulns == ["CVE-2026-0001"]
    assert private.scope == "private"
    assert private.country is None
    assert report.cache_misses == 1
    assert report.sources["internetdb"].status == "ok"

    second = service.enrich(routing, [])
    assert second.cache_hits == 1
    assert second.cache_misses == 0
    assert second.sources["geoip"].status == "ok"
    assert second.sources["internetdb"].status == "ok"
    service.close()


def test_domain_enrichment_dns_rdap_lookalike_and_cache(tmp_path):
    settings = settings_for(tmp_path)
    cache = TTLCache(settings.cache_path)
    rdap_calls: list[str] = []
    http = HttpClient(offline=False, transport=rdap_transport(rdap_calls))
    service = EnrichmentService(
        settings,
        cache=cache,
        http=http,
        geoip=FakeGeoIp(),
        dns=DnsResolver(resolver=FakeResolver()),
        now=lambda: datetime(2026, 10, 20, tzinfo=UTC),
    )

    report = service.enrich(
        RoutingReport(),
        [IOC(type="domain", value="micros0ft-verify.com", context="header:from")],
    )
    domain = report.domain["micros0ft-verify.com"]

    assert domain.age_days == 10
    assert domain.registrar == "Example Registrar, Inc."
    assert domain.mx == ["mail.micros0ft-verify.com"]
    assert domain.spf == "v=spf1 include:example.net -all"
    assert domain.dmarc == "v=DMARC1; p=reject"
    assert domain.lookalike_of == "microsoft.com"
    assert domain.distance == 1
    assert report.cache_misses == 1
    assert len(rdap_calls) == 1

    second = service.enrich(
        RoutingReport(),
        [IOC(type="domain", value="micros0ft-verify.com", context="header:from")],
    )
    assert second.cache_hits == 1
    assert len(rdap_calls) == 1
    service.close()


def test_offline_enrichment_is_structured_and_skips_network(tmp_path):
    settings = settings_for(
        tmp_path,
        offline_mode=True,
        rdap_enabled=True,
        internetdb_enabled=True,
        tor_exit_list_enabled=True,
    )
    service = EnrichmentService(
        settings,
        cache=TTLCache(settings.cache_path),
        http=HttpClient(offline=True),
        geoip=FakeGeoIp(),
        dns=DnsResolver(resolver=ExplodingResolver()),
    )

    report = service.enrich(
        RoutingReport(origin_ip="8.8.8.8", public_ip_count=1),
        [
            IOC(type="domain", value="micros0ft-verify.com", context="header:from"),
            IOC(type="url", value="http://185.220.101.45/login", context="body"),
        ],
    )

    assert report.offline_mode is True
    assert report.sources["dns"].status == "offline"
    assert report.sources["rdap"].status == "offline"
    assert report.sources["internetdb"].status == "offline"
    assert report.sources["tor_exit_list"].status == "offline"
    assert report.domain["micros0ft-verify.com"].lookalike_of == "microsoft.com"
    assert report.url["http://185.220.101.45/login"].ip_literal is True
    assert any("Offline mode" in note for note in report.notes)
    service.close()


def test_url_heuristics(tmp_path):
    service = EnrichmentService(
        settings_for(tmp_path, offline_mode=True),
        cache=TTLCache(str(tmp_path / "cache")),
        http=HttpClient(offline=True),
        geoip=FakeGeoIp(),
        dns=DnsResolver(resolver=ExplodingResolver()),
    )
    report = service.enrich(
        RoutingReport(),
        [
            IOC(type="url", value="http://bit.ly/abc", context="body"),
            IOC(type="url", value="https://xn--pple-43d.com/login", context="body"),
        ],
    )

    shortened = report.url["http://bit.ly/abc"]
    punycode = report.url["https://xn--pple-43d.com/login"]

    assert shortened.shortened is True
    assert shortened.suspicious is True
    assert punycode.punycode is True
    assert punycode.lookalike_of == "apple.com"
    assert punycode.https is True
    assert report.sources["url_passive"].status == "ok"
    service.close()


def test_daily_budget(tmp_path):
    cache = TTLCache(str(tmp_path / "cache"))
    budget = RequestBudget(cache, daily_limit=2)

    assert budget.consume("rdap") is True
    assert budget.consume("internetdb") is True
    assert budget.consume("rdap") is False
    assert budget.remaining() == 0

    record = cache.get(f"budget:{datetime.now(UTC).date().isoformat()}")
    assert record["count"] == 2
    assert record["sources"] == {"rdap": 1, "internetdb": 1}
    cache.close()


def test_http_offline_raises_structured_error():
    client = HttpClient(offline=True)
    with pytest.raises(SourceUnavailable) as error:
        client.get_json("https://example.invalid", "internetdb")
    assert error.value.source == "internetdb"
    assert error.value.reason == "offline mode"
    client.close()


def test_http_circuit_breaker():
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(500)

    client = HttpClient(
        timeout_seconds=0.5,
        transport=httpx.MockTransport(handler),
        max_failures=2,
    )
    for _ in range(2):
        with pytest.raises(SourceUnavailable):
            client.get_json("https://example.invalid", "rdap")
    with pytest.raises(SourceUnavailable) as error:
        client.get_json("https://example.invalid", "rdap")
    assert "circuit breaker" in error.value.reason
    assert len(calls) == 4
    client.close()
