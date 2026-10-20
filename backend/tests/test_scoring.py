from app.core.config import Settings
from app.enrichers.domain_enrich import find_lookalike
from app.schemas import DomainIntel, EnrichmentReport, IpIntel, UrlIntel
from app.services.scorer import score_analysis


def _score(result, enrichment):
    return score_analysis(
        result.email,
        result.auth,
        result.routing,
        enrichment,
        Settings(),
    )


def test_phishing_fixture_reaches_malicious(analyze_fixture):
    result = analyze_fixture("phishing_credential.eml")
    enrichment = EnrichmentReport(
        ip={
            "185.220.101.45": IpIntel(
                ip="185.220.101.45",
                scope="public",
                available=True,
                tor=True,
            )
        },
        domain={
            "micros0ft-verify.com": DomainIntel(
                domain="micros0ft-verify.com",
                available=True,
                lookalike_of="microsoft.com",
                distance=1,
                sources=["dns"],
            )
        },
        url={
            "https://micros0ft-verify.com/login": UrlIntel(
                url="https://micros0ft-verify.com/login",
                host="micros0ft-verify.com",
                suspicious=True,
            )
        },
    )

    score = _score(result, enrichment)

    assert score.total >= 70
    assert score.label == "malicious"
    assert score.signals["ip"] == 20
    assert score.signals["domain"] == 14
    assert score.families_above_threshold >= 2


def test_bec_fixture_stays_suspicious(analyze_fixture):
    result = analyze_fixture("bec_wire_transfer.eml")
    enrichment = EnrichmentReport(
        domain={
            "acme-finance.com": DomainIntel(
                domain="acme-finance.com",
                available=True,
                sources=["dns"],
            ),
            "acme-corp.com": DomainIntel(
                domain="acme-corp.com",
                available=True,
                sources=["dns"],
            ),
        }
    )

    score = _score(result, enrichment)

    assert 40 <= score.total < 70
    assert score.label == "suspicious"
    assert score.signals["content"] == 20


def test_forwarded_mailing_list_remains_likely_legitimate(analyze_fixture):
    result = analyze_fixture("forwarded_mailing_list.eml")

    score = _score(result, EnrichmentReport())

    assert score.label == "likely_legitimate"
    assert score.signals["auth"] == 0
    assert score.signals["content"] == 0


def test_spoofed_display_name_is_suspicious(analyze_fixture):
    result = analyze_fixture("spoofed_display_name.eml")
    enrichment = EnrichmentReport(
        url={
            "https://microsoft-support-desk.net/verify": UrlIntel(
                url="https://microsoft-support-desk.net/verify",
                host="microsoft-support-desk.net",
                lookalike_of="microsoft.com",
                distance=0,
                suspicious=True,
            )
        },
        domain={
            "gmail.com": DomainIntel(
                domain="gmail.com",
                available=True,
                spf="v=spf1 redirect=_spf.google.com",
                dmarc="v=DMARC1; p=none",
                sources=["dns", "rdap"],
            ),
            "microsoft-support-desk.net": DomainIntel(
                domain="microsoft-support-desk.net",
                available=True,
                lookalike_of="microsoft.com",
                distance=0,
                sources=["dns"],
            ),
        }
    )

    score = _score(result, enrichment)

    assert 40 <= score.total < 70
    assert score.label == "suspicious"
    assert score.signals["domain"] == 20


def test_malformed_message_has_low_confidence(analyze_fixture):
    result = analyze_fixture("malformed.eml")

    score = _score(result, EnrichmentReport())

    assert score.label == "likely_legitimate"
    assert score.coverage < 0.6
    assert score.confidence < 0.65


def test_lookalike_rejects_common_word_but_accepts_homoglyph():
    assert find_lookalike("acme-finance.com") == (None, None)
    assert find_lookalike("xn--pple-43d.com") == ("apple.com", 0)
