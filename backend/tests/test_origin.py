def test_legit_origin_and_delay(analyze_fixture):
    result = analyze_fixture("legit_business.eml")

    assert len(result.routing.hops) == 2
    assert result.routing.hops[0].ip == "13.107.42.14"
    assert result.routing.hops[1].ip == "52.95.110.10"
    assert result.routing.hops[1].delay_seconds == 2
    assert result.routing.origin_ip == "13.107.42.14"
    assert result.routing.origin_method == "earliest_public_received_ip"
    assert result.routing.origin_confidence == 0.55


def test_phishing_origin_uses_earliest_public_hop(analyze_fixture):
    result = analyze_fixture("phishing_credential.eml")

    assert len(result.routing.hops) == 2
    assert result.routing.hops[0].ip == "127.0.0.1"
    assert result.routing.origin_ip == "185.220.101.45"
    assert "private_ip_in_chain" in result.routing.anomalies


def test_forwarded_chain_origin(analyze_fixture):
    result = analyze_fixture("forwarded_mailing_list.eml")

    assert len(result.routing.hops) == 4
    assert result.routing.hops[0].ip == "45.33.32.156"
    assert result.routing.origin_ip == "45.33.32.156"
    assert result.routing.anomalies == []


def test_missing_received_headers_leave_origin_undetermined(analyze_fixture):
    result = analyze_fixture("malformed.eml")

    assert result.routing.hops == []
    assert result.routing.origin_ip is None
    assert result.routing.origin_confidence == 0.0
    assert "no_received_headers" in result.routing.anomalies
    assert "origin_undetermined" in result.routing.anomalies
