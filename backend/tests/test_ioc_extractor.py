def test_phishing_iocs(analyze_fixture):
    result = analyze_fixture("phishing_credential.eml")
    values = {(ioc.type, ioc.value) for ioc in result.iocs}

    assert ("domain", "micros0ft-verify.com") in values
    assert ("domain", "cdn.micros0ft-verify.com") in values
    assert ("ip", "185.220.101.45") in values
    assert ("email", "security@micros0ft-verify.com") in values
    assert any(ioc.type == "url" and "session=8842" in ioc.value for ioc in result.iocs)


def test_attachment_hash_is_an_ioc(analyze_fixture):
    result = analyze_fixture("bec_wire_transfer.eml")
    attachment = result.email.attachments[0]
    values = {(ioc.type, ioc.value) for ioc in result.iocs}

    assert ("sha256", attachment.sha256) in values
    assert any(ioc.context == "attachment:invoice_october.pdf" for ioc in result.iocs)


def test_iocs_are_unique(analyze_fixture):
    result = analyze_fixture("phishing_credential.eml")
    keys = [(ioc.type, ioc.value.lower()) for ioc in result.iocs]

    assert len(keys) == len(set(keys))
    assert len(result.iocs) <= 200
