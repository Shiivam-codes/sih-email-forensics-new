def test_legit_email_passes_authentication(analyze_fixture):
    result = analyze_fixture("legit_business.eml")

    assert result.auth.spf.result == "pass"
    assert result.auth.dmarc.result == "pass"
    assert result.auth.dkim[0].result == "pass"
    assert result.auth.verdict == "pass"
    assert result.auth.alignment.spf_aligned is True
    assert result.auth.alignment.dkim_aligned is True
    assert result.auth.alignment.reply_to_mismatch is False


def test_phishing_email_fails_authentication(analyze_fixture):
    result = analyze_fixture("phishing_credential.eml")

    assert result.auth.spf.result == "fail"
    assert result.auth.dmarc.result == "fail"
    assert result.auth.dkim[0].result == "none"
    assert result.auth.verdict == "fail"


def test_forwarded_email_is_partial_not_fail(analyze_fixture):
    result = analyze_fixture("forwarded_mailing_list.eml")

    assert result.auth.spf.result == "fail"
    assert result.auth.dkim[0].result == "pass"
    assert result.auth.dmarc.result == "pass"
    assert result.auth.verdict == "partial"
    assert any("forwarding" in note for note in result.auth.notes)


def test_bec_reply_to_mismatch_is_flagged(analyze_fixture):
    result = analyze_fixture("bec_wire_transfer.eml")

    assert result.auth.verdict == "pass"
    assert result.auth.alignment.reply_to_mismatch is True
    assert result.auth.alignment.reply_to_domain == "acme-finance.com"


def test_display_name_spoof_passes_auth_but_flags_reply_to(analyze_fixture):
    result = analyze_fixture("spoofed_display_name.eml")

    assert result.auth.verdict == "pass"
    assert result.auth.alignment.reply_to_mismatch is True
    assert result.auth.alignment.from_domain == "gmail.com"


def test_missing_auth_headers_are_unknown(analyze_fixture):
    result = analyze_fixture("malformed.eml")

    assert result.auth.verdict == "unknown"
    assert result.auth.spf.result == "none"
    assert any("No SPF" in note for note in result.auth.notes)
