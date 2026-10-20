from app.services.header_parser import build_email_meta, parse_message
from app.services.ingest import ingest


def test_parses_legitimate_email(load_fixture):
    ingested = ingest("legit_business.eml", load_fixture("legit_business.eml"), 1024 * 1024)
    parsed = parse_message(ingested)
    meta = build_email_meta(parsed)

    assert meta.sender.name == "Priya Menon"
    assert meta.sender.address == "priya.menon@acme-corp.com"
    assert meta.sender.domain == "acme-corp.com"
    assert meta.subject == "Quarterly vendor review meeting"
    assert len(meta.to) == 1
    assert meta.to[0].address == "arjun.rao@recipient.org"
    assert "vendor review" in meta.body_excerpt
    assert meta.html_present is False
    assert len(parsed.received_headers) == 2
    assert "Received:" in meta.headers_excerpt


def test_parses_html_only_body(load_fixture):
    ingested = ingest(
        "phishing_credential.eml", load_fixture("phishing_credential.eml"), 1024 * 1024
    )
    meta = build_email_meta(parse_message(ingested))

    assert meta.sender.name == "Microsoft Security"
    assert meta.sender.domain == "micros0ft-verify.com"
    assert meta.html_present is True
    assert "unusual sign-in activity" in meta.body_excerpt
    assert "<html>" not in meta.body_excerpt


def test_parses_attachment(load_fixture):
    ingested = ingest(
        "bec_wire_transfer.eml", load_fixture("bec_wire_transfer.eml"), 1024 * 1024
    )
    meta = build_email_meta(parse_message(ingested))

    assert len(meta.attachments) == 1
    attachment = meta.attachments[0]
    assert attachment.filename == "invoice_october.pdf"
    assert attachment.content_type == "application/pdf"
    assert len(attachment.sha256) == 64
    assert attachment.size_bytes > 0


def test_missing_headers_are_reported(load_fixture):
    ingested = ingest("malformed.eml", load_fixture("malformed.eml"), 1024 * 1024)
    parsed = parse_message(ingested)
    meta = build_email_meta(parsed)

    assert meta.sender.address == ""
    assert meta.message_id is None
    assert any("From" in warning for warning in parsed.warnings)
    assert any("Date" in warning for warning in parsed.warnings)
