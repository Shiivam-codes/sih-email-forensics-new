from datetime import UTC, datetime
from uuid import uuid4

from app import __version__
from app.schemas import AnalysisEvidence, AnalysisResult
from app.services.auth import build_auth_report
from app.services.header_parser import build_email_meta, parse_message
from app.services.ingest import IngestedEmail, ingest
from app.services.ioc_extractor import extract_iocs
from app.services.origin import resolve_origin


def analyze_email(data: bytes, filename: str | None, max_upload_bytes: int) -> AnalysisResult:
    ingested: IngestedEmail = ingest(filename, data, max_upload_bytes)
    parsed = parse_message(ingested)
    auth = build_auth_report(parsed)
    routing = resolve_origin(parsed, auth)
    email = build_email_meta(parsed)
    iocs = extract_iocs(parsed)

    warnings = list(parsed.warnings)
    if routing.origin_ip is None:
        warnings.append("Probable origin could not be determined from the available headers")
    if auth.verdict == "unknown":
        warnings.append("Sender authentication could not be established from the headers")

    return AnalysisResult(
        id=str(uuid4()),
        evidence=AnalysisEvidence(
            filename=ingested.filename,
            sha256=ingested.sha256,
            size_bytes=ingested.size_bytes,
            analyzed_at=datetime.now(UTC),
            tool_version=__version__,
        ),
        email=email,
        auth=auth,
        routing=routing,
        iocs=iocs,
        warnings=warnings,
    )
