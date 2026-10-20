import hashlib
from dataclasses import dataclass
from pathlib import Path


class IngestError(Exception):
    pass


@dataclass
class IngestedEmail:
    filename: str
    raw: bytes
    sha256: str
    size_bytes: int


def ingest(filename: str | None, data: bytes, max_bytes: int) -> IngestedEmail:
    safe_name = Path(filename or "email.eml").name
    if not safe_name:
        raise IngestError("A filename is required")

    if Path(safe_name).suffix.lower() != ".eml":
        raise IngestError("Only .eml files are supported in this phase")

    if not data or not data.strip():
        raise IngestError("The uploaded file is empty")

    if len(data) > max_bytes:
        limit_mb = max_bytes / (1024 * 1024)
        raise IngestError(f"File exceeds the {limit_mb:.0f} MB upload limit")

    return IngestedEmail(
        filename=safe_name,
        raw=data,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )
