from datetime import datetime

from pydantic import BaseModel, Field


class EmailAddress(BaseModel):
    name: str = ""
    address: str = ""
    domain: str = ""


class AttachmentInfo(BaseModel):
    filename: str = ""
    content_type: str = "application/octet-stream"
    size_bytes: int = 0
    sha256: str = ""


class AuthResult(BaseModel):
    result: str = "none"
    domain: str | None = None
    client_ip: str | None = None
    source: str = "header"
    detail: str | None = None


class DkimResult(AuthResult):
    selector: str | None = None


class AlignmentReport(BaseModel):
    from_domain: str = ""
    return_path_domain: str | None = None
    reply_to_domain: str | None = None
    spf_aligned: bool | None = None
    dkim_aligned: bool | None = None
    reply_to_mismatch: bool = False


class AuthReport(BaseModel):
    spf: AuthResult = Field(default_factory=AuthResult)
    dkim: list[DkimResult] = Field(default_factory=list)
    dmarc: AuthResult = Field(default_factory=AuthResult)
    alignment: AlignmentReport = Field(default_factory=AlignmentReport)
    verdict: str = "unknown"
    notes: list[str] = Field(default_factory=list)


class ReceivedHop(BaseModel):
    index: int
    from_host: str | None = None
    by_host: str | None = None
    ip: str | None = None
    timestamp: str | None = None
    delay_seconds: int | None = None
    raw: str = ""


class RoutingReport(BaseModel):
    hops: list[ReceivedHop] = Field(default_factory=list)
    origin_ip: str | None = None
    origin_confidence: float = 0.0
    origin_method: str = "unavailable"
    anomalies: list[str] = Field(default_factory=list)
    public_ip_count: int = 0


class IOC(BaseModel):
    type: str
    value: str
    context: str = ""


class EmailMeta(BaseModel):
    subject: str = ""
    date: str | None = None
    sender: EmailAddress = Field(default_factory=EmailAddress)
    reply_to: EmailAddress | None = None
    return_path: EmailAddress | None = None
    to: list[EmailAddress] = Field(default_factory=list)
    cc: list[EmailAddress] = Field(default_factory=list)
    message_id: str | None = None
    headers_excerpt: str = ""
    attachments: list[AttachmentInfo] = Field(default_factory=list)
    body_excerpt: str = ""
    body_length: int = 0
    html_present: bool = False


class AnalysisEvidence(BaseModel):
    filename: str
    sha256: str
    size_bytes: int
    analyzed_at: datetime
    tool_version: str = "0.1.0"


class AnalysisResult(BaseModel):
    id: str
    evidence: AnalysisEvidence
    email: EmailMeta
    auth: AuthReport
    routing: RoutingReport
    iocs: list[IOC] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class AnalysisSummary(BaseModel):
    id: str
    filename: str
    sha256: str
    analyzed_at: datetime
    verdict: str
    hop_count: int
    ioc_count: int
    subject: str
    sender: str
    origin_ip: str | None = None
    score: int | None = None
    label: str | None = None


class BatchError(BaseModel):
    filename: str
    detail: str


class BatchAnalysisResponse(BaseModel):
    results: list[AnalysisResult] = Field(default_factory=list)
    errors: list[BatchError] = Field(default_factory=list)
