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


class SourceStatus(BaseModel):
    source: str
    status: str = "not_queried"
    detail: str | None = None


class IpIntel(BaseModel):
    ip: str
    scope: str = "public"
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    region: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    timezone: str | None = None
    asn: int | None = None
    isp: str | None = None
    as_org: str | None = None
    hosting: bool | None = None
    vpn: bool | None = None
    tor: bool | None = None
    cloud: bool | None = None
    abuse_score: int | None = None
    tags: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    vulns: list[str] = Field(default_factory=list)
    available: bool = False
    sources: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class DomainIntel(BaseModel):
    domain: str
    available: bool = False
    age_days: int | None = None
    created_at: str | None = None
    updated_at: str | None = None
    expires_at: str | None = None
    registrar: str | None = None
    statuses: list[str] = Field(default_factory=list)
    resolved: bool | None = None
    a_records: list[str] = Field(default_factory=list)
    mx: list[str] = Field(default_factory=list)
    ns: list[str] = Field(default_factory=list)
    spf: str | None = None
    dmarc: str | None = None
    lookalike_of: str | None = None
    distance: int | None = None
    sources: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class UrlIntel(BaseModel):
    url: str
    host: str | None = None
    scheme: str | None = None
    https: bool = False
    ip_literal: bool = False
    punycode: bool = False
    userinfo: bool = False
    shortened: bool = False
    suspicious_tld: bool = False
    lookalike_of: str | None = None
    distance: int | None = None
    suspicious: bool = False
    reputation: str = "not_checked"
    available: bool = True
    sources: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class EnrichmentReport(BaseModel):
    offline_mode: bool = False
    status: str = "not_queried"
    ip: dict[str, IpIntel] = Field(default_factory=dict)
    domain: dict[str, DomainIntel] = Field(default_factory=dict)
    url: dict[str, UrlIntel] = Field(default_factory=dict)
    sources: dict[str, SourceStatus] = Field(default_factory=dict)
    cache_hits: int = 0
    cache_misses: int = 0
    notes: list[str] = Field(default_factory=list)


class EmailMeta(BaseModel):
    subject: str = ""
    date: str | None = None
    sender: EmailAddress = Field(default_factory=EmailAddress)
    reply_to: EmailAddress | None = None
    return_path: EmailAddress | None = None
    to: list[EmailAddress] = Field(default_factory=list)
    cc: list[EmailAddress] = Field(default_factory=list)
    message_id: str | None = None
    list_id: str | None = None
    list_unsubscribe: bool = False
    headers_excerpt: str = ""
    attachments: list[AttachmentInfo] = Field(default_factory=list)
    body_excerpt: str = ""
    body_length: int = 0
    html_present: bool = False


class ScoreReport(BaseModel):
    available: bool = False
    total: int = 0
    label: str = "unscored"
    confidence: float = 0.0
    signals: dict[str, int] = Field(default_factory=dict)
    max_signals: dict[str, int] = Field(default_factory=dict)
    families_above_threshold: int = 0
    coverage: float = 0.0
    top_reasons: list[str] = Field(default_factory=list)
    version: str = "phase3-rules-v1"
    notes: list[str] = Field(default_factory=list)


class AnalysisEvidence(BaseModel):
    filename: str
    sha256: str
    size_bytes: int
    analyzed_at: datetime
    tool_version: str = "0.1.0"
    offline_mode: bool = False


class AnalysisResult(BaseModel):
    id: str
    evidence: AnalysisEvidence
    email: EmailMeta
    auth: AuthReport
    routing: RoutingReport
    enrichment: EnrichmentReport = Field(default_factory=EnrichmentReport)
    score: ScoreReport = Field(default_factory=ScoreReport)
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
