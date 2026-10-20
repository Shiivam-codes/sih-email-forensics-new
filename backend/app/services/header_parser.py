import email
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from email import policy
from email.message import EmailMessage
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser

from app.schemas import AttachmentInfo, EmailAddress, EmailMeta
from app.services.ingest import IngestedEmail

_BLOCK_TAGS = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "table"}
_MAX_EXCERPT = 2500
_MAX_HEADER_CHARS = 14000


@dataclass
class ParsedEmail:
    ingested: IngestedEmail
    message: EmailMessage
    received_headers: list[str] = field(default_factory=list)
    body_text: str = ""
    body_html: str = ""
    attachments: list[AttachmentInfo] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style"}:
            self._skip_depth += 1
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self._skip_depth:
            self._skip_depth -= 1
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self.parts.append(data)

    def text(self) -> str:
        raw = "".join(self.parts)
        raw = re.sub(r"[ \t]+", " ", raw)
        raw = re.sub(r"\n\s*\n+", "\n\n", raw)
        return raw.strip()


def html_to_text(value: str) -> str:
    parser = _TextExtractor()
    try:
        parser.feed(value)
    except Exception:
        return re.sub(r"<[^>]+>", " ", value)
    return parser.text()


def parse_address(value: str | None) -> EmailAddress:
    if not value:
        return EmailAddress()
    pairs = getaddresses([value])
    name, address = pairs[0] if pairs else ("", "")
    name = " ".join(name.split())
    address = address.strip().lower()
    domain = address.rsplit("@", 1)[-1] if "@" in address else ""
    return EmailAddress(name=name, address=address, domain=domain)


def parse_address_list(values: list[str]) -> list[EmailAddress]:
    parsed = []
    for name, address in getaddresses(values):
        address = address.strip().lower()
        if not address:
            continue
        parsed.append(
            EmailAddress(
                name=" ".join(name.split()),
                address=address,
                domain=address.rsplit("@", 1)[-1] if "@" in address else "",
            )
        )
    return parsed


def _decode_part(part: email.message.Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        value = part.get_payload()
        return value if isinstance(value, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _extract_bodies(message: EmailMessage) -> tuple[str, str]:
    texts: list[str] = []
    htmls: list[str] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        disposition = (part.get("Content-Disposition") or "").lower()
        if "attachment" in disposition:
            continue
        content_type = part.get_content_type()
        if content_type == "text/plain":
            texts.append(_decode_part(part))
        elif content_type == "text/html":
            htmls.append(_decode_part(part))
    return "\n\n".join(text.strip() for text in texts if text.strip()), "\n\n".join(
        html.strip() for html in htmls if html.strip()
    )


def _extract_attachments(message: EmailMessage) -> list[AttachmentInfo]:
    attachments: list[AttachmentInfo] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = (part.get("Content-Disposition") or "").lower()
        if not filename and "attachment" not in disposition:
            continue
        payload = part.get_payload(decode=True) or b""
        attachments.append(
            AttachmentInfo(
                filename=filename or "unnamed",
                content_type=part.get_content_type(),
                size_bytes=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        )
    return attachments


def _parse_date(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value.strip())
    except (TypeError, ValueError):
        return None
    if parsed is None:
        return None
    return parsed.isoformat()


def _headers_excerpt(message: EmailMessage) -> str:
    lines: list[str] = []
    for key, value in message.items():
        lines.append(f"{key}: {value}")
        if sum(len(line) + 1 for line in lines) > _MAX_HEADER_CHARS:
            lines.append("... truncated ...")
            break
    return "\n".join(lines)


def parse_message(ingested: IngestedEmail) -> ParsedEmail:
    message = email.message_from_bytes(ingested.raw, policy=policy.default)
    assert isinstance(message, EmailMessage)

    warnings: list[str] = []
    if message.defects:
        warnings.extend(f"Parser defect: {defect}" for defect in message.defects)

    sender = parse_address(str(message.get("From", "")) or None)
    date_raw = str(message.get("Date", "")) or None
    message_id = str(message.get("Message-ID", "")).strip() or None

    body_plain, body_html = _extract_bodies(message)
    body_text = body_plain or html_to_text(body_html)
    attachments = _extract_attachments(message)

    if not sender.address:
        warnings.append("Missing or unparseable From header")
    if not date_raw:
        warnings.append("Missing Date header")
    if not message_id:
        warnings.append("Missing Message-ID header")

    return ParsedEmail(
        ingested=ingested,
        message=message,
        received_headers=[str(value) for value in message.get_all("Received", [])],
        body_text=body_text,
        body_html=body_html,
        attachments=attachments,
        warnings=warnings,
    )


def build_email_meta(parsed: ParsedEmail) -> EmailMeta:
    message = parsed.message
    subject = " ".join(str(message.get("Subject", "")).split())
    reply_to = parse_address(str(message.get("Reply-To", "")) or None)
    return_path = parse_address(str(message.get("Return-Path", "")) or None)
    return EmailMeta(
        subject=subject,
        date=_parse_date(str(message.get("Date", "")) or None),
        sender=parse_address(str(message.get("From", "")) or None),
        reply_to=reply_to if reply_to.address else None,
        return_path=return_path if return_path.address else None,
        to=parse_address_list(message.get_all("To", [])),
        cc=parse_address_list(message.get_all("Cc", [])),
        message_id=str(message.get("Message-ID", "")).strip() or None,
        headers_excerpt=_headers_excerpt(message),
        attachments=parsed.attachments,
        body_excerpt=parsed.body_text[:_MAX_EXCERPT],
        body_length=len(parsed.body_text),
        html_present=bool(parsed.body_html),
    )


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
