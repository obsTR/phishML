from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, asdict
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from bs4 import BeautifulSoup

_URL_RE = re.compile(r"(https?://[^\s<>\"'\]]+|www\.[^\s<>\"'\]]+)", re.IGNORECASE)
_URL_TEXT_RE = re.compile(r"\bhttps?://[^\s]+\b", re.IGNORECASE)

@dataclass
class ParsedEmail:
    message_id: str | None
    timestamp_utc: str | None
    from_name: str | None
    from_email: str | None
    reply_to_name: str | None
    reply_to_email: str | None
    to_emails: list[str]
    cc_emails: list[str]
    subject: str
    body_text: str
    body_html: str
    headers: dict[str, Any]
    urls: list[dict[str, Any]]
    attachments: list[dict[str, Any]]


def _get_first_address(header_value: str | None) -> tuple[str | None, str | None]:
    if not header_value:
        return None, None
    addrs = getaddresses([header_value])
    if not addrs:
        return None, None
    name, email = addrs[0]
    return (name or None), (email or None)


def _get_all_addresses(header_value: str | None) -> list[str]:
    if not header_value:
        return []
    addrs = getaddresses([header_value])
    emails = [email for _, email in addrs if email]
    return emails


def _extract_bodies(msg) -> tuple[str, str, list[dict[str, Any]]]:
    body_text_parts: list[str] = []
    body_html_parts: list[str] = []
    attachments: list[dict[str, Any]] = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = part.get_content_disposition()  # attachment/inline/None
            filename = part.get_filename()
            payload = part.get_payload(decode=True) or b""
            if filename or disp == "attachment":
                attachments.append(
                    {
                        "filename": filename or "",
                        "mime": ctype,
                        "size_bytes": len(payload),
                    }
                )
                continue

            if ctype == "text/plain":
                try:
                    body_text_parts.append(part.get_content())
                except Exception:
                    body_text_parts.append(payload.decode(errors="ignore"))
            elif ctype == "text/html":
                try:
                    body_html_parts.append(part.get_content())
                except Exception:
                    body_html_parts.append(payload.decode(errors="ignore"))
    else:
        ctype = msg.get_content_type()
        payload = msg.get_payload(decode=True) or b""
        if ctype == "text/plain":
            body_text_parts.append(msg.get_content())
        elif ctype == "text/html":
            body_html_parts.append(msg.get_content())
        else:
            # unknown single-part type
            body_text_parts.append(payload.decode(errors="ignore"))

    return ("\n".join(body_text_parts).strip(), "\n".join(body_html_parts).strip(), attachments)


def _normalize_url(raw: str) -> str:
    if raw.lower().startswith("www."):
        return "http://" + raw
    return raw


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def _split_domain(host: str) -> tuple[str, str]:
    parts = [p for p in host.split(".") if p]
    if len(parts) >= 2:
        return (".".join(parts[:-1]), parts[-1])
    if parts:
        return (parts[0], "")
    return ("", "")


def _extract_urls(text: str) -> list[dict[str, Any]]:
    urls: list[dict[str, Any]] = []
    for match in _URL_RE.findall(text or ""):
        url = _normalize_url(match)
        parsed = urlparse(url)
        host = parsed.hostname or ""
        domain, tld = _split_domain(host)
        urls.append(
            {
                "url": url,
                "domain": domain,
                "tld": tld,
                "path": parsed.path or "",
                "query": parsed.query or "",
                "is_ip_url": bool(host) and _is_ip(host),
            }
        )
    return urls


def parse_eml(path: str | Path) -> ParsedEmail:
    raw = Path(path).read_bytes()
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    from_name, from_email = _get_first_address(msg.get("From"))
    reply_to_name, reply_to_email = _get_first_address(msg.get("Reply-To"))
    to_emails = _get_all_addresses(msg.get("To"))
    cc_emails = _get_all_addresses(msg.get("Cc"))

    body_text, body_html, attachments = _extract_bodies(msg)
    combined_for_urls = "\n".join([body_text, body_html])
    urls = _extract_urls(combined_for_urls)

    headers = {
        "return_path": msg.get("Return-Path", ""),
        "received": msg.get_all("Received", []),
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
        "mime_version": msg.get("MIME-Version", ""),
        "content_type": msg.get("Content-Type", ""),
        "user_agent": msg.get("User-Agent", ""),
        "authentication_results": msg.get("Authentication-Results", ""),
    }

    return ParsedEmail(
        message_id=msg.get("Message-ID"),
        timestamp_utc=msg.get("Date"),
        from_name=from_name,
        from_email=from_email,
        reply_to_name=reply_to_name,
        reply_to_email=reply_to_email,
        to_emails=to_emails,
        cc_emails=cc_emails,
        subject=msg.get("Subject", ""),
        body_text=body_text,
        body_html=body_html,
        headers=headers,
        urls=urls,
        attachments=attachments,
    )


def parsed_to_dict(parsed: ParsedEmail) -> dict[str, Any]:
    return asdict(parsed)


def extract_urls_from_text(text: str) -> list[str]:
    return _URL_TEXT_RE.findall(text or "")
