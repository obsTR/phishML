from __future__ import annotations

import re
from typing import Any

from bs4 import BeautifulSoup

URGENCY_TERMS = {
    "urgent",
    "immediately",
    "action required",
    "verify",
    "verify now",
    "account locked",
    "suspended",
    "security alert",
    "password",
    "update",
    "confirm",
    "click below",
    "limited time",
}

CREDENTIAL_TERMS = {
    "password",
    "login",
    "sign in",
    "signin",
    "credential",
    "ssn",
    "bank",
    "wire",
    "invoice",
    "payment",
    "otp",
}

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "work",
    "support",
    "click",
    "country",
    "stream",
    "zip",
    "mov",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "rebrand.ly",
    "ow.ly",
}

_EXECUTABLE_EXTS = {
    ".exe",
    ".js",
    ".vbs",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".lnk",
    ".jar",
    ".msi",
    ".apk",
    ".iso",
    ".img",
}

_URL_LIKE_TEXT_RE = re.compile(r"\bhttps?://[^\s]+\b", re.IGNORECASE)


def _count_caps_words(text: str) -> int:
    words = re.findall(r"\b[A-Z]{2,}\b", text or "")
    return len(words)


def _has_terms(text: str, terms: set[str]) -> int:
    text_lower = (text or "").lower()
    return int(any(term in text_lower for term in terms))


def _html_features(html: str) -> dict[str, Any]:
    if not html:
        return {
            "num_html_links": 0,
            "link_text_mismatch_count": 0,
            "num_forms": 0,
            "has_hidden_text": 0,
        }

    soup = BeautifulSoup(html, "html.parser")
    links = soup.find_all("a")
    forms = soup.find_all("form")
    link_text_mismatch = 0

    for a in links:
        href = a.get("href", "")
        text = (a.get_text() or "").strip()
        if _URL_LIKE_TEXT_RE.search(text) and text not in href:
            link_text_mismatch += 1

    hidden_text = 0
    for tag in soup.find_all(True):
        style = (tag.get("style") or "").lower()
        if "display:none" in style or "visibility:hidden" in style:
            hidden_text = 1
            break
        if tag.name == "input" and (tag.get("type") or "").lower() == "hidden":
            hidden_text = 1
            break

    return {
        "num_html_links": len(links),
        "link_text_mismatch_count": link_text_mismatch,
        "num_forms": len(forms),
        "has_hidden_text": hidden_text,
    }


def _attachment_features(attachments: list[dict[str, Any]]) -> dict[str, Any]:
    if not attachments:
        return {
            "num_attachments": 0,
            "has_executable_attachment": 0,
            "max_attachment_size": 0,
        }

    max_size = 0
    has_exec = 0
    for att in attachments:
        filename = (att.get("filename") or "").lower()
        for ext in _EXECUTABLE_EXTS:
            if filename.endswith(ext):
                has_exec = 1
                break
        size = int(att.get("size_bytes") or 0)
        if size > max_size:
            max_size = size

    return {
        "num_attachments": len(attachments),
        "has_executable_attachment": has_exec,
        "max_attachment_size": max_size,
    }


def extract_features(parsed: dict[str, Any]) -> dict[str, Any]:
    subject = parsed.get("subject") or ""
    body_text = parsed.get("body_text") or ""
    body_html = parsed.get("body_html") or ""

    urls = parsed.get("urls") or []
    num_urls = len(urls)
    unique_domains = {u.get("domain") for u in urls if u.get("domain")}
    num_ip_urls = sum(1 for u in urls if u.get("is_ip_url"))
    avg_url_length = int(sum(len(u.get("url") or "") for u in urls) / num_urls) if num_urls else 0
    has_at_symbol = int(any("@" in (u.get("url") or "") for u in urls))
    num_shorteners = sum(
        1 for u in urls if ((u.get("domain") or "").lower() + "." + (u.get("tld") or "").lower()) in SHORTENER_DOMAINS
    )
    num_suspicious_tlds = sum(1 for u in urls if (u.get("tld") or "").lower() in SUSPICIOUS_TLDS)

    headers = parsed.get("headers") or {}
    received = headers.get("received") or []

    from_email = (parsed.get("from_email") or "").lower()
    reply_to_email = (parsed.get("reply_to_email") or "").lower()
    return_path = (headers.get("return_path") or "").lower()

    features = {
        "subject_length": len(subject),
        "body_length": len(body_text),
        "num_exclamations": subject.count("!") + body_text.count("!"),
        "num_caps_words": _count_caps_words(subject + " " + body_text),
        "has_urgency_terms": _has_terms(subject + " " + body_text, URGENCY_TERMS),
        "has_credential_terms": _has_terms(subject + " " + body_text, CREDENTIAL_TERMS),
        "num_urls": num_urls,
        "num_unique_domains": len(unique_domains),
        "num_ip_urls": num_ip_urls,
        "num_shorteners": num_shorteners,
        "avg_url_length": avg_url_length,
        "has_at_symbol_url": has_at_symbol,
        "num_suspicious_tlds": num_suspicious_tlds,
        "received_count": len(received),
        "from_replyto_mismatch": int(bool(from_email and reply_to_email and from_email != reply_to_email)),
        "return_path_mismatch": int(bool(from_email and return_path and from_email not in return_path)),
    }

    features.update(_html_features(body_html))
    features.update(_attachment_features(parsed.get("attachments") or []))
    return features
