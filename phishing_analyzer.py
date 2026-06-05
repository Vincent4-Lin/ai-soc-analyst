"""Phishing email triage with local evidence extraction and optional LLM review."""

from __future__ import annotations

import html
import ipaddress
import json
import re
import textwrap
from dataclasses import dataclass
from email import policy
from email.message import EmailMessage, Message
from email.parser import Parser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlparse

from soc_analyzer import MAX_LLM_INPUT_CHARS, call_llm, extract_iocs, redact_secrets


URL_PATTERN = re.compile(r"\bhttps?://[^\s\"'<>)]+", re.IGNORECASE)
DOMAIN_IN_TEXT_PATTERN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
PORT_PATTERN = re.compile(r"\b(?:port|dport|dst_port|spt|src_port)\s*[:= ]\s*(\d{1,5})\b", re.IGNORECASE)
RISKY_ATTACHMENT_EXTENSIONS = {
    ".exe",
    ".scr",
    ".js",
    ".vbs",
    ".ps1",
    ".bat",
    ".cmd",
    ".hta",
    ".iso",
    ".img",
    ".lnk",
    ".docm",
    ".xlsm",
    ".zip",
    ".rar",
    ".7z",
}
SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "ow.ly",
    "rebrand.ly",
    "buff.ly",
    "s.id",
}
URGENT_WORDS = [
    "urgent",
    "immediate",
    "within 24 hours",
    "final notice",
    "suspend",
    "locked",
    "expire",
    "verify",
    "password",
    "login",
    "sign in",
    "payment",
    "invoice",
    "wire transfer",
    "mfa",
    "otp",
    "緊急",
    "立即",
    "停用",
    "鎖定",
    "到期",
    "驗證",
    "密碼",
    "登入",
    "付款",
    "匯款",
    "發票",
    "一次性密碼",
]
CREDENTIAL_WORDS = [
    "password",
    "credential",
    "sign in",
    "login",
    "verify account",
    "reset",
    "mfa",
    "otp",
    "密碼",
    "登入",
    "驗證帳號",
    "重設",
    "一次性密碼",
]
NETWORK_PRECHECK_CATEGORIES = {"url_analysis", "network_indicator"}
NETWORK_PRECHECK_FINDINGS = {"Credential request over plain HTTP"}


@dataclass
class FindingBuilder:
    findings: list[dict[str, Any]]

    def add(self, name: str, severity: str, category: str, evidence: str, recommendation: str) -> None:
        for item in self.findings:
            if item["name"] == name:
                item["count"] += 1
                if len(item["examples"]) < 3:
                    item["examples"].append({"line": "email", "text": evidence[:240]})
                return
        self.findings.append(
            {
                "name": name,
                "severity": severity,
                "category": category,
                "count": 1,
                "examples": [{"line": "email", "text": evidence[:240]}],
                "recommendation": recommendation,
            }
        )


class AnchorExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.anchors: list[dict[str, str]] = []
        self._active_href: str | None = None
        self._active_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        attributes = dict(attrs)
        href = attributes.get("href")
        if href:
            self._active_href = html.unescape(href)
            self._active_text = []

    def handle_data(self, data: str) -> None:
        if self._active_href:
            self._active_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._active_href:
            self.anchors.append({"href": self._active_href, "text": " ".join(self._active_text).strip()})
            self._active_href = None
            self._active_text = []


class TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)

    def text(self) -> str:
        return " ".join(part.strip() for part in self.parts if part.strip())


def _risk_label(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _severity_weight(severity: str) -> int:
    return {"critical": 32, "high": 20, "medium": 10, "low": 4}.get(severity, 1)


def _parse_email(raw_text: str) -> EmailMessage | Message:
    return Parser(policy=policy.default).parsestr(raw_text)


def _header_values(message: EmailMessage | Message, name: str) -> list[str]:
    return [str(value) for value in message.get_all(name, [])]


def _first_header(message: EmailMessage | Message, name: str) -> str:
    values = _header_values(message, name)
    return values[0] if values else ""


def _email_domain(value: str) -> str:
    address = parseaddr(value)[1]
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].lower().strip(">")


def _root_domain(domain: str) -> str:
    cleaned = domain.lower().strip(".")
    labels = [part for part in cleaned.split(".") if part]
    if len(labels) < 2:
        return cleaned
    return ".".join(labels[-2:])


def _host_from_url(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _url_port(url: str) -> int | None:
    try:
        return urlparse(url).port
    except ValueError:
        return None


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _ip_safety(ip: str) -> str:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_private:
        return "private"
    if parsed.is_multicast:
        return "multicast"
    if parsed.is_reserved:
        return "reserved"
    if parsed.is_global:
        return "public"
    return "special-use"


def _build_network_precheck(
    findings: list[dict[str, Any]],
    iocs: dict[str, list[str]],
    ip_classification: list[dict[str, str]],
) -> dict[str, Any]:
    network_findings = [
        finding
        for finding in findings
        if finding["category"] in NETWORK_PRECHECK_CATEGORIES or finding["name"] in NETWORK_PRECHECK_FINDINGS
    ]
    suspicious_reasons = [
        finding
        for finding in network_findings
        if finding["severity"] in {"critical", "high", "medium"}
        and finding["name"] != "Public IP observed in email path or URL"
    ]
    suspicious = bool(suspicious_reasons)

    return {
        "suspicious": suspicious,
        "verdict": "suspicious" if suspicious else "no_obvious_network_suspicion",
        "summary": (
            "IP / port / URL precheck found suspicious indicators before LLM review."
            if suspicious
            else "IP / port / URL precheck did not find a strong suspicious indicator; LLM review still ran."
        ),
        "reasons": suspicious_reasons,
        "observed": {
            "urls": iocs.get("url", []),
            "ports": iocs.get("port", []),
            "domains": iocs.get("domain", []),
            "ips": ip_classification,
        },
    }


def _extract_message_text(message: EmailMessage | Message) -> tuple[str, str, list[str]]:
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[str] = []

    def read_part(part: EmailMessage | Message) -> str:
        try:
            content = part.get_content()
            return content if isinstance(content, str) else str(content)
        except Exception:
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                return payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            return str(part.get_payload())

    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        filename = part.get_filename()
        if filename:
            attachments.append(filename)
        content_disposition = str(part.get_content_disposition() or "").lower()
        content_type = part.get_content_type().lower()
        if content_disposition == "attachment":
            continue
        if content_type == "text/plain":
            text_parts.append(read_part(part))
        elif content_type == "text/html":
            html_content = read_part(part)
            html_parts.append(html_content)
            extractor = TextExtractor()
            extractor.feed(html_content)
            text_parts.append(extractor.text())

    return "\n".join(text_parts), "\n".join(html_parts), attachments


def _extract_urls(text: str, html_text: str) -> tuple[list[str], list[dict[str, str]]]:
    urls = URL_PATTERN.findall(text + "\n" + html_text)
    extractor = AnchorExtractor()
    extractor.feed(html_text)
    for anchor in extractor.anchors:
        if anchor["href"].lower().startswith(("http://", "https://")):
            urls.append(anchor["href"])

    unique_urls: list[str] = []
    seen: set[str] = set()
    for url in urls:
        cleaned = html.unescape(url).rstrip(".,;]")
        if cleaned not in seen:
            seen.add(cleaned)
            unique_urls.append(cleaned)
    return unique_urls, extractor.anchors


def analyze_email_locally(raw_text: str) -> dict[str, Any]:
    redacted = redact_secrets(raw_text)
    message = _parse_email(redacted)
    body_text, html_text, attachments = _extract_message_text(message)
    urls, anchors = _extract_urls(body_text, html_text)
    headers_text = "\n".join(f"{key}: {value}" for key, value in message.items())
    combined_text = "\n".join([headers_text, body_text, html_text])
    iocs = extract_iocs(combined_text)
    finding_builder = FindingBuilder([])
    auth_results = " ".join(_header_values(message, "Authentication-Results") + _header_values(message, "ARC-Authentication-Results"))

    from_header = _first_header(message, "From")
    reply_to_header = _first_header(message, "Reply-To")
    return_path_header = _first_header(message, "Return-Path")
    from_domain = _email_domain(from_header)
    reply_to_domain = _email_domain(reply_to_header)
    return_path_domain = _email_domain(return_path_header)

    if not auth_results:
        finding_builder.add(
            "Missing authentication results",
            "low",
            "email_authentication",
            "No Authentication-Results header was present.",
            "Check the mail gateway result for SPF, DKIM, and DMARC before trusting the sender.",
        )
    else:
        lower_auth = auth_results.lower()
        for mechanism in ["spf", "dkim", "dmarc"]:
            if f"{mechanism}=fail" in lower_auth:
                finding_builder.add(
                    f"{mechanism.upper()} failed",
                    "high",
                    "email_authentication",
                    auth_results,
                    "Treat sender identity as suspicious and inspect mail gateway telemetry for similar messages.",
                )
            elif f"{mechanism}=softfail" in lower_auth or f"{mechanism}=none" in lower_auth:
                finding_builder.add(
                    f"{mechanism.upper()} weak or missing",
                    "medium",
                    "email_authentication",
                    auth_results,
                    "Verify whether this sender is authorized before users interact with links or attachments.",
                )

    if from_domain and reply_to_domain and _root_domain(from_domain) != _root_domain(reply_to_domain):
        finding_builder.add(
            "From and Reply-To domain mismatch",
            "high",
            "sender_identity",
            f"From={from_header}; Reply-To={reply_to_header}",
            "Confirm whether replies are expected to leave the sender domain; block or quarantine when unexpected.",
        )

    if from_domain and return_path_domain and _root_domain(from_domain) != _root_domain(return_path_domain):
        finding_builder.add(
            "From and Return-Path domain mismatch",
            "medium",
            "sender_identity",
            f"From={from_header}; Return-Path={return_path_header}",
            "Compare envelope sender with the visible sender and mail gateway authentication result.",
        )

    subject = _first_header(message, "Subject")
    language_source = f"{subject}\n{body_text}".lower()
    urgent_hits = [word for word in URGENT_WORDS if word in language_source]
    credential_hits = [word for word in CREDENTIAL_WORDS if word in language_source]
    if urgent_hits:
        finding_builder.add(
            "Urgent or pressure-based language",
            "medium",
            "social_engineering",
            ", ".join(urgent_hits[:8]),
            "Treat urgency as a social-engineering indicator and verify through an independent channel.",
        )
    if credential_hits:
        finding_builder.add(
            "Credential or account verification request",
            "high",
            "credential_harvesting",
            ", ".join(credential_hits[:8]),
            "Do not enter credentials from email links; inspect the target URL and report the message.",
        )

    for filename in attachments:
        lower_name = filename.lower()
        if any(lower_name.endswith(ext) for ext in RISKY_ATTACHMENT_EXTENSIONS):
            finding_builder.add(
                "Risky attachment type",
                "high",
                "payload_delivery",
                filename,
                "Detonate only in a controlled sandbox and search for similar attachments across mailboxes.",
            )

    url_ports: list[str] = []
    url_hosts: list[str] = []
    for url in urls:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host:
            continue
        url_hosts.append(host)
        if _is_ip_literal(host):
            finding_builder.add(
                "URL uses IP address instead of domain",
                "high",
                "url_analysis",
                url,
                "IP-literal login links are suspicious; block or detonate the URL before user access.",
            )
        if host in SHORTENER_DOMAINS:
            finding_builder.add(
                "URL shortener detected",
                "medium",
                "url_analysis",
                url,
                "Expand shortened links in a safe environment and compare the destination to the claimed sender.",
            )
        if "xn--" in host:
            finding_builder.add(
                "Punycode domain detected",
                "high",
                "url_analysis",
                url,
                "Decode and inspect the domain for homograph or typosquatting abuse.",
            )
        port = _url_port(url)
        if port:
            url_ports.append(f"{host}:{port}")
            standard = (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443)
            if not standard:
                finding_builder.add(
                    "Non-standard URL port",
                    "medium",
                    "network_indicator",
                    url,
                    "Non-standard ports are not automatically malicious, but should be checked against known business services.",
                )
        if parsed.scheme == "http" and credential_hits:
            finding_builder.add(
                "Credential request over plain HTTP",
                "high",
                "credential_harvesting",
                url,
                "Do not submit credentials; block the URL and check whether any user visited it.",
            )

    for anchor in anchors:
        href = anchor.get("href", "")
        text = anchor.get("text", "")
        href_host = _host_from_url(href)
        text_domains = DOMAIN_IN_TEXT_PATTERN.findall(text)
        for text_domain in text_domains:
            if href_host and _root_domain(text_domain) != _root_domain(href_host):
                finding_builder.add(
                    "Displayed link text does not match destination",
                    "high",
                    "url_analysis",
                    f"text={text}; href={href}",
                    "Warn users not to trust displayed link text; inspect the real href destination.",
                )
                break

    received_text = "\n".join(_header_values(message, "Received"))
    received_ips = extract_iocs(received_text).get("ipv4", [])
    ip_classification = [{"ip": ip, "classification": _ip_safety(ip)} for ip in received_ips + iocs.get("ipv4", [])]
    unique_ip_classification = []
    seen_ips: set[str] = set()
    for item in ip_classification:
        if item["ip"] not in seen_ips:
            seen_ips.add(item["ip"])
            unique_ip_classification.append(item)
    for item in unique_ip_classification:
        if item["classification"] == "public":
            finding_builder.add(
                "Public IP observed in email path or URL",
                "low",
                "network_indicator",
                f"{item['ip']} is public",
                "Public IPs require reputation or mail-gateway context; this local check does not prove maliciousness.",
            )

    explicit_ports = []
    for value in PORT_PATTERN.findall(headers_text + "\n" + body_text):
        port_number = int(value)
        if 0 < port_number <= 65535:
            explicit_ports.append(str(port_number))
    iocs["url"] = urls[:50]
    iocs["domain"] = sorted(set(iocs.get("domain", []) + url_hosts + [item for item in [from_domain, reply_to_domain, return_path_domain] if item]))[:50]
    iocs["port"] = sorted(set(url_ports + explicit_ports))[:50]
    iocs["attachment"] = attachments[:50]

    findings = sorted(
        finding_builder.findings,
        key=lambda item: (_severity_weight(item["severity"]), item["count"]),
        reverse=True,
    )
    network_precheck = _build_network_precheck(findings, iocs, unique_ip_classification)
    score = min(
        100,
        sum(_severity_weight(item["severity"]) * min(item["count"], 3) for item in findings)
        + min(len(urls) * 3, 18)
        + min(len(attachments) * 3, 12),
    )
    timeline = [
        {
            "timestamp": "email header",
            "event": "Sender identity parsed",
            "severity": "low",
            "detail": f"From={from_header}; Reply-To={reply_to_header or 'none'}; Return-Path={return_path_header or 'none'}",
        },
        {
            "timestamp": "email body",
            "event": "URLs extracted",
            "severity": "medium" if urls else "low",
            "detail": f"{len(urls)} URLs, {len(iocs['port'])} explicit ports, {len(attachments)} attachments",
        },
    ]

    return {
        "line_count": len(redacted.splitlines()),
        "scanned_line_count": len(redacted.splitlines()),
        "truncated_for_local_scan": False,
        "risk_score": score,
        "risk_label": _risk_label(score),
        "severity_counts": {severity: sum(1 for item in findings if item["severity"] == severity) for severity in ["critical", "high", "medium", "low"]},
        "findings": findings,
        "iocs": iocs,
        "top_sources": unique_ip_classification,
        "network_precheck": network_precheck,
        "timeline": timeline,
        "email": {
            "from": from_header,
            "reply_to": reply_to_header,
            "return_path": return_path_header,
            "subject": subject,
            "authentication_results": auth_results,
            "attachments": attachments,
            "urls": urls,
            "ip_classification": unique_ip_classification,
        },
        "redacted_text": redacted,
    }


def build_network_precheck_report(analysis: dict[str, Any]) -> str:
    precheck = analysis["network_precheck"]
    observed = precheck["observed"]
    verdict = "可疑" if precheck["suspicious"] else "未發現明顯可疑"

    reason_lines = []
    for reason in precheck["reasons"][:8]:
        evidence = reason["examples"][0]["text"] if reason.get("examples") else reason["name"]
        reason_lines.append(f"- **{reason['severity'].upper()} | {reason['name']}**: `{evidence}`")
    if not reason_lines:
        reason_lines.append("- IP / port / URL 本地檢查沒有發現強可疑指標。")

    observed_lines = [
        f"- **URLs**: {len(observed['urls'])}",
        f"- **Ports**: {', '.join(observed['ports'][:12]) if observed['ports'] else 'none'}",
        f"- **Domains**: {', '.join(observed['domains'][:12]) if observed['domains'] else 'none'}",
        "- **IPs**: "
        + (
            ", ".join(f"{item['ip']} ({item['classification']})" for item in observed["ips"][:12])
            if observed["ips"]
            else "none"
        ),
    ]

    return "\n".join(
        [
            "# 第一階段：IP / Port / URL Precheck",
            "",
            f"**判定：{verdict}**",
            "",
            precheck["summary"],
            "",
            "## 本地理由",
            *reason_lines,
            "",
            "## 檢查到的網路指標",
            *observed_lines,
        ]
    )


def build_local_email_report(analysis: dict[str, Any]) -> str:
    email_meta = analysis["email"]
    findings = analysis["findings"]
    iocs = analysis["iocs"]
    top = findings[0]["name"] if findings else "no high-confidence phishing indicator"
    summary = (
        f"Local email analysis rates this message as {analysis['risk_label'].upper()} "
        f"risk ({analysis['risk_score']}/100), led by {top}."
    )

    finding_lines = []
    for finding in findings[:10]:
        finding_lines.append(
            f"- **{finding['severity'].upper()} | {finding['name']}**: "
            f"{finding['recommendation']}"
        )
        for example in finding["examples"][:2]:
            finding_lines.append(f"  - Evidence: `{example['text']}`")
    if not finding_lines:
        finding_lines.append("- No strong phishing indicators were found by local checks.")

    indicator_lines = []
    for key in ["ipv4", "domain", "url", "port", "attachment", "email"]:
        values = iocs.get(key, [])
        if values:
            indicator_lines.append(f"- **{key}**: {', '.join(values[:12])}")
    if not indicator_lines:
        indicator_lines.append("- No common indicators extracted.")

    ip_lines = []
    for item in email_meta["ip_classification"][:12]:
        ip_lines.append(f"- **{item['ip']}**: {item['classification']}")
    if not ip_lines:
        ip_lines.append("- No IP addresses found in Received headers or URLs.")

    return "\n".join(
        [
            build_network_precheck_report(analysis),
            "",
            "---",
            "",
            "# Phishing Email Triage Report",
            "",
            "## Executive Summary",
            summary,
            "",
            "## Email Metadata",
            f"- **From**: {email_meta['from'] or 'unknown'}",
            f"- **Reply-To**: {email_meta['reply_to'] or 'none'}",
            f"- **Return-Path**: {email_meta['return_path'] or 'none'}",
            f"- **Subject**: {email_meta['subject'] or 'none'}",
            "",
            "## Key Findings",
            *finding_lines,
            "",
            "## Indicators",
            *indicator_lines,
            "",
            "## IP And Port Notes",
            *ip_lines,
            "",
            "## Recommended Actions",
            "- Do not click links or open attachments until the sender and destination are verified.",
            "- Search the mail gateway for the same sender, subject, URLs, and attachment names.",
            "- Check proxy, DNS, and EDR telemetry for users who visited listed URLs.",
            "- If authentication failed or link mismatch exists, quarantine similar emails and notify affected users.",
        ]
    )


def build_email_llm_messages(raw_text: str, analysis: dict[str, Any]) -> list[dict[str, str]]:
    redacted_text = redact_secrets(raw_text)
    if len(redacted_text) > MAX_LLM_INPUT_CHARS:
        redacted_text = redacted_text[:MAX_LLM_INPUT_CHARS] + "\n[TRUNCATED_FOR_LLM]"

    local_context = {
        "risk_score": analysis["risk_score"],
        "risk_label": analysis["risk_label"],
        "network_precheck": analysis["network_precheck"],
        "findings": [
            {
                "name": item["name"],
                "severity": item["severity"],
                "category": item["category"],
                "count": item["count"],
                "examples": item["examples"][:2],
            }
            for item in analysis["findings"][:12]
        ],
        "iocs": {key: values[:20] for key, values in analysis["iocs"].items() if values},
        "email": analysis["email"],
    }
    system = textwrap.dedent(
        """
        You are a defensive phishing email analyst. Analyze only the provided email and local evidence.
        The application already performed an IP / port / URL precheck and will display it before your answer.
        You must still consider that precheck, then decide whether the email content is phishing, benign, or inconclusive.
        Write the report in Traditional Chinese. Use exactly these Markdown headings:
        ## 判定
        ## 信心
        ## 可疑或正常的理由
        ## Header 與寄件驗證證據
        ## URL、IP、Port 證據
        ## 使用者影響
        ## SOC 建議處置
        ## 給一般使用者的說明
        Distinguish evidence from hypothesis. Do not claim an IP, domain, or port is malicious unless the evidence supports it.
        Do not write phishing templates, evasion advice, malware code, or offensive instructions.
        """
    ).strip()
    user = "\n\n".join(
        [
            "Local rule-based email evidence:",
            json.dumps(local_context, ensure_ascii=False, indent=2),
            "Raw email, redacted and possibly truncated:",
            redacted_text,
        ]
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def analyze_email_with_report(raw_text: str, use_llm: bool = True) -> dict[str, Any]:
    analysis = analyze_email_locally(raw_text)
    local_report = build_local_email_report(analysis)
    llm_result = {"used": False, "error": None, "content": None}

    if use_llm:
        llm_result = call_llm(build_email_llm_messages(raw_text, analysis))

    if llm_result.get("content"):
        report = "\n\n---\n\n".join(
            [
                build_network_precheck_report(analysis),
                "# 第二階段：LLM Email 內容分析\n\n" + llm_result["content"],
            ]
        )
    else:
        report = local_report
    response_analysis = dict(analysis)
    response_analysis.pop("redacted_text", None)

    return {
        "analysis": response_analysis,
        "report": report,
        "local_report": local_report,
        "llm": llm_result,
        "mode": "email",
    }
