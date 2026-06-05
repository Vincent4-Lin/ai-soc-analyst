"""Local security analysis and LLM report generation for the AI SOC Analyst app."""

from __future__ import annotations

import json
import os
import re
import ssl
import textwrap
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass
from typing import Any


MAX_LLM_INPUT_CHARS = 24_000
MAX_LOCAL_LINES = 2_000


IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "url": re.compile(r"\bhttps?://[^\s\"'<>)]+", re.IGNORECASE),
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
}


SECRET_PATTERNS = [
    re.compile(r"\bgsk_[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*['\"]?[^'\"\s]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
]


TIMESTAMP_PATTERN = re.compile(
    r"(?P<ts>\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2})?\b|"
    r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b)"
)


@dataclass(frozen=True)
class SignalRule:
    name: str
    severity: str
    category: str
    pattern: re.Pattern[str]
    recommendation: str


SIGNAL_RULES = [
    SignalRule(
        "SSH brute-force pattern",
        "high",
        "credential_access",
        re.compile(r"(?i)(failed password|authentication failure|invalid user|maximum authentication attempts)"),
        "Block repeated sources, enforce MFA, disable password SSH when possible, and review successful logins near this window.",
    ),
    SignalRule(
        "Successful authentication",
        "medium",
        "initial_access",
        re.compile(r"(?i)(accepted password|accepted publickey|login successful|session opened)"),
        "Verify whether the user, source IP, and time are expected; correlate with preceding failures.",
    ),
    SignalRule(
        "Web exploit probe",
        "high",
        "initial_access",
        re.compile(r"(?i)(\.\./|\%2e\%2e|/etc/passwd|wp-admin|phpmyadmin|jndi:ldap|select.+from|union.+select|<script|cmd=|powershell)"),
        "Confirm whether requests reached vulnerable code paths, patch exposed services, and add WAF or reverse-proxy filtering.",
    ),
    SignalRule(
        "Malware or EDR alert",
        "critical",
        "execution",
        re.compile(r"(?i)(malware|trojan|ransomware|quarantine|edr alert|cobalt strike|mimikatz|meterpreter|beacon)"),
        "Isolate affected hosts, preserve evidence, collect process/network telemetry, and run a scoped threat hunt.",
    ),
    SignalRule(
        "Privilege escalation signal",
        "high",
        "privilege_escalation",
        re.compile(r"(?i)(sudo|uac bypass|privilege escalation|permission denied.*root|admin group|se(?:takeownership|debug)privilege)"),
        "Review privilege changes and administrative command history, then rotate credentials if misuse is suspected.",
    ),
    SignalRule(
        "Outbound exfiltration hint",
        "high",
        "exfiltration",
        re.compile(r"(?i)(exfil|large upload|data transfer|dropbox|mega\.nz|pastebin|curl .*-d|scp .*@|rclone)"),
        "Check egress logs, destination reputation, data volume, and whether sensitive files were accessed before transfer.",
    ),
    SignalRule(
        "Vulnerability scanner critical finding",
        "critical",
        "vulnerability_management",
        re.compile(r"(?i)(critical|cvss\s*:? 9|cvss\s*:? 10|remote code execution|rce|unauthenticated)"),
        "Prioritize internet-facing assets, verify exploitability, and patch or mitigate before lower-severity items.",
    ),
    SignalRule(
        "Suspicious command execution",
        "high",
        "execution",
        re.compile(r"(?i)(/bin/sh -c|cmd\.exe|powershell|wget http|curl http|certutil|bitsadmin|base64 -d|chmod \+x)"),
        "Correlate command parent process, user, host, and outbound connections; preserve process artifacts.",
    ),
]


def redact_secrets(text: str) -> str:
    """Remove common secret formats before local display or LLM transmission."""
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED_SECRET]", redacted)
    return redacted


def _unique_limited(values: list[str], limit: int = 50) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        normalized = value.strip().rstrip(".,;]")
        key = normalized.lower()
        if key and key not in seen:
            seen.add(key)
            unique.append(normalized)
        if len(unique) >= limit:
            break
    return unique


def extract_iocs(text: str) -> dict[str, list[str]]:
    iocs: dict[str, list[str]] = {}
    for name, pattern in IOC_PATTERNS.items():
        iocs[name] = _unique_limited(pattern.findall(text))
    domains = []
    for url in iocs["url"]:
        match = re.search(r"https?://([^/:?#]+)", url, re.IGNORECASE)
        if match:
            domains.append(match.group(1))
    iocs["domain"] = _unique_limited(domains)
    return iocs


def _severity_weight(severity: str) -> int:
    return {
        "critical": 30,
        "high": 18,
        "medium": 8,
        "low": 3,
    }.get(severity, 1)


def _risk_label(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _extract_timestamp(line: str) -> str | None:
    match = TIMESTAMP_PATTERN.search(line)
    return match.group("ts") if match else None


def analyze_locally(raw_text: str) -> dict[str, Any]:
    text = redact_secrets(raw_text)
    lines = text.splitlines()
    scanned_lines = lines[:MAX_LOCAL_LINES]
    findings_by_rule: dict[str, dict[str, Any]] = {}
    timeline: list[dict[str, str]] = []

    for index, line in enumerate(scanned_lines, start=1):
        for rule in SIGNAL_RULES:
            if rule.pattern.search(line):
                finding = findings_by_rule.setdefault(
                    rule.name,
                    {
                        "name": rule.name,
                        "severity": rule.severity,
                        "category": rule.category,
                        "count": 0,
                        "examples": [],
                        "recommendation": rule.recommendation,
                    },
                )
                finding["count"] += 1
                if len(finding["examples"]) < 3:
                    finding["examples"].append({"line": index, "text": line[:240]})
                if len(timeline) < 30:
                    timeline.append(
                        {
                            "timestamp": _extract_timestamp(line) or f"line {index}",
                            "event": rule.name,
                            "severity": rule.severity,
                            "detail": line[:220],
                        }
                    )

    findings = sorted(
        findings_by_rule.values(),
        key=lambda item: (_severity_weight(item["severity"]), item["count"]),
        reverse=True,
    )
    iocs = extract_iocs(text)
    severity_counts = Counter(item["severity"] for item in findings)
    score = min(
        100,
        sum(_severity_weight(item["severity"]) * min(item["count"], 5) for item in findings)
        + min(len(findings) * 3, 12)
        + min(len(iocs["ipv4"]), 20)
        + min(len(iocs["cve"]) * 8, 24),
    )

    top_sources = Counter(iocs["ipv4"]).most_common(10)

    return {
        "line_count": len(lines),
        "scanned_line_count": len(scanned_lines),
        "truncated_for_local_scan": len(lines) > MAX_LOCAL_LINES,
        "risk_score": score,
        "risk_label": _risk_label(score),
        "severity_counts": dict(severity_counts),
        "findings": findings,
        "iocs": iocs,
        "top_sources": [{"value": value, "count": count} for value, count in top_sources],
        "timeline": timeline,
        "redacted_text": text,
    }


def build_local_report(analysis: dict[str, Any]) -> str:
    findings = analysis["findings"]
    iocs = analysis["iocs"]
    timeline = analysis["timeline"]

    if not findings:
        summary = "No high-confidence suspicious patterns were matched by the local rule set."
    else:
        top = findings[0]
        summary = (
            f"Local analysis rates this artifact as {analysis['risk_label'].upper()} "
            f"risk ({analysis['risk_score']}/100), led by {top['name']} "
            f"({top['count']} matches)."
        )

    finding_lines = []
    for item in findings[:8]:
        finding_lines.append(
            f"- **{item['severity'].upper()} | {item['name']}**: {item['count']} matches. "
            f"{item['recommendation']}"
        )
        for example in item["examples"][:2]:
            finding_lines.append(f"  - Line {example['line']}: `{example['text']}`")
    if not finding_lines:
        finding_lines.append("- No rule-based findings.")

    ioc_lines = []
    for ioc_type in ["ipv4", "domain", "url", "cve", "sha256", "sha1", "md5", "email"]:
        values = iocs.get(ioc_type, [])
        if values:
            ioc_lines.append(f"- **{ioc_type}**: {', '.join(values[:15])}")
    if not ioc_lines:
        ioc_lines.append("- No common IOCs detected.")

    timeline_lines = []
    for event in timeline[:10]:
        timeline_lines.append(
            f"- **{event['timestamp']}** [{event['severity']}] {event['event']}: {event['detail']}"
        )
    if not timeline_lines:
        timeline_lines.append("- No suspicious timeline events detected.")

    recommendations = [
        "Validate whether listed source IPs and users are expected for this asset.",
        "Correlate the suspicious window with authentication, EDR, DNS, proxy, and firewall logs.",
        "Preserve raw logs and avoid overwriting evidence before triage is complete.",
        "Prioritize containment first when critical malware, credential access, or exfiltration signals appear.",
    ]

    return "\n".join(
        [
            "# AI SOC Analyst Report",
            "",
            "## Executive Summary",
            summary,
            "",
            "## Key Findings",
            *finding_lines,
            "",
            "## Indicators",
            *ioc_lines,
            "",
            "## Timeline",
            *timeline_lines,
            "",
            "## Recommended Next Actions",
            *[f"- {item}" for item in recommendations],
        ]
    )


def _llm_endpoint() -> str:
    explicit = os.getenv("LLM_CHAT_COMPLETIONS_URL")
    if explicit:
        return explicit
    base_url = os.getenv("LLM_API_BASE_URL", "https://api.groq.com/openai/v1").rstrip("/")
    return f"{base_url}/chat/completions"


def _api_key() -> str | None:
    return os.getenv("LLM_API_KEY") or os.getenv("GROQ_API_KEY")


def _ssl_context() -> ssl.SSLContext:
    try:
        import certifi  # type: ignore[import-not-found]

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def build_llm_messages(raw_text: str, analysis: dict[str, Any]) -> list[dict[str, str]]:
    redacted_text = redact_secrets(raw_text)
    if len(redacted_text) > MAX_LLM_INPUT_CHARS:
        redacted_text = redacted_text[:MAX_LLM_INPUT_CHARS] + "\n[TRUNCATED_FOR_LLM]"

    local_context = {
        "risk_score": analysis["risk_score"],
        "risk_label": analysis["risk_label"],
        "severity_counts": analysis["severity_counts"],
        "findings": [
            {
                "name": item["name"],
                "severity": item["severity"],
                "category": item["category"],
                "count": item["count"],
                "examples": item["examples"][:2],
            }
            for item in analysis["findings"][:10]
        ],
        "iocs": {key: values[:20] for key, values in analysis["iocs"].items() if values},
        "timeline": analysis["timeline"][:20],
    }
    system = textwrap.dedent(
        """
        You are a defensive SOC analyst. Analyze only the user-provided logs or scanner output.
        Produce a concise incident triage report in Traditional Chinese with these sections:
        Executive Summary, Risk Rating, Evidence, Timeline, Likely MITRE ATT&CK Tactics,
        Immediate Containment, Remediation, and Follow-up Queries.
        Do not provide exploit instructions, offensive playbooks, credential theft steps, or malware code.
        Be explicit when evidence is weak or when a conclusion is only a hypothesis.
        """
    ).strip()
    user = "\n\n".join(
        [
            "Local rule-based context:",
            json.dumps(local_context, ensure_ascii=False, indent=2),
            "Raw artifact, redacted and possibly truncated:",
            redacted_text,
        ]
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def call_llm(messages: list[dict[str, str]]) -> dict[str, Any]:
    key = _api_key()
    if not key:
        return {
            "used": False,
            "error": "LLM_API_KEY or GROQ_API_KEY is not configured.",
            "content": None,
        }

    payload = {
        "model": os.getenv("LLM_MODEL", "llama-3.3-70b-versatile"),
        "messages": messages,
        "temperature": float(os.getenv("LLM_TEMPERATURE", "0.2")),
        "max_tokens": int(os.getenv("LLM_MAX_TOKENS", "1800")),
    }
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        _llm_endpoint(),
        data=data,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "User-Agent": "ai-soc-analyst/0.1",
        },
        method="POST",
    )

    started = time.time()
    try:
        with urllib.request.urlopen(request, timeout=45, context=_ssl_context()) as response:
            response_data = json.loads(response.read().decode("utf-8"))
        content = response_data["choices"][0]["message"]["content"]
        return {
            "used": True,
            "error": None,
            "latency_ms": round((time.time() - started) * 1000),
            "model": payload["model"],
            "content": content,
        }
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {
            "used": False,
            "error": f"LLM HTTP {exc.code}: {body[:500]}",
            "content": None,
        }
    except (urllib.error.URLError, TimeoutError, KeyError, json.JSONDecodeError) as exc:
        return {
            "used": False,
            "error": f"LLM request failed: {exc}",
            "content": None,
        }


def analyze_with_report(raw_text: str, use_llm: bool = True) -> dict[str, Any]:
    analysis = analyze_locally(raw_text)
    local_report = build_local_report(analysis)
    llm_result = {"used": False, "error": None, "content": None}

    if use_llm:
        messages = build_llm_messages(raw_text, analysis)
        llm_result = call_llm(messages)

    report = llm_result["content"] if llm_result.get("content") else local_report
    response_analysis = dict(analysis)
    response_analysis.pop("redacted_text", None)

    return {
        "analysis": response_analysis,
        "report": report,
        "local_report": local_report,
        "llm": llm_result,
    }
