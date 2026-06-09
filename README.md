# AI SOC Analyst

Local defensive SOC triage MVP for logs, scanner output, and phishing email artifacts. It extracts IOCs, matches common SOC signals, scores risk, and optionally sends redacted context to an OpenAI-compatible LLM endpoint for a Traditional Chinese incident report.

This is the main integration project in my cybersecurity portfolio. It combines ideas from earlier focused projects such as phishing email analysis, suspicious login analysis, network log analysis, and threat intelligence writing into one SOC-style workflow.

For a Traditional Chinese project explanation, see [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md).

## Portfolio Position

This repository is intended to be the primary project for showing my current research and engineering direction:

```text
AI-assisted cybersecurity investigation and network security incident triage.
```

The goal is not to replace a human analyst with an LLM. The goal is to help an analyst structure messy security artifacts into a reviewable triage report while keeping the detection logic explainable and the workflow defensive.

## How It Relates To My Other Projects

- `Phishing-Email-Analysis` is an earlier rule-based phishing baseline. This project extends that idea with raw `.eml` parsing and SOC-style reporting.
- `suspicious-login-analyzer` focuses deeply on login events. This project uses similar triage ideas in a broader SOC workflow.
- `network-log-analysis` is an earlier network log analysis project. This project generalizes the workflow to multiple artifact types.
- `threat-intelligence-briefs` supports the writing and ATT&CK mapping side of incident reporting.
- `ai-assisted-security-incident-triage` is an earlier prototype for structured LLM-assisted triage. This repository is the more complete application direction.

## Setup

Rotate any API key that was pasted into chat or committed to GitHub before using it here.

```bash
cp .env.example .env
```

Edit `.env` and set `GROQ_API_KEY` or `LLM_API_KEY`.

```bash
python3 app.py
```

Open:

```text
http://127.0.0.1:8787
```

To verify the authenticated LLM call:

```bash
python3 scripts/check_llm_api.py
```

## What It Does

- Parses SSH, web, EDR-style, and vulnerability scanner text.
- Parses raw `.eml` phishing emails in Email mode.
- Extracts IPv4 addresses, URLs, domains, emails, CVEs, and hashes.
- Detects brute-force activity, suspicious web probes, malware alerts, privilege escalation hints, exfiltration hints, and critical scanner findings.
- Detects phishing indicators such as SPF/DKIM/DMARC failures, From/Reply-To mismatch, link text mismatch, IP-literal URLs, non-standard URL ports, risky attachment extensions, and urgent credential requests.
- Redacts common secret patterns before LLM transmission.
- Falls back to a local Markdown report when no API key is configured or the LLM call fails.

## Notes

This project is for defensive analysis of artifacts you are authorized to inspect. It does not scan targets or run exploit code.
