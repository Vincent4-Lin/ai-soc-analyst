# AI SOC Analyst

Local defensive triage MVP for logs and scanner output. It extracts IOCs, matches common SOC signals, scores risk, and optionally sends redacted context to an OpenAI-compatible LLM endpoint for a Traditional Chinese incident report.

For a Traditional Chinese project explanation, see [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md).

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
