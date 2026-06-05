"""Check the configured OpenAI-compatible LLM API without printing secrets."""

from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_dotenv(path: Path = ROOT / ".env") -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def endpoint() -> str:
    explicit = os.getenv("LLM_CHAT_COMPLETIONS_URL")
    if explicit:
        return explicit
    base_url = os.getenv("LLM_API_BASE_URL", "https://api.groq.com/openai/v1").rstrip("/")
    return f"{base_url}/chat/completions"


def ssl_context() -> ssl.SSLContext:
    try:
        import certifi  # type: ignore[import-not-found]

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def main() -> int:
    load_dotenv()
    key = os.getenv("GROQ_API_KEY") or os.getenv("LLM_API_KEY")
    if not key:
        print("MISSING_KEY: set GROQ_API_KEY or LLM_API_KEY in .env")
        return 2

    payload = {
        "model": os.getenv("LLM_MODEL", "llama-3.3-70b-versatile"),
        "messages": [
            {"role": "system", "content": "Reply with exactly: ok"},
            {"role": "user", "content": "health check"},
        ],
        "temperature": 0,
        "max_tokens": 8,
    }
    request = urllib.request.Request(
        endpoint(),
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "User-Agent": "ai-soc-analyst-health-check/0.1",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=30, context=ssl_context()) as response:
            body = json.loads(response.read().decode("utf-8"))
        content = body["choices"][0]["message"]["content"].strip()
        print(f"OK: authenticated completion worked with model={payload['model']} reply={content!r}")
        return 0
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        print(f"HTTP_ERROR: status={exc.code} body={body[:300]}")
        return 1
    except Exception as exc:  # noqa: BLE001 - diagnostics script should explain any failure.
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
