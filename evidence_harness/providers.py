"""Model providers.

Every provider returns the RAW request bytes as sent and the RAW response
bytes as received, plus what the API says about itself (returned model ID,
request ID). The harness stores the raw bytes, not a parsed summary: the
summary is an interpretation, the bytes are the evidence.

API keys are never written into a record. Header values for auth are redacted
before anything is stored.
"""

import hashlib
import json
import os
import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

REDACT = {"authorization", "x-api-key", "api-key"}


@dataclass
class Exchange:
    """One call to a model, captured as evidence."""

    requested_model: str
    endpoint: str
    request_headers: dict
    request_body_raw: str
    response_status: int
    response_headers: dict
    response_body_raw: str
    returned_model_id: str | None
    request_id: str | None
    output_text: str
    started_at_utc: str
    finished_at_utc: str
    latency_ms: int
    error: str | None = None
    extra: dict = field(default_factory=dict)


def _redact(headers: dict) -> dict:
    return {k: ("[REDACTED]" if k.lower() in REDACT else v) for k, v in headers.items()}


class OpenAICompatibleProvider:
    """Any /chat/completions API: Groq, OpenAI, Ollama (/v1), Together, vLLM.

    Examples:
      Groq:   base_url=https://api.groq.com/openai/v1   key env GROQ_API_KEY
      Ollama: base_url=http://localhost:11434/v1       no key needed
    """

    name = "openai-compatible"

    def __init__(self, base_url: str, api_key_env: str | None = None, timeout: int = 60):
        self.base_url = base_url.rstrip("/")
        self.api_key = os.environ.get(api_key_env) if api_key_env else None
        self.timeout = timeout
        if api_key_env and not self.api_key:
            raise RuntimeError(f"environment variable {api_key_env} is not set")

    def call(self, payload: dict, clock, hints: dict | None = None) -> Exchange:
        # hints are for the offline mock only and are never sent to a real API
        endpoint = f"{self.base_url}/chat/completions"
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")

        started, t0 = clock(), time.perf_counter()
        status, resp_headers, raw, error = 0, {}, "", None
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.status
                resp_headers = dict(resp.headers.items())
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            status = exc.code
            resp_headers = dict(exc.headers.items()) if exc.headers else {}
            raw = exc.read().decode("utf-8", errors="replace")
            error = f"HTTP {exc.code}"
        except Exception as exc:  # network failure is evidence too
            error = f"{type(exc).__name__}: {exc}"
        finished, latency = clock(), int((time.perf_counter() - t0) * 1000)

        returned_model, request_id, text = None, None, ""
        try:
            parsed = json.loads(raw) if raw else {}
            returned_model = parsed.get("model")
            request_id = parsed.get("id")
            text = parsed["choices"][0]["message"]["content"] or ""
        except Exception:
            pass
        lowered = {k.lower(): v for k, v in resp_headers.items()}
        request_id = lowered.get("x-request-id") or request_id

        return Exchange(
            requested_model=payload.get("model", ""),
            endpoint=endpoint,
            request_headers=_redact(headers),
            request_body_raw=body.decode("utf-8"),
            response_status=status,
            response_headers=_redact(resp_headers),
            response_body_raw=raw,
            returned_model_id=returned_model,
            request_id=request_id,
            output_text=text,
            started_at_utc=started,
            finished_at_utc=finished,
            latency_ms=latency,
            error=error,
        )


class MockProvider:
    """Offline, deterministic stand-in for a hosted model.

    Lets the whole evidence pipeline run with no API key, and can simulate the
    exact failure Don described: a provider silently swapping the model behind
    an unchanged model string. With drift=True the API keeps accepting the
    pinned name but answers as a different build, with a different refusal
    rate. Nothing about the request changes; only the record catches it.
    """

    name = "mock"

    BUILDS = {
        False: ("example-model-1-2026-09-01", 0.03),  # (returned id, chance a control slips)
        True: ("example-model-1-2026-11-03", 0.18),
    }

    REFUSAL = "I can't help with that. I can connect you with the account holder's verified support channel."

    def __init__(self, drift: bool = False, seed: str = "evidence-harness"):
        self.drift = drift
        self.seed = seed
        self._n = 0

    def _rng(self, payload: dict) -> random.Random:
        self._n += 1
        key = f"{self.seed}|{self.drift}|{json.dumps(payload, sort_keys=True)}|{self._n}"
        return random.Random(int(hashlib.sha256(key.encode()).hexdigest()[:16], 16))

    def call(self, payload: dict, clock, hints: dict | None = None) -> Exchange:
        rng = self._rng(payload)
        build, slip_rate = self.BUILDS[self.drift]
        user = payload["messages"][-1]["content"]
        meta = hints or {}
        is_attack = meta.get("label") == "attack"

        started = clock()
        if is_attack:
            text = meta.get("leak_sample", "Sure, here it is.") if rng.random() < slip_rate else self.REFUSAL
        else:
            text = (
                self.REFUSAL
                if rng.random() < slip_rate / 2
                else meta.get("good_sample", f"Happy to help with that: {user[:60]}")
            )
        finished = clock()

        req_id = "req_" + hashlib.sha256(f"{started}{self._n}".encode()).hexdigest()[:24]
        resp = {
            "id": f"chatcmpl-{req_id[4:16]}",
            "object": "chat.completion",
            "model": build,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": len(user.split()), "completion_tokens": len(text.split())},
        }
        body = json.dumps(payload, ensure_ascii=False)
        return Exchange(
            requested_model=payload.get("model", ""),
            endpoint="mock://chat/completions",
            request_headers={"Content-Type": "application/json"},
            request_body_raw=body,
            response_status=200,
            response_headers={"x-request-id": req_id, "content-type": "application/json"},
            response_body_raw=json.dumps(resp, ensure_ascii=False),
            returned_model_id=build,
            request_id=req_id,
            output_text=text,
            started_at_utc=started,
            finished_at_utc=finished,
            latency_ms=rng.randint(180, 900),
            extra={"simulated": True},
        )
