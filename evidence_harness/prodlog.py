"""Production-side half of the bridge.

Sentinel runs say which model answered on the test dates. Production logs say
which model answered on the incident date. Wrap every production model call
with `logged_call` and each request leaves a hash-chained line recording the
model asked for, the model that answered and the request ID, plus hashes of
the payloads (not the payloads, so customer data stays out of the log).
"""

import json
import os
from pathlib import Path

from .hashing import sha256_bytes, sha256_obj, utc_now


class ProductionLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._head = self._last_hash()

    def _last_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        last = None
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line
        return json.loads(last)["entry_sha256"] if last else "0" * 64

    def logged_call(self, provider, payload: dict):
        ex = provider.call(payload, utc_now)
        body = {
            "at_utc": ex.started_at_utc,
            "requested_model": ex.requested_model,
            "returned_model_id": ex.returned_model_id,
            "request_id": ex.request_id,
            "request_sha256": sha256_bytes(ex.request_body_raw.encode()),
            "response_sha256": sha256_bytes(ex.response_body_raw.encode()),
            "status": ex.response_status,
            "prev_entry_sha256": self._head,
        }
        entry = {**body, "entry_sha256": sha256_obj(body)}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._head = entry["entry_sha256"]
        return ex
