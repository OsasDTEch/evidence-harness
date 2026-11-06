"""Canonical hashing. Every record is hashed over a canonical JSON form so the
same content always produces the same digest, on any machine, in any language."""

import hashlib
import json
from datetime import datetime, timezone


def canonical(obj) -> bytes:
    """Canonical JSON: sorted keys, no whitespace, UTF-8. Stable across runs."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_obj(obj) -> str:
    return sha256_bytes(canonical(obj))


def seal(record: dict) -> dict:
    """Return a copy of the record with its own hash attached.

    The hash covers every field except `record_sha256` itself, so anyone can
    recompute it by removing that field and hashing what is left."""
    body = {k: v for k, v in record.items() if k != "record_sha256"}
    return {**body, "record_sha256": sha256_obj(body)}


def check_seal(record: dict) -> bool:
    claimed = record.get("record_sha256")
    body = {k: v for k, v in record.items() if k != "record_sha256"}
    return claimed == sha256_obj(body)


def utc_now() -> str:
    """UTC only, microsecond precision, explicit Z suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
