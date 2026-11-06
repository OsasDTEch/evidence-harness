"""Write-once storage and the append-only ledger.

Locally, write-once means: a file is created exclusively (it cannot already
exist), then marked read-only. That makes the store tamper-EVIDENT, not
tamper-PROOF: someone with disk access can still change a file, but every
record is sealed with its own hash, every run is listed in the manifest by
hash, and every manifest is chained into the ledger. Changing any byte
anywhere breaks a hash that `verify` checks.

For tamper-PROOF storage, point the same files at an object store with a
retention lock (S3 Object Lock in compliance mode, Azure immutable blobs, or
GCS bucket lock). The file layout does not change.
"""

import json
import os
import stat
from pathlib import Path

from .hashing import canonical, sha256_obj, utc_now

READ_ONLY = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH


class WriteOnceError(Exception):
    pass


def write_once(path: Path, obj) -> str:
    """Create `path` with canonical JSON content. Refuses to overwrite.
    Returns the SHA-256 of the exact bytes written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = canonical(obj)
    try:
        with open(path, "xb") as fh:  # "x" = fail if the file already exists
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    except FileExistsError as exc:
        raise WriteOnceError(f"refusing to overwrite existing evidence file: {path}") from exc
    os.chmod(path, READ_ONLY)  # on Windows this sets the read-only attribute
    from .hashing import sha256_bytes

    return sha256_bytes(data)


def read_json(path: Path):
    with open(path, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


def file_sha256(path: Path) -> str:
    from .hashing import sha256_bytes

    with open(path, "rb") as fh:
        return sha256_bytes(fh.read())


class Ledger:
    """Append-only, hash-chained index of every run ever recorded.

    Each line commits to the previous line's hash, so removing, reordering or
    editing a past run breaks the chain from that point forward."""

    GENESIS = "0" * 64

    def __init__(self, path: Path):
        self.path = path

    def entries(self):
        if not self.path.exists():
            return []
        with open(self.path, "r", encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def head(self) -> str:
        entries = self.entries()
        return entries[-1]["entry_sha256"] if entries else self.GENESIS

    def append(self, run_id: str, suite_id: str, manifest_sha256: str, sentinel: bool) -> dict:
        body = {
            "run_id": run_id,
            "suite_id": suite_id,
            "manifest_sha256": manifest_sha256,
            "sentinel": sentinel,
            "appended_at_utc": utc_now(),
            "prev_entry_sha256": self.head(),
        }
        entry = {**body, "entry_sha256": sha256_obj(body)}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            os.chmod(self.path, READ_ONLY | stat.S_IWUSR)
        with open(self.path, "a", encoding="utf-8") as fh:  # append only, never rewrite
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        os.chmod(self.path, READ_ONLY)
        return entry
