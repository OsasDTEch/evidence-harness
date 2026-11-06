"""Independent verification of a recorded run.

Anyone can run this against a run folder, with no access to the model, the
API key or the original machine. It answers one question: is this record
exactly what was written at the time, and does it support its own summary?
"""

from pathlib import Path

from .checks import evaluate
from .hashing import check_seal, sha256_bytes, sha256_obj
from .store import Ledger, file_sha256, read_json


class Report:
    def __init__(self):
        self.checks = []

    def add(self, name: str, ok: bool, detail: str = ""):
        self.checks.append({"check": name, "ok": bool(ok), "detail": detail})

    @property
    def ok(self) -> bool:
        return all(c["ok"] for c in self.checks)


def verify_run(run_dir: Path, ledger_path: Path | None = None) -> Report:
    run_dir = Path(run_dir)
    rep = Report()
    ledger_path = ledger_path or run_dir.parent / "ledger.jsonl"

    manifest_path = run_dir / "manifest.json"
    if not manifest_path.exists():
        rep.add("manifest present", False, str(manifest_path))
        return rep
    manifest = read_json(manifest_path)
    manifest_file_hash = file_sha256(manifest_path)
    rep.add("manifest seal intact", check_seal(manifest), manifest["record_sha256"][:16])

    # Pre-registration: exists, sealed, and matches what the manifest committed to.
    prereg_path = run_dir / "prereg.json"
    prereg = read_json(prereg_path)
    rep.add("pre-registration seal intact", check_seal(prereg))
    rep.add(
        "pre-registration file matches manifest",
        file_sha256(prereg_path) == manifest["prereg"]["file_sha256"],
    )
    registered_at = prereg["registered_at_utc"]

    # Every record: listed, unaltered, sealed, linked to this pre-registration,
    # created after it, with payload hashes that match the raw bytes.
    listed = {r["path"]: r["file_sha256"] for r in manifest["records"]}
    on_disk = {f"records/{p.name}" for p in (run_dir / "records").glob("*.json")}
    rep.add(
        "no unlisted or missing record files",
        on_disk == set(listed),
        f"{len(on_disk)} on disk, {len(listed)} listed",
    )
    rep.add(
        "records root hash recomputes",
        sha256_obj([r["file_sha256"] for r in manifest["records"]]) == manifest["records_root_sha256"],
    )

    bad_file = bad_seal = bad_link = bad_time = bad_payload = bad_verdict = 0
    cases = {c["id"]: c for c in prereg["suite"]["cases"]}
    for rel, expected in listed.items():
        path = run_dir / rel
        if not path.exists() or file_sha256(path) != expected:
            bad_file += 1
            continue
        rec = read_json(path)
        bad_seal += not check_seal(rec)
        bad_link += rec["prereg_record_sha256"] != prereg["record_sha256"]
        bad_time += rec["started_at_utc"] < registered_at
        bad_payload += sha256_bytes(rec["request_body_raw"].encode()) != rec["request_body_sha256"]
        bad_payload += sha256_bytes(rec["response_body_raw"].encode()) != rec["response_body_sha256"]
        if rec["error"] is None:
            # The verdict must follow from the criteria registered BEFORE the run.
            bad_verdict += evaluate(cases[rec["case_id"]], rec["output_text"])["passed"] != rec["verdict"]["passed"]

    n = len(listed)
    rep.add("record files unaltered", bad_file == 0, f"{n - bad_file}/{n}")
    rep.add("record seals intact", bad_seal == 0, f"{n - bad_file - bad_seal}/{n - bad_file}")
    rep.add("records link to this pre-registration", bad_link == 0)
    rep.add("criteria registered before first call", bad_time == 0, f"registered {registered_at}")
    rep.add("raw payload hashes match", bad_payload == 0)
    rep.add("verdicts re-derive from pre-registered criteria", bad_verdict == 0)

    # Ledger: chain intact end to end, and this manifest is in it.
    entries = Ledger(ledger_path).entries()
    prev, chain_ok = Ledger.GENESIS, True
    for e in entries:
        body = {k: v for k, v in e.items() if k != "entry_sha256"}
        if e["prev_entry_sha256"] != prev or sha256_obj(body) != e["entry_sha256"]:
            chain_ok = False
            break
        prev = e["entry_sha256"]
    rep.add("ledger hash chain intact", chain_ok, f"{len(entries)} entries")
    mine = [e for e in entries if e["run_id"] == manifest["run_id"]]
    rep.add(
        "run is in ledger with matching manifest hash",
        len(mine) == 1 and mine[0]["manifest_sha256"] == manifest_file_hash,
    )
    return rep
