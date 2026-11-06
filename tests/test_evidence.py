"""The harness's own evidence that it works: every tamper attempt must be caught.

Run with:  python -m unittest -v
"""

import json
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from evidence_harness.drift import detect, history
from evidence_harness.hashing import canonical, seal
from evidence_harness.providers import MockProvider
from evidence_harness.runner import run_suite
from evidence_harness.store import Ledger, WriteOnceError, write_once
from evidence_harness.verify import verify_run

SUITE = Path(__file__).resolve().parent.parent / "suites" / "support_agent_controls.json"


def writable(path: Path):
    for p in [path, *path.rglob("*")]:
        p.chmod(p.stat().st_mode | stat.S_IWUSR)


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.runs = cls.tmp / "runs"
        cls.base = run_suite(SUITE, MockProvider(seed="base"), cls.runs, sentinel=True)
        cls.drift = run_suite(SUITE, MockProvider(drift=True, seed="drift"), cls.runs, sentinel=True)

    @classmethod
    def tearDownClass(cls):
        writable(cls.tmp)
        shutil.rmtree(cls.tmp)

    def copy(self) -> Path:
        dst = Path(tempfile.mkdtemp()) / "runs"
        shutil.copytree(self.runs, dst)
        writable(dst)
        self.addCleanup(lambda: (writable(dst.parent), shutil.rmtree(dst.parent)))
        return dst

    def failing_record(self, runs: Path) -> Path:
        for p in sorted((runs / self.drift.name / "records").glob("A*.json")):
            if not json.loads(p.read_text())["verdict"]["passed"]:
                return p
        self.fail("drift run produced no failing attack record")

    def test_clean_runs_verify(self):
        self.assertTrue(verify_run(self.base).ok)
        self.assertTrue(verify_run(self.drift).ok)

    def test_files_cannot_be_overwritten(self):
        target = next((self.base / "records").glob("*.json"))
        with self.assertRaises(WriteOnceError):
            write_once(target, {"forged": True})

    def test_flipped_verdict_is_caught(self):
        runs = self.copy()
        p = self.failing_record(runs)
        p.write_text(p.read_text().replace('"passed":false', '"passed":true', 1))
        self.assertFalse(verify_run(runs / self.drift.name).ok)

    def test_resealed_forgery_is_caught(self):
        runs = self.copy()
        p = self.failing_record(runs)
        rec = json.loads(p.read_text())
        rec["verdict"]["passed"] = True
        rec["output_text"] = "I can't help with that."
        p.write_bytes(canonical(seal(rec)))  # attacker knows the hashing scheme
        self.assertFalse(verify_run(runs / self.drift.name).ok)

    def test_deleted_record_is_caught(self):
        runs = self.copy()
        self.failing_record(runs).unlink()
        self.assertFalse(verify_run(runs / self.drift.name).ok)

    def test_loosened_criteria_are_caught(self):
        runs = self.copy()
        p = runs / self.drift.name / "prereg.json"
        pre = json.loads(p.read_text())
        for c in pre["suite"]["cases"]:
            c["forbidden"] = []
        p.write_bytes(canonical(seal(pre)))
        self.assertFalse(verify_run(runs / self.drift.name).ok)

    def test_truncated_ledger_is_caught(self):
        runs = self.copy()
        lines = (runs / "ledger.jsonl").read_text().splitlines()
        (runs / "ledger.jsonl").write_text(lines[0] + "\n")
        self.assertFalse(verify_run(runs / self.drift.name).ok)

    def test_external_anchor_survives_only_if_chain_does(self):
        head = Ledger(self.runs / "ledger.jsonl").entries()[-1]["entry_sha256"]
        self.assertTrue(verify_run(self.drift, anchors=[head]).ok)
        self.assertFalse(verify_run(self.drift, anchors=["f" * 64]).ok)

    def test_silent_model_swap_is_detected(self):
        events = detect(history(self.runs, "support-agent-controls"))
        kinds = {e["kind"] for e in events}
        self.assertIn("model_identity_changed", kinds)

    def test_no_api_key_in_records(self):
        for p in self.base.rglob("*.json"):
            self.assertNotIn("Bearer ", p.read_text())


if __name__ == "__main__":
    unittest.main()
