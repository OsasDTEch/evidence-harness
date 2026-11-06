"""Sentinel drift: bridging the test date to the incident date.

A test proves a control held on the day it ran. A dispute is about the day
something went wrong. A frozen sentinel suite re-run on a schedule fills the
gap: for any incident date, there is a recorded run shortly before and after
it, each stating which model actually answered and how the control performed.

This module reads the run history for one suite and flags the two changes
that matter: the returned model identity changed, or the false-negative rate
moved outside what the earlier runs support.
"""

from pathlib import Path

from .checks import wilson_interval
from .store import Ledger, read_json


def history(runs_dir: Path, suite_id: str) -> list[dict]:
    rows = []
    for entry in Ledger(Path(runs_dir) / "ledger.jsonl").entries():
        if entry["suite_id"] != suite_id:
            continue
        m = read_json(Path(runs_dir) / entry["run_id"] / "manifest.json")
        fn_fail, fn_n = m["summary"]["false_negative_counts"]
        rows.append(
            {
                "run_id": m["run_id"],
                "sealed_at_utc": m["sealed_at_utc"],
                "sentinel": m["sentinel"],
                "requested": m["model_identity"]["requested"],
                "returned_ids": sorted(m["model_identity"]["returned_ids"]),
                "fn_fail": fn_fail,
                "fn_n": fn_n,
                "false_negative_rate": m["summary"]["false_negative_rate"],
                "critical_breaches": m["summary"]["critical_breaches"],
            }
        )
    return rows


def detect(rows: list[dict]) -> list[dict]:
    """Compare each run with the one before it."""
    events = []
    for prev, cur in zip(rows, rows[1:]):
        if cur["returned_ids"] != prev["returned_ids"]:
            events.append(
                {
                    "run_id": cur["run_id"],
                    "kind": "model_identity_changed",
                    "detail": (
                        f"requested '{cur['requested']}' both times, but the API answered as "
                        f"{prev['returned_ids']} then {cur['returned_ids']}"
                    ),
                }
            )
        lo, hi = wilson_interval(prev["fn_n"] - prev["fn_fail"], prev["fn_n"])
        prev_fn_hi = 1 - lo  # upper bound on the earlier false-negative rate
        if cur["false_negative_rate"] is not None and cur["false_negative_rate"] > prev_fn_hi:
            events.append(
                {
                    "run_id": cur["run_id"],
                    "kind": "false_negative_rate_rose",
                    "detail": (
                        f"false-negative rate {cur['false_negative_rate']:.1%} is above the earlier run's "
                        f"95% upper bound of {prev_fn_hi:.1%}"
                    ),
                }
            )
    return events
