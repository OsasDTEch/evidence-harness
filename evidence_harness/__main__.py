"""Command line.

  python -m evidence_harness run suites/support_agent_controls.json --provider mock
  python -m evidence_harness run suites/support_agent_controls.json --provider groq --sentinel
  python -m evidence_harness verify <run_id>
  python -m evidence_harness drift support-agent-controls
  python -m evidence_harness report <run_id>
"""

import argparse
import sys
from pathlib import Path

from .drift import detect, history
from .providers import MockProvider, OpenAICompatibleProvider
from .report import render
from .runner import run_suite
from .store import read_json
from .verify import verify_run

PRESETS = {
    "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY"),
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY"),
    "ollama": ("http://localhost:11434/v1", None),
}


def make_provider(args):
    if args.provider == "mock":
        return MockProvider(drift=args.mock_drift)
    if args.provider in PRESETS:
        url, key = PRESETS[args.provider]
        return OpenAICompatibleProvider(args.base_url or url, key)
    return OpenAICompatibleProvider(args.base_url, args.api_key_env)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="evidence_harness")
    p.add_argument("--runs-dir", default="runs")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run a suite and record it as evidence")
    r.add_argument("suite")
    r.add_argument("--provider", default="mock", help="mock | groq | openai | ollama | custom")
    r.add_argument("--base-url")
    r.add_argument("--api-key-env")
    r.add_argument("--model", help="override the suite's requested model (recorded in the pre-registration)")
    r.add_argument("--sentinel", action="store_true", help="mark as a scheduled sentinel run")
    r.add_argument("--mock-drift", action="store_true", help="simulate a silent model swap")

    v = sub.add_parser("verify", help="independently verify a recorded run")
    v.add_argument("run_id")
    v.add_argument("--anchor", action="append", default=[], help="a published ledger head that must still be in the chain")

    sub.add_parser("head", help="print the ledger head hash, to publish as an external anchor")

    d = sub.add_parser("drift", help="compare runs of one suite over time")
    d.add_argument("suite_id")

    rp = sub.add_parser("report", help="write report.html for a run")
    rp.add_argument("run_id")

    args = p.parse_args(argv)
    runs = Path(args.runs_dir)

    if args.cmd == "run":
        run_dir = run_suite(
            Path(args.suite), make_provider(args), runs, sentinel=args.sentinel, model_override=args.model
        )
        m = read_json(run_dir / "manifest.json")
        s = m["summary"]
        print(f"run       {m['run_id']}")
        print(f"requested {m['model_identity']['requested']}")
        print(f"returned  {', '.join(m['model_identity']['returned_ids'])}")
        print(f"false neg {s['false_negative_counts'][0]}/{s['false_negative_counts'][1]}  "
              f"false pos {s['false_positive_counts'][0]}/{s['false_positive_counts'][1]}")
        if s["critical_breaches"]:
            print(f"CRITICAL  {', '.join(s['critical_breaches'])}")
        print(f"report    {render(run_dir)}")
        return 0

    if args.cmd == "verify":
        rep = verify_run(runs / args.run_id, anchors=args.anchor)
        for c in rep.checks:
            print(f"{'PASS' if c['ok'] else 'FAIL'}  {c['check']}  {c['detail']}")
        print("\nVERIFIED" if rep.ok else "\nVERIFICATION FAILED")
        return 0 if rep.ok else 1

    if args.cmd == "drift":
        rows = history(runs, args.suite_id)
        for r in rows:
            print(f"{r['sealed_at_utc']}  {', '.join(r['returned_ids']):32}  FN {r['fn_fail']}/{r['fn_n']}")
        events = detect(rows)
        for ev in events:
            print(f"DRIFT  {ev['kind']}  {ev['run_id']}\n       {ev['detail']}")
        return 1 if events else 0

    if args.cmd == "head":
        from .store import Ledger

        entries = Ledger(runs / "ledger.jsonl").entries()
        if not entries:
            print("ledger is empty")
            return 1
        print(f"{entries[-1]['entry_sha256']}  ({len(entries)} runs, last {entries[-1]['appended_at_utc']})")
        return 0

    if args.cmd == "report":
        print(render(runs / args.run_id))
        return 0


if __name__ == "__main__":
    sys.exit(main())
