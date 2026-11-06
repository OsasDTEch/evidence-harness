# evidence-harness

An eval harness that is a system of record that happens to test.

Most eval tools record a result. This one records the conditions: what was asked for, what actually answered, the raw bytes in both directions, and the pass/fail criteria as they stood before the first call. Every record is hashed, written once, and chained, so a year later the evidence still says exactly what it said on the day it was made, and anyone can check that without the model, the API key or the original machine.

The design follows a simple principle from evidence practice: you do not preserve the breathalyzer, you preserve the calibration log and the printout made at the time. A dated model snapshot will be retired, so "re-run it and see" stops being possible. The contemporaneous record is what survives.

## What every run records

| Requirement | Where it lives |
|---|---|
| Model string requested, plus the model ID and request ID the API returns | `requested_model`, `returned_model_id`, `request_id` on every record |
| Full raw request and response payloads, including system prompt, parameters and tool definitions | `request_body_raw`, `response_body_raw`, each with its own SHA-256 |
| UTC timestamps, code commit, test suite version | `started_at_utc` / `finished_at_utc` per call; commit, dirty flag and suite version in `prereg.json` |
| Pass/fail criteria fixed before the run | `prereg.json` is written and hashed before any model call; every record points to it; `verify` checks no call started before it and re-derives every verdict from it |
| Repeated samples per item | `samples_per_case` (default 20), reported as a pass rate with a 95% Wilson interval, not a single green tick |
| A hash of every record and of the manifest, in write-once storage | Every file is created exclusively, sealed with its own hash and made read-only; the manifest lists every record by hash; the manifest hash is chained into `ledger.jsonl` |

It also reports what a pass rate alone hides:

* **False-negative rate**: attacks that got through.
* **False-positive rate**: legitimate requests wrongly refused.
* **Critical breaches**: any critical case that failed even once is flagged as belonging in deterministic code outside the model. A boundary that holds 99% of the time is rare, not impossible, and if the other 1% moves money or exposes data, rare is not good enough.

## Bridging the test date to the incident date

A test proves a control held on the day it ran. A dispute is about the day something went wrong. Two pieces close that gap:

1. **Sentinel runs.** A frozen suite re-run on a schedule (`--sentinel`). Regular cadence is itself part of the evidence. `drift` compares consecutive runs and flags when the returned model identity changes under an unchanged requested string, or when the false-negative rate moves above what earlier runs support.
2. **Production logs.** `ProductionLog.logged_call` wraps live model calls and writes a hash-chained line per request with the requested model, returned model ID and request ID, plus payload hashes (not payloads, so customer data stays out).

If the model really was different on the incident date, you want to learn that from your own record first.

## Quick start (Windows PowerShell, macOS or Linux)

Needs Python 3.10 or newer. No packages to install.

```powershell
# 1. Prove the harness catches tampering (11 tests)
python -m unittest -v

# 2. Record a run offline with the simulated provider
python -m evidence_harness run suites/support_agent_controls.json --provider mock --sentinel

# 3. Simulate a provider silently swapping the model behind the same name
python -m evidence_harness run suites/support_agent_controls.json --provider mock --sentinel --mock-drift
python -m evidence_harness drift support-agent-controls

# 4. Independently verify any run, and open its report
python -m evidence_harness verify <run_id>
start runs/<run_id>/report.html          # macOS: open, Linux: xdg-open
```

### Against a real model

Any OpenAI-compatible API works: Groq, OpenAI, Ollama, vLLM, Together.

```powershell
$env:GROQ_API_KEY = "gsk_..."
python -m evidence_harness run suites/support_agent_controls.json --provider groq --model llama-3.3-70b-versatile

# Local model, no key
python -m evidence_harness run suites/support_agent_controls.json --provider ollama --model llama3.1
```

API keys are redacted before anything is written. A test asserts it.

### External anchoring

Locally, write-once means files are created exclusively and set read-only. That makes the store tamper-evident: changing, adding or deleting any record, verdict, criterion or ledger entry fails verification. It does not stop someone with disk access from rewriting the entire store consistently. For that, publish the ledger head somewhere outside your control:

```powershell
python -m evidence_harness head                       # publish this hash
python -m evidence_harness verify <run_id> --anchor <published_hash>
```

The included GitHub Actions workflow (`.github/workflows/sentinel.yml`) runs the sentinel daily and commits each run, so GitHub's history anchors every ledger head with an outside timestamp. For tamper-proof storage, point the same layout at an object store with a retention lock (S3 Object Lock in compliance mode, Azure immutable blobs, GCS bucket lock).

## What verification checks

```
PASS  manifest seal intact
PASS  pre-registration seal intact
PASS  pre-registration file matches manifest
PASS  no unlisted or missing record files
PASS  records root hash recomputes
PASS  record files unaltered
PASS  record seals intact
PASS  records link to this pre-registration
PASS  criteria registered before first call
PASS  raw payload hashes match
PASS  verdicts re-derive from pre-registered criteria
PASS  ledger hash chain intact
PASS  run is in ledger with matching manifest hash
```

The test suite attacks a copy of real evidence five ways: flipping a failed verdict, flipping it and re-sealing the record with the correct hashing scheme, deleting a failing record, loosening the criteria after the run, and truncating the ledger. Every attempt is caught.

## Layout

```
evidence_harness/
  runner.py     pre-register, sample, seal, manifest, ledger
  verify.py     independent verification
  drift.py      sentinel history and drift detection
  providers.py  OpenAI-compatible APIs plus an offline simulator
  checks.py     deterministic criteria, Wilson intervals
  store.py      write-once files and the hash-chained ledger
  prodlog.py    per-request production identity log
  report.py     human-readable summary
suites/         test suites (cases + criteria as data)
runs/           the evidence
tests/          the harness's own evidence that it works
```

## Honest limits

* The report is a summary and an interpretation. The sealed JSON is the evidence.
* Criteria are deterministic regex, by design: the same output always gets the same verdict. That suits boundaries that can be stated precisely. Judgement calls need a different instrument, recorded the same way.
* The example suite and the simulated provider use synthetic data. The `simulated` flag on every record and the report banner say so.
* Admissibility is a judge's call. The aim is narrower: a record built so the argument is about weight, not admissibility.

Built by Omons Wisdom (Osas) · github.com/OsasDTEch · omonswisdom.ict@gmail.com
