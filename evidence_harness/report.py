"""Human-readable report for one run.

The report is a SUMMARY, and says so. The evidence is the sealed JSON beside
it. Every figure here can be re-derived from those files with `verify`.
"""

import html
import json
from pathlib import Path

from .drift import detect, history
from .store import Ledger, file_sha256, read_json
from .verify import verify_run

CSS = """
:root{--bg:#f7f6f2;--card:#fff;--ink:#1c1b19;--mute:#6b675f;--line:#e4e1d8;--ok:#1f7a4d;--okbg:#e6f3ec;
--bad:#b3261e;--badbg:#fbe9e7;--warn:#8a5a00;--warnbg:#fff3d6;--accent:#2b4c7e;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--card:#1d1c1a;--ink:#ecebe6;--mute:#9b978d;--line:#33312c;
--ok:#6fcf9b;--okbg:#17291f;--bad:#f2867c;--badbg:#2e1a18;--warn:#f0c062;--warnbg:#2c2414;--accent:#8fb0e6}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:26px;margin:0 0 4px;letter-spacing:-.01em}h2{font-size:17px;margin:0 0 12px}
.sub{color:var(--mute);margin:0 0 24px}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin:0 0 16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.stat{border:1px solid var(--line);border-radius:10px;padding:14px}.stat b{display:block;font-size:24px}.stat span{color:var(--mute);font-size:13px}
.pill{display:inline-block;padding:2px 9px;border-radius:99px;font-size:12px;font-weight:600}
.ok{color:var(--ok);background:var(--okbg)}.bad{color:var(--bad);background:var(--badbg)}.warn{color:var(--warn);background:var(--warnbg)}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mute);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
code,.mono{font-family:var(--mono);font-size:12.5px;word-break:break-all}
.bar{position:relative;height:8px;background:var(--line);border-radius:4px;min-width:120px;margin-top:6px}
.bar i{position:absolute;top:0;height:8px;border-radius:4px;background:var(--accent);opacity:.35}
.bar em{position:absolute;top:-3px;width:3px;height:14px;background:var(--accent);border-radius:2px}
.note{border-left:3px solid var(--bad);padding:10px 14px;background:var(--badbg);border-radius:6px;margin-top:12px}
.callout{border-left:3px solid var(--warn);padding:10px 14px;background:var(--warnbg);border-radius:6px;margin-top:12px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:12px;overflow-x:auto;font-family:var(--mono);font-size:12px;white-space:pre-wrap;word-break:break-all}
.checks li{list-style:none;margin:4px 0}.checks{padding:0;margin:0}
footer{color:var(--mute);font-size:13px;margin-top:24px}
"""


def e(x) -> str:
    return html.escape(str(x))


def pct(x) -> str:
    return "n/a" if x is None else f"{x:.1%}"


def render(run_dir: Path) -> Path:
    run_dir = Path(run_dir)
    runs_dir = run_dir.parent
    m = read_json(run_dir / "manifest.json")
    s = m["summary"]
    ident = m["model_identity"]
    vr = verify_run(run_dir)
    rows = history(runs_dir, m["suite_id"])
    events = detect(rows)
    ledger = Ledger(runs_dir / "ledger.jsonl").entries()
    first = read_json(run_dir / m["records"][0]["path"])

    v_pill = '<span class="pill ok">VERIFIED</span>' if vr.ok else '<span class="pill bad">VERIFICATION FAILED</span>'
    sim = '<span class="pill warn">SIMULATED PROVIDER</span>' if first.get("simulated") else ""
    checks = "".join(
        f'<li><span class="pill {"ok" if c["ok"] else "bad"}">{"PASS" if c["ok"] else "FAIL"}</span> '
        f'{e(c["check"])} <span class="mono" style="color:var(--mute)">{e(c["detail"])}</span></li>'
        for c in vr.checks
    )

    returned = "".join(
        f"<tr><td><code>{e(k)}</code></td><td>{v}</td></tr>" for k, v in ident["returned_ids"].items()
    )
    id_note = (
        '<span class="pill ok">returned ID equals requested</span>'
        if ident["requested_equals_returned"]
        else '<span class="pill warn">returned ID differs from requested</span>'
    )

    case_rows = ""
    for c in s["cases"]:
        lo, hi = c["pass_rate_ci95"]
        status = "ok" if c["meets_requirement"] else "bad"
        case_rows += (
            f"<tr><td><b>{e(c['title'])}</b><br><code>{e(c['case_id'])}</code></td>"
            f"<td>{e(c['label'])}<br><span style='color:var(--mute)'>{e(c['adversarial_condition'] or '')}</span></td>"
            f"<td><span class='pill {'bad' if c['severity']=='critical' else 'warn' if c['severity']=='high' else 'ok'}'>{e(c['severity'])}</span></td>"
            f"<td>{c['passes']}/{c['samples']} ({pct(c['pass_rate'])})"
            f"<div class='bar'><i style='left:{lo*100:.1f}%;width:{(hi-lo)*100:.1f}%'></i><em style='left:calc({c['pass_rate']*100:.1f}% - 1px)'></em></div>"
            f"<span style='color:var(--mute);font-size:12px'>95% CI {pct(lo)} to {pct(hi)}</span></td>"
            f"<td>{pct(c['required_pass_rate'])}</td>"
            f"<td><span class='pill {status}'>{'meets' if c['meets_requirement'] else 'below'}</span></td></tr>"
        )

    crit = ""
    if s["critical_breaches"]:
        crit = (
            f"<div class='note'><b>Critical boundary breached in {len(s['critical_breaches'])} case(s):</b> "
            f"{', '.join(e(x) for x in s['critical_breaches'])}. {e(s['critical_breach_note'])}</div>"
        )

    hist_rows = "".join(
        f"<tr><td><code>{e(r['run_id'])}</code>{' <span class=\"pill ok\">sentinel</span>' if r['sentinel'] else ''}</td>"
        f"<td class='mono'>{e(r['sealed_at_utc'])}</td><td><code>{e(', '.join(r['returned_ids']))}</code></td>"
        f"<td>{r['fn_fail']}/{r['fn_n']} ({pct(r['false_negative_rate'])})</td></tr>"
        for r in rows
    )
    ev_html = "".join(
        f"<div class='callout'><b>{e(x['kind'].replace('_', ' '))}</b> in <code>{e(x['run_id'])}</code>: {e(x['detail'])}</div>"
        for x in events
    ) or "<p style='color:var(--mute)'>No drift between consecutive runs.</p>"

    excerpt = {
        k: first[k]
        for k in (
            "case_id", "sample_index", "requested_model", "returned_model_id", "request_id",
            "started_at_utc", "request_body_sha256", "response_body_sha256", "verdict", "record_sha256",
        )
    }

    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Evidence Report</title><style>{CSS}</style></head>
<body><main>
<h1>Control test evidence report</h1>
<p class="sub">Suite <b>{e(m['suite_id'])}</b> v{e(m['suite_version'])} · run <code>{e(m['run_id'])}</code> · sealed {e(m['sealed_at_utc'])} {v_pill} {sim}</p>

<div class="card"><h2>Headline</h2><div class="grid">
<div class="stat"><b>{pct(s['false_negative_rate'])}</b><span>false-negative rate (attacks that got through), {s['false_negative_counts'][0]}/{s['false_negative_counts'][1]} samples</span></div>
<div class="stat"><b>{pct(s['false_positive_rate'])}</b><span>false-positive rate (legitimate requests refused), {s['false_positive_counts'][0]}/{s['false_positive_counts'][1]}</span></div>
<div class="stat"><b>{len(s['critical_breaches'])}</b><span>critical cases with any failure</span></div>
<div class="stat"><b>{len(m['records'])}</b><span>sealed records, each holding raw request and response</span></div>
</div>{crit}</div>

<div class="card"><h2>Which model actually answered</h2>
<p>Requested: <code>{e(ident['requested'])}</code> {id_note}</p>
<table><tr><th>Returned model ID (from the API response)</th><th>Samples</th></tr>{returned}</table>
<p style="color:var(--mute);font-size:13px;margin-bottom:0">The requested string is the caller's intent. The returned ID is the provider's own statement of what ran, captured per response.</p></div>

<div class="card"><h2>Cases</h2>
<table><tr><th>Case</th><th>Type / condition</th><th>Severity</th><th>Result</th><th>Required</th><th></th></tr>{case_rows}</table></div>

<div class="card"><h2>Sentinel history and drift</h2>
<table><tr><th>Run</th><th>Sealed (UTC)</th><th>Returned model</th><th>False negatives</th></tr>{hist_rows}</table>
{ev_html}</div>

<div class="card"><h2>Independent verification</h2><ul class="checks">{checks}</ul>
<p style="color:var(--mute);font-size:13px">Re-run with <code>python -m evidence_harness verify {e(run_dir.name)}</code>. No model access or API key needed.</p></div>

<div class="card"><h2>Evidence index</h2><table>
<tr><td>Pre-registration (criteria, fixed before first call)</td><td><code>{e(m['prereg']['file_sha256'])}</code></td></tr>
<tr><td>Manifest file</td><td><code>{e(file_sha256(run_dir / 'manifest.json'))}</code></td></tr>
<tr><td>Records root</td><td><code>{e(m['records_root_sha256'])}</code></td></tr>
<tr><td>Ledger head ({len(ledger)} runs chained)</td><td><code>{e(ledger[-1]['entry_sha256'] if ledger else '')}</code></td></tr>
</table>
<h2 style="margin-top:16px">One record, excerpted</h2><pre>{e(json.dumps(excerpt, indent=2))}</pre></div>

<footer>This page is a summary. The evidence is the sealed JSON in this run folder. A summary is an interpretation; the raw records are what was produced.</footer>
</main></body></html>"""
    out = run_dir / "report.html"
    out.write_text(page, encoding="utf-8")
    return out
