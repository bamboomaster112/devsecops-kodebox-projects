#!/usr/bin/env python3
"""Decide pass/fail for the security gate and render the HTML report.

    python3 gate.py <report-dir> [--policy policy.env] [--html <file>] [--title "..."]

Reads the JSON reports written by gate.sh, applies the thresholds in policy.env,
prints a summary table, writes gate-result.json, and exits 1 when any check fails.
Standard library only, so it runs the same on the KodeBox and on a CI runner.
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
import kbx_reports as kr  # noqa: E402

RANK = {s: i for i, s in enumerate(kr.SEVERITIES)}  # CRITICAL=0 ... UNKNOWN=4


def read_policy(path: Path) -> dict:
    policy = {
        "FAIL_SEVERITY": "HIGH",          # vulnerabilities at this severity or worse fail the gate
        "ONLY_FIXABLE": "true",           # count only vulnerabilities that have a fixed version
        "MAX_SECRETS": "0",
        "HADOLINT_FAIL_LEVELS": "error,warning",
        "MAX_DOCKLE_FATAL": "0",
        "SEMGREP_FAIL_SEVERITY": "HIGH",  # semgrep ERROR maps to HIGH
        "BANDIT_FAIL_SEVERITY": "HIGH",
        "MAX_CHECKOV_FAILED": "0",
    }
    if path and path.is_file():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                policy[key.strip()] = value.split("#", 1)[0].strip().strip('"')  # drop inline comments
    for key in list(policy):  # environment variables override the file
        policy[key] = os.environ.get(key, policy[key])
    return policy


def at_or_above(counts: dict, threshold: str) -> int:
    limit = RANK[threshold.upper()]
    return sum(n for sev, n in (counts or {}).items() if RANK.get(sev, 99) <= limit)


def evaluate(s: dict, p: dict) -> list[dict]:
    checks = []

    def add(name, tool, value, limit, detail, present=True):
        if not present:
            checks.append({"name": name, "tool": tool, "status": "SKIP", "value": "-", "limit": limit,
                           "detail": "report not found"})
            return
        checks.append({"name": name, "tool": tool, "status": "PASS" if value <= limit else "FAIL",
                       "value": value, "limit": limit, "detail": detail})

    fixable = p["ONLY_FIXABLE"].lower() == "true"
    kind = "fixable " if fixable else ""
    sev = p["FAIL_SEVERITY"].upper()

    g = s["gitleaks"]
    add("Secrets in source and history", "gitleaks", g["total"] if g else 0, int(p["MAX_SECRETS"]),
        "hard-coded credentials", g is not None)

    h = s["hadolint"]
    levels = [lv.strip() for lv in p["HADOLINT_FAIL_LEVELS"].split(",") if lv.strip()]
    add("Dockerfile lint", "hadolint", sum(h["levels"].get(lv, 0) for lv in levels) if h else 0, 0,
        f"findings at level {'/'.join(levels)}", h is not None)

    sg = s["semgrep"]
    add("Static analysis (SAST)", "semgrep", at_or_above(sg["severity"], p["SEMGREP_FAIL_SEVERITY"]) if sg else 0, 0,
        f"rules at {p['SEMGREP_FAIL_SEVERITY']} or worse", sg is not None)

    b = s["bandit"]
    add("Python security lint", "bandit", at_or_above(b["severity"], p["BANDIT_FAIL_SEVERITY"]) if b else 0, 0,
        f"issues at {p['BANDIT_FAIL_SEVERITY']} or worse", b is not None)

    c = s["checkov"]
    add("Dockerfile and manifest policy", "checkov", c["failed"] if c else 0, int(p["MAX_CHECKOV_FAILED"]),
        "failed checks", c is not None)

    t = s["trivy"]
    add("Image vulnerabilities", "trivy", at_or_above(t["fixable" if fixable else "severity"], sev) if t else 0, 0,
        f"{kind}{sev} or worse", t is not None)
    add("Secrets inside the image", "trivy", len(t["secrets"]) if t else 0, int(p["MAX_SECRETS"]),
        "secret files baked into layers", t is not None)

    gr = s["grype"]
    add("Image vulnerabilities (2nd opinion)", "grype",
        at_or_above(gr["fixable" if fixable else "severity"], sev) if gr else 0, 0, f"{kind}{sev} or worse",
        gr is not None)

    d = s["dockle"]
    add("Image configuration (CIS)", "dockle", d["summary"].get("fatal", 0) if d else 0, int(p["MAX_DOCKLE_FATAL"]),
        "FATAL checks", d is not None)
    return checks


# ------------------------------------------------------------------ HTML ---
CSS = """
:root{--bg:#0b0d12;--panel:#141822;--line:#252b3a;--text:#e6e9f0;--muted:#8b93a7;--pass:#2fbf71;--fail:#ff5c5c;--skip:#a0a7b8;--accent:#8b5cf6}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text)}
main{max-width:1100px;margin:0 auto;padding:32px 20px 64px}h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:36px 0 12px}
.muted{color:var(--muted)}.verdict{display:inline-block;margin:18px 0 8px;padding:8px 18px;border-radius:999px;font-weight:700;letter-spacing:.04em}
.verdict.PASS{background:rgba(47,191,113,.15);color:var(--pass)}.verdict.FAIL{background:rgba(255,92,92,.15);color:var(--fail)}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--skip);border-radius:10px;padding:14px 16px}
.card.PASS{border-left-color:var(--pass)}.card.FAIL{border-left-color:var(--fail)}
.card .tool{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.card .val{font-size:28px;font-weight:700;margin:2px 0}.card .det{font-size:13px;color:var(--muted)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}
.sev{font-weight:700}.CRITICAL{color:#ff4d6d}.HIGH{color:#ff8c42}.MEDIUM{color:#f6c945}.LOW{color:#7aa2ff}.UNKNOWN{color:var(--muted)}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
"""


def table(headers, rows, empty="Nothing found."):
    if not rows:
        return f'<p class="muted">{empty}</p>'
    head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def e(v) -> str:
    return html.escape(str(v if v is not None else ""))


def sev_cell(sev: str) -> str:
    return f'<span class="sev {e(sev)}">{e(sev)}</span>'


def render_html(title: str, s: dict, checks: list[dict], verdict: str, p: dict) -> str:
    when = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cards = "".join(
        f'<div class="card {c["status"]}"><div class="tool">{e(c["tool"])} &middot; {e(c["status"])}</div>'
        f'<div class="val">{e(c["value"])}</div><div>{e(c["name"])}</div>'
        f'<div class="det">{e(c["detail"])} (limit {e(c["limit"])})</div></div>' for c in checks)

    t, g = s["trivy"] or {"vulns": []}, s["grype"] or {"vulns": []}
    vulns = sorted(t["vulns"], key=lambda v: (RANK.get(v["severity"], 9), v["pkg"] or ""))
    vrows = [[sev_cell(v["severity"]), f"<code>{e(v['id'])}</code>", e(v["pkg"]), e(v["installed"]),
              e(v["fixed"] or "no fix yet"), e(v["title"])] for v in vulns[:200]]
    gro = sorted(g["vulns"], key=lambda v: (RANK.get(v["severity"], 9), v["pkg"] or ""))
    grows = [[sev_cell(v["severity"]), f"<code>{e(v['id'])}</code>", e(v["pkg"]), e(v["installed"]),
              e(v["fixed"] or "no fix yet")] for v in gro[:200]]

    other = []
    for tool in ("gitleaks", "hadolint", "semgrep", "bandit", "checkov"):
        rep = s[tool]
        for f in (rep or {}).get("findings", []):
            loc = f.get("file") or ""
            if f.get("line"):
                loc += f":{f['line']}"
            other.append([e(tool), f"<code>{e(f.get('id') or f.get('rule'))}</code>",
                          sev_cell(f.get("severity") or (f.get("level") or "").upper() or "UNKNOWN"),
                          e(loc), e(f.get("message") or f.get("title") or f.get("rule") or "")])
    d = s["dockle"] or {"details": []}
    drows = [[e(x["level"]), f"<code>{e(x['id'])}</code>", e(x["title"]), e("; ".join(x["alerts"])[:200])]
             for x in d["details"]]
    img = s.get("image") or {}

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title><style>{CSS}</style></head><body><main>
<h1>{e(title)}</h1>
<div class="muted">Generated {e(when)} &middot; policy: fail on {e(p['FAIL_SEVERITY'])}+
{'(fixable only)' if p['ONLY_FIXABLE'].lower() == 'true' else ''} &middot; image size {e(img.get('size_mb', '?'))} MB,
user {e(img.get('user', '?'))}</div>
<div class="verdict {verdict}">GATE {verdict}</div>
<div class="cards">{cards}</div>
<h2>Image vulnerabilities (Trivy)</h2>{table(["Severity", "ID", "Package", "Installed", "Fixed in", "Title"], vrows)}
<h2>Image vulnerabilities (Grype)</h2>{table(["Severity", "ID", "Package", "Installed", "Fixed in"], grows)}
<h2>Code, Dockerfile and secret findings</h2>{table(["Tool", "Rule", "Severity", "Location", "Message"], other)}
<h2>Image configuration (Dockle)</h2>{table(["Level", "Check", "Title", "Detail"], drows)}
</main></body></html>
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("report_dir", type=Path)
    ap.add_argument("--policy", type=Path, default=Path(__file__).with_name("policy.env"))
    ap.add_argument("--html", type=Path)
    ap.add_argument("--title", default="DevSecOps security gate")
    args = ap.parse_args()

    policy = read_policy(args.policy)
    summary = kr.summarize_dir(args.report_dir)
    checks = evaluate(summary, policy)
    verdict = "FAIL" if any(c["status"] == "FAIL" for c in checks) else "PASS"

    kr.print_table(["Result", "Tool", "Check", "Found", "Limit"],
                   [[c["status"], c["tool"], c["name"], str(c["value"]), str(c["limit"])] for c in checks])
    print(f"GATE {verdict}")

    (args.report_dir / "gate-result.json").write_text(
        json.dumps({"verdict": verdict, "checks": checks, "policy": policy}, indent=2))
    icon = {"PASS": "✅", "FAIL": "❌", "SKIP": "➖"}
    md = [f"## {args.title}: **{verdict}**", "", "| Result | Tool | Check | Found | Limit |", "|---|---|---|---|---|"]
    md += [f"| {icon[c['status']]} {c['status']} | {c['tool']} | {c['name']} | {c['value']} | {c['limit']} |"
           for c in checks]
    (args.report_dir / "gate-summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    if args.html:
        args.html.parent.mkdir(parents=True, exist_ok=True)
        args.html.write_text(render_html(args.title, summary, checks, verdict, policy), encoding="utf-8")
        print(f"HTML report: {args.html}")
    return 1 if verdict == "FAIL" else 0


if __name__ == "__main__":
    sys.exit(main())
