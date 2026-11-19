#!/usr/bin/env python3
"""Read the JSON reports the scanners write and turn them into comparable numbers.

Used by 01-image-hardening/compare.sh (before/after table) and by
04-ci-security-gate (gate decision and HTML report). Standard library only.

    python3 lib/kbx_reports.py summary  <report-dir>
    python3 lib/kbx_reports.py compare  <before-dir> <after-dir>
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
_SEV_ALIASES = {"NEGLIGIBLE": "LOW", "ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


def norm_sev(value: str | None) -> str:
    sev = (value or "UNKNOWN").upper()
    sev = _SEV_ALIASES.get(sev, sev)
    return sev if sev in SEVERITIES else "UNKNOWN"


def load(path: Path):
    """Return parsed JSON, or None when the file is missing or empty."""
    if not path.is_file() or path.stat().st_size == 0:
        return None
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------- parsers ---
def parse_hadolint(path: Path) -> dict | None:
    data = load(path)
    if data is None:
        return None
    levels = Counter(item.get("level", "info") for item in data)
    return {
        "total": len(data),
        "levels": dict(levels),
        "findings": [
            {"id": i.get("code"), "level": i.get("level"), "line": i.get("line"), "message": i.get("message")}
            for i in data
        ],
    }


def parse_trivy(path: Path) -> dict | None:
    data = load(path)
    if data is None:
        return None
    sev_all, sev_fixable = Counter(), Counter()
    vulns, secrets, misconfigs = [], [], []
    for result in data.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            sev = norm_sev(v.get("Severity"))
            sev_all[sev] += 1
            fixable = bool(v.get("FixedVersion"))
            if fixable:
                sev_fixable[sev] += 1
            vulns.append({
                "id": v.get("VulnerabilityID"), "pkg": v.get("PkgName"), "installed": v.get("InstalledVersion"),
                "fixed": v.get("FixedVersion") or "", "severity": sev, "target": result.get("Target"),
                "title": (v.get("Title") or "")[:120],
            })
        for s in result.get("Secrets") or []:
            secrets.append({"rule": s.get("RuleID"), "severity": norm_sev(s.get("Severity")),
                            "target": result.get("Target"), "line": s.get("StartLine"), "title": s.get("Title")})
        for m in result.get("Misconfigurations") or []:
            if m.get("Status") == "FAIL":
                misconfigs.append({"id": m.get("ID"), "severity": norm_sev(m.get("Severity")),
                                   "target": result.get("Target"), "title": m.get("Title")})
    return {"severity": dict(sev_all), "fixable": dict(sev_fixable), "vulns": vulns,
            "secrets": secrets, "misconfigs": misconfigs}


def parse_grype(path: Path) -> dict | None:
    data = load(path)
    if data is None:
        return None
    sev_all, sev_fixable = Counter(), Counter()
    vulns = []
    for m in data.get("matches") or []:
        v, a = m.get("vulnerability", {}), m.get("artifact", {})
        sev = norm_sev(v.get("severity"))
        sev_all[sev] += 1
        fix = v.get("fix") or {}
        fixable = fix.get("state") == "fixed"
        if fixable:
            sev_fixable[sev] += 1
        vulns.append({"id": v.get("id"), "pkg": a.get("name"), "installed": a.get("version"),
                      "fixed": ", ".join(fix.get("versions") or []), "severity": sev, "type": a.get("type")})
    return {"severity": dict(sev_all), "fixable": dict(sev_fixable), "vulns": vulns}


def parse_dockle(path: Path) -> dict | None:
    data = load(path)
    if data is None:
        return None
    summary = {k: int(v) for k, v in (data.get("summary") or {}).items()}
    details = [{"id": d.get("code"), "level": d.get("level"), "title": d.get("title"),
                "alerts": d.get("alerts") or []} for d in data.get("details") or []]
    return {"summary": summary, "details": details}


def parse_gitleaks(path: Path) -> dict | None:
    data = load(path)
    if data is None:
        return None
    return {"total": len(data), "findings": [
        {"rule": f.get("RuleID"), "file": f.get("File"), "line": f.get("StartLine"),
         "commit": (f.get("Commit") or "")[:10], "fingerprint": f.get("Fingerprint")} for f in data]}


def parse_semgrep(path: Path) -> dict | None:
    data = load(path)
    if data is None:
        return None
    findings = [{"id": r.get("check_id", "").split(".")[-1], "severity": norm_sev(r.get("extra", {}).get("severity")),
                 "file": r.get("path"), "line": r.get("start", {}).get("line"),
                 "message": (r.get("extra", {}).get("message") or "")[:160]} for r in data.get("results") or []]
    return {"severity": dict(Counter(f["severity"] for f in findings)), "findings": findings}


def parse_bandit(path: Path) -> dict | None:
    data = load(path)
    if data is None:
        return None
    findings = [{"id": r.get("test_id"), "severity": norm_sev(r.get("issue_severity")),
                 "confidence": r.get("issue_confidence"), "file": r.get("filename"),
                 "line": r.get("line_number"), "message": r.get("issue_text")} for r in data.get("results") or []]
    return {"severity": dict(Counter(f["severity"] for f in findings)), "findings": findings}


def load_stream(path: Path) -> list | None:
    """Checkov prints one JSON document per scanned directory, back to back."""
    if not path.is_file() or path.stat().st_size == 0:
        return None
    text, docs, pos, dec = path.read_text(encoding="utf-8"), [], 0, json.JSONDecoder()
    while pos < len(text):
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            break
        doc, pos = dec.raw_decode(text, pos)
        docs.extend(doc if isinstance(doc, list) else [doc])
    return docs


def parse_checkov(path: Path) -> dict | None:
    blocks = load_stream(path)
    if blocks is None:
        return None
    failed = []
    passed = 0
    for block in blocks:
        results = block.get("results") or {}
        # --quiet drops the passed list from the results, but the summary keeps the count.
        passed += (block.get("summary") or {}).get("passed", len(results.get("passed_checks") or []))
        for c in results.get("failed_checks") or []:
            failed.append({"id": c.get("check_id"), "title": c.get("check_name"), "file": c.get("file_path"),
                           "framework": block.get("check_type"), "severity": norm_sev(c.get("severity"))})
    return {"passed": passed, "failed": len(failed), "findings": failed}


# --------------------------------------------------------------- summaries ---
def sev_line(counts: dict | None) -> str:
    if counts is None:
        return "n/a"
    return " ".join(f"{s[0]}:{counts.get(s, 0)}" for s in SEVERITIES[:4])


def summarize_dir(report_dir: Path) -> dict:
    d = Path(report_dir)
    out = {
        "hadolint": parse_hadolint(d / "hadolint.json"),
        "trivy": parse_trivy(d / "trivy.json"),
        "grype": parse_grype(d / "grype.json"),
        "dockle": parse_dockle(d / "dockle.json"),
        "gitleaks": parse_gitleaks(d / "gitleaks.json"),
        "semgrep": parse_semgrep(d / "semgrep.json"),
        "bandit": parse_bandit(d / "bandit.json"),
        "checkov": parse_checkov(d / "checkov.json"),
    }
    inspect = load(d / "inspect.json")
    if inspect:
        img = inspect[0]
        out["image"] = {"size_mb": round(img.get("Size", 0) / 1_000_000, 1),
                        "user": img.get("Config", {}).get("User") or "root (unset)",
                        "layers": len(img.get("RootFS", {}).get("Layers") or [])}
    return out


def rows(summary: dict) -> list[tuple[str, str]]:
    h, t, g, k = summary["hadolint"], summary["trivy"], summary["grype"], summary["dockle"]
    img = summary.get("image") or {}
    return [
        ("Image size (MB)", str(img.get("size_mb", "n/a"))),
        ("Runs as user", str(img.get("user", "n/a"))),
        ("Hadolint findings", "n/a" if h is None else f"{h['total']} ({', '.join(f'{k2}:{v}' for k2, v in sorted(h['levels'].items())) or 'clean'})"),
        ("Trivy vulns (all)", "n/a" if t is None else sev_line(t["severity"])),
        ("Trivy vulns (fixable)", "n/a" if t is None else sev_line(t["fixable"])),
        ("Trivy secrets in image", "n/a" if t is None else str(len(t["secrets"]))),
        ("Grype vulns (all)", "n/a" if g is None else sev_line(g["severity"])),
        ("Grype vulns (fixable)", "n/a" if g is None else sev_line(g["fixable"])),
        ("Dockle fatal/warn/info", "n/a" if k is None else
         f"{k['summary'].get('fatal', 0)}/{k['summary'].get('warn', 0)}/{k['summary'].get('info', 0)}"),
    ]


def print_table(headers: list[str], body: list[list[str]]) -> None:
    widths = [max(len(str(r[i])) for r in [headers] + body) for i in range(len(headers))]
    line = "+".join("-" * (w + 2) for w in widths)
    fmt = "|".join(f" {{:<{w}}} " for w in widths)
    print(line)
    print(fmt.format(*headers))
    print(line)
    for r in body:
        print(fmt.format(*r))
    print(line)


def main(argv: list[str]) -> int:
    if len(argv) >= 3 and argv[1] == "summary":
        s = summarize_dir(Path(argv[2]))
        print_table(["Check", Path(argv[2]).name], [list(r) for r in rows(s)])
        return 0
    if len(argv) >= 4 and argv[1] == "compare":
        before, after = summarize_dir(Path(argv[2])), summarize_dir(Path(argv[3]))
        body = [[a[0], a[1], b[1]] for a, b in zip(rows(before), rows(after))]
        print_table(["Check", "before (~/devsecops)", "after (hardened)"], body)
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
