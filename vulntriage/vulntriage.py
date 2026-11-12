#!/usr/bin/env python3
"""VulnTriage - risk-based vulnerability prioritization.

Reads a vulnerability scan export (CSV) and ranks findings by *real* risk rather than CVSS alone,
combining CVSS, exploit availability, internet exposure and asset criticality.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path

REQUIRED = {"host", "cve", "title", "cvss"}
# Weighted model, max total = 100 (no capping, so findings stay distinguishable)
W_CVSS, W_EXPLOIT, W_EXPOSED = 50, 25, 15
CRIT_POINTS = {"critical": 10, "high": 7, "medium": 4, "low": 0}
# (min_score, label, suggested SLA in days) - adjust to your organization's policy
PRIORITIES = [(80, "P1", 3), (60, "P2", 14), (40, "P3", 30), (0, "P4", 90)]
TRUE = {"yes", "y", "true", "1"}


@dataclass
class Vuln:
    host: str
    cve: str
    title: str
    cvss: float
    exploit: bool
    internet_facing: bool
    criticality: str
    score: float = 0.0
    priority: str = ""
    sla_days: int = 0


def calculate_score(cvss: float, exploit: bool, internet: bool, criticality: str) -> float:
    """Risk score 0-100.

    CVSS contributes up to 50 points, a public exploit 25, internet exposure 15 and
    asset criticality up to 10. Weights sum to 100, so no capping is needed.
    """
    if not 0 <= cvss <= 10:
        raise ValueError(f"CVSS out of range: {cvss}")
    score = (cvss / 10) * W_CVSS
    score += W_EXPLOIT if exploit else 0
    score += W_EXPOSED if internet else 0
    score += CRIT_POINTS.get(criticality, CRIT_POINTS["medium"])
    return round(score, 1)


def assign_priority(score: float) -> tuple[str, int]:
    for minimum, label, sla in PRIORITIES:
        if score >= minimum:
            return label, sla
    return "P4", 90


def load(path: Path) -> list[Vuln]:
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        missing = REQUIRED - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV is missing required columns: {', '.join(sorted(missing))}")
        out = []
        for n, row in enumerate(reader, start=2):
            try:
                v = Vuln(
                    host=row["host"].strip(), cve=row["cve"].strip(), title=row["title"].strip(),
                    cvss=float(row["cvss"]),
                    exploit=(row.get("exploit_available") or "").strip().lower() in TRUE,
                    internet_facing=(row.get("internet_facing") or "").strip().lower() in TRUE,
                    criticality=(row.get("asset_criticality") or "medium").strip().lower(),
                )
            except ValueError as e:
                print(f"warning: skipping line {n}: {e}", file=sys.stderr)
                continue
            v.score = calculate_score(v.cvss, v.exploit, v.internet_facing, v.criticality)
            v.priority, v.sla_days = assign_priority(v.score)
            out.append(v)
    return sorted(out, key=lambda v: (-v.score, v.host))


def to_markdown(vulns: list[Vuln], top: int) -> str:
    counts = Counter(v.priority for v in vulns)
    host_risk: dict[str, float] = defaultdict(float)
    for v in vulns:
        host_risk[v.host] += v.score
    lines = ["# Vulnerability Triage Report", "",
             f"Total findings: **{len(vulns)}**  |  "
             f"P1: {counts['P1']}  P2: {counts['P2']}  P3: {counts['P3']}  P4: {counts['P4']}", "",
             "> Score (0-100) = CVSS (50) + public exploit (25) + internet-facing (15) + asset criticality (10).",
             "> SLAs are suggestions - align them with your policy.", "",
             f"## Top {min(top, len(vulns))} findings", "",
             "| # | Priority | Score | Host | CVE | Title | CVSS | Exploit | Exposed | SLA |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for i, v in enumerate(vulns[:top], 1):
        lines.append(f"| {i} | **{v.priority}** | {v.score} | {v.host} | {v.cve} | {v.title} | {v.cvss} | "
                     f"{'yes' if v.exploit else 'no'} | {'yes' if v.internet_facing else 'no'} | {v.sla_days}d |")
    lines += ["", "## Riskiest hosts (sum of scores)", "", "| Host | Risk | Findings |", "|---|---|---|"]
    per_host = Counter(v.host for v in vulns)
    for host, risk in sorted(host_risk.items(), key=lambda kv: -kv[1])[:10]:
        lines.append(f"| {host} | {risk:.0f} | {per_host[host]} |")
    return "\n".join(lines)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Risk-based vulnerability prioritization")
    p.add_argument("input", type=Path, help="scan CSV (host,cve,title,cvss,exploit_available,internet_facing,asset_criticality)")
    p.add_argument("--top", type=int, default=15)
    p.add_argument("--format", choices=["md", "json", "csv"], default="md")
    p.add_argument("-o", "--output", type=Path)
    args = p.parse_args(argv)

    try:
        vulns = load(args.input)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.format == "json":
        text = json.dumps([asdict(v) for v in vulns], indent=2)
    elif args.format == "csv":
        import io
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=list(asdict(vulns[0]).keys()) if vulns else ["host"])
        w.writeheader()
        w.writerows(asdict(v) for v in vulns)
        text = buf.getvalue()
    else:
        text = to_markdown(vulns, args.top)

    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"Wrote {args.output} ({len(vulns)} findings)")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
