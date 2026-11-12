# 🎯 VulnTriage

![CI](https://github.com/Taha2045/vulntriage/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**Risk-based vulnerability prioritization.** A scanner can return thousands of findings; CVSS alone
doesn't tell you what to patch first. VulnTriage ranks findings using *context*: exploit availability,
internet exposure and asset criticality - the same factors vulnerability-management teams (Qualys VMDR,
Tenable, Rapid7) use to cut through the noise.

## Scoring model

Weights add up to exactly 100, so there is no capping and findings stay distinguishable:

| Factor | Points |
|---|---|
| CVSS base score | up to **50** (CVSS / 10 x 50) |
| Public exploit available | **25** |
| Internet-facing asset | **15** |
| Asset criticality | critical 10 / high 7 / medium 4 / low 0 |

| Score | Priority | Suggested SLA |
|---|---|---|
| >= 80 | **P1** | 3 days |
| >= 60 | **P2** | 14 days |
| >= 40 | **P3** | 30 days |
| < 40 | **P4** | 90 days |

> Weights, thresholds and SLAs are sensible defaults, not a standard - adapt them to your organization's policy.

**Why it matters:** a CVSS 7.5 flaw that is internet-facing, exploitable and on a critical asset outranks
an isolated CVSS 9.8 on a low-value test box (covered by a unit test).

## Usage

```bash
python vulntriage.py samples/scan.csv                       # Markdown report
python vulntriage.py samples/scan.csv --top 5               # top 5 only
python vulntriage.py samples/scan.csv --format json -o out.json
python vulntriage.py samples/scan.csv --format csv  -o out.csv
```

Input CSV columns: `host, cve, title, cvss` (required) + `exploit_available, internet_facing, asset_criticality`
(optional, values `yes/no` and `critical/high/medium/low`). Export from your scanner and map the columns -
the parser is a single function (`load`) that is easy to adapt to a Qualys or Nessus export.

## Tests

```bash
python -m unittest discover -s tests -t . -v
```

## Roadmap

- [ ] Native Qualys / Nessus export parsers   - [ ] EPSS and CISA KEV enrichment   - [ ] HTML report

## License

MIT
