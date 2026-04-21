# Executive Summary

## Problem

Security teams usually face more known vulnerabilities than they can remediate immediately. A CVSS-only ranking is too limited for operational decision-making.

## Approach

`vuln-prioritizer` combines four signals:

- technical severity from NVD/CVSS
- exploitation probability from FIRST EPSS
- known real-world exploitation from CISA KEV
- adversary-behavior and impact context from CTID/MITRE ATT&CK mappings

## Benefit

- better remediation sequencing for patching and mitigation
- clearer escalation material for management and CISO audiences
- visible separation between mapped and unmapped risk context
- deterministic, evidence-based outputs suitable for demos and evaluation

## Output

The tool now provides:

- prioritized terminal output
- Markdown and JSON reports
- `CVSS-only` vs enriched comparison output
- mapped-CVE ATT&CK context in `explain`
- ATT&CK coverage summaries
- ATT&CK Navigator layer export
