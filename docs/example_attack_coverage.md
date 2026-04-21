# ATT&CK Coverage

- Input file: `data/sample_cves_mixed.txt`
- ATT&CK source: `ctid-mappings-explorer`
- Mapping file: `data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json`
- Technique metadata file: `data/attack/attack_techniques_enterprise_16.1_subset.json`
- Mapped CVEs: 3
- Unmapped CVEs: 2
- Mapping type distribution: exploitation_technique: 3, primary_impact: 3, secondary_impact: 3
- Technique distribution: T1059: 2, T1068: 2, T1190: 2, T1003: 1, T1003.001: 1, T1005: 1, T1021: 1, T1033: 1, T1041: 1, T1053: 1, T1071.001: 1, T1082: 1, T1087.002: 1, T1105: 1, T1110: 1, T1112: 1, T1133: 1, T1136: 1, T1486: 1, T1531: 1, T1543: 1, T1570: 1
- Tactic distribution: discovery: 3, initial-access: 3, persistence: 3, command-and-control: 2, credential-access: 2, execution: 2, impact: 2, lateral-movement: 2, privilege-escalation: 2, collection: 1, defense-evasion: 1, exfiltration: 1

## Items

| CVE ID | Mapped | Relevance | Techniques | Tactics | Mapping Types |
| --- | --- | --- | --- | --- | --- |
| CVE-2020-1472 | Yes | High | T1087.002, T1133, T1021, T1110, T1486, T1068 | discovery, persistence, initial-access, lateral-movement, credential-access, impact, privilege-escalation | secondary_impact, primary_impact, exploitation_technique |
| CVE-2023-34362 | Yes | High | T1190, T1059, T1531, T1136, T1005, T1082, T1105 | initial-access, execution, impact, persistence, collection, discovery, command-and-control | exploitation_technique, primary_impact, secondary_impact |
| CVE-2024-4577 | Yes | High | T1190, T1059, T1112, T1053, T1543, T1033, T1068, T1071.001, T1570, T1003, T1003.001, T1041 | initial-access, execution, defense-evasion, persistence, privilege-escalation, discovery, command-and-control, lateral-movement, credential-access, exfiltration | exploitation_technique, primary_impact, secondary_impact |
| CVE-2023-44487 | No | Unmapped | N.A. | N.A. | N.A. |
| CVE-2024-3094 | No | Unmapped | N.A. | N.A. | N.A. |

## Warnings
- None
