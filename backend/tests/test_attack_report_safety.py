from __future__ import annotations

import re
from pathlib import Path

from vuln_prioritizer.models import (
    AnalysisContext,
    AttackMapping,
    AttackSummary,
    PrioritizedFinding,
)
from vuln_prioritizer.reporter import generate_markdown_report
from vuln_prioritizer.reporting_payloads import generate_summary_markdown

REPO_ROOT = Path(__file__).resolve().parents[2]

ATTACK_DEMO_ARTIFACTS = (
    "data/cve_attack_mappings.yml",
    "data/attack/local_curated_low_confidence_vpw058.yml",
    "docs/example_attack_report.md",
    "docs/example_attack_compare.md",
    "docs/example_attack_explain.json",
    "docs/examples/example_report.html",
    "docs/evidence/vpw-060-attack-navigator-layer.json",
)

FORBIDDEN_PROCEDURE_PATTERNS = {
    "proof-of-concept instructions": (
        r"\bproof[- ]of[- ]concept\b|\bpoc\s+(?:code|payload|exploit)\b"
    ),
    "payload assignment": r"\bpayload\s*[:=]",
    "copy-paste command": r"\bcopy and paste\b|\brun\s+(?:the|this)\s+(?:command|payload)\b",
    "shell download command": r"\b(?:curl|wget|nc|ncat)\s+https?://|\bpowershell\s+-|\bbash\s+-c\b",
    "weaponization guidance": r"\bweaponiz(?:e|ed|ation|ing)\b",
    "exploit recipe": r"\bexploit\s+(?:chain|steps|procedure|recipe|instructions?)\b",
    "step-by-step attack": r"\bstep[- ]by[- ]step\s+(?:exploit|attack|procedure|instructions?)\b",
    "active probing": r"\bactive probing\b|\bscan target\b",
}

UNSUPPORTED_EXPLOITATION_CLAIMS = (
    "known exploited in the wild",
    "exploitation observed",
    "was exploited",
    "confirmed attack path",
    "is proof that exploitation occurred",
)


def test_attack_demo_artifacts_do_not_include_procedure_guidance() -> None:
    failures: list[str] = []
    for relative_path in ATTACK_DEMO_ARTIFACTS:
        text = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
        for label, pattern in FORBIDDEN_PROCEDURE_PATTERNS.items():
            if re.search(pattern, text, flags=re.IGNORECASE):
                failures.append(f"{relative_path}: {label}")

    assert not failures, "Forbidden ATT&CK procedure wording found: " + ", ".join(failures)


def test_attack_markdown_report_keeps_non_kev_mapping_defensive() -> None:
    finding = PrioritizedFinding(
        cve_id="CVE-2026-0001",
        description="Reviewed demo CVE for defensive ATT&CK reporting.",
        cvss_base_score=7.5,
        cvss_severity="HIGH",
        epss=0.12,
        epss_percentile=0.7,
        in_kev=False,
        attack_mapped=True,
        attack_relevance="Medium",
        attack_techniques=["T1190"],
        attack_tactics=["initial-access"],
        attack_note="Reviewed source-backed defensive mapping for exposure review.",
        attack_mappings=[
            AttackMapping(
                capability_id="CVE-2026-0001",
                attack_object_id="T1190",
                attack_object_name="Exploit Public-Facing Application",
                mapping_type="detection_context",
                source="Curated defensive review",
                confidence="medium",
                review_status="reviewed",
                defensive_note="Defensive context only.",
                reviewer="security-review",
                reviewed_at="2026-04-29",
            )
        ],
        priority_label="Medium",
        priority_rank=3,
        rationale="NVD and EPSS place this finding in the medium queue.",
        recommended_action="Validate exposure and detection coverage.",
    )
    context = AnalysisContext(
        input_path="demo.txt",
        output_path="report.md",
        output_format="markdown",
        generated_at="2026-04-29T00:00:00+00:00",
        attack_enabled=True,
        attack_source="local-curated",
        attack_hits=1,
        total_input=1,
        valid_input=1,
        findings_count=1,
        nvd_hits=1,
        epss_hits=1,
        kev_hits=0,
        counts_by_priority={"Medium": 1},
        data_sources=["NVD", "EPSS", "local-curated ATT&CK"],
        attack_summary=AttackSummary(
            mapped_cves=1,
            unmapped_cves=0,
            mapping_type_distribution={"detection_context": 1},
            technique_distribution={"T1190": 1},
            tactic_distribution={"initial-access": 1},
        ),
    )

    report = generate_markdown_report([finding], context)
    lowered = report.lower()

    assert (
        "ATT&CK context is defensive context; it is not proof that exploitation occurred." in report
    )
    assert "Tactics describe objectives, techniques describe behavior categories" in report
    assert "Reported tactics and techniques are defensive review context" in report
    assert "Reviewed source-backed defensive mapping for exposure review." in report
    for claim in UNSUPPORTED_EXPLOITATION_CLAIMS:
        assert claim not in lowered


def test_workbench_summary_states_attack_safety_boundary() -> None:
    summary = generate_summary_markdown(
        {
            "metadata": {
                "input_path": "demo.txt",
                "input_format": "cve-list",
                "counts_by_priority": {"Critical": 0, "High": 0},
            },
            "attack_summary": {"mapped_cves": 1},
            "findings": [],
        }
    )

    assert (
        "- ATT&CK safety: defensive context only; not proof that exploitation occurred "
        "or procedure guidance."
    ) in summary
