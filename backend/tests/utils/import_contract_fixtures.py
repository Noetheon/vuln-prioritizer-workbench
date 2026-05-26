from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_ROOT = PROJECT_ROOT / "data"
INPUT_FIXTURES_ROOT = DATA_ROOT / "input_fixtures"
ATTACK_ARTIFACT_ROOT = DATA_ROOT / "attack"

SAMPLE_CVES = DATA_ROOT / "sample_cves.txt"
TRIVY_REPORT = INPUT_FIXTURES_ROOT / "trivy_report.json"
OPENVEX = INPUT_FIXTURES_ROOT / "openvex_statements.json"
CYCLONEDX_VEX = INPUT_FIXTURES_ROOT / "cyclonedx_vex.json"
ATTACK_MAPPING = ATTACK_ARTIFACT_ROOT / "local_curated_low_confidence_vpw058.yml"


def cve_list_payload(*cves: str) -> bytes:
    return ("\n".join(cves) + "\n").encode()


def generic_occurrence_csv(*rows: str) -> bytes:
    return ("\n".join(rows) + "\n").encode()


def fixture_bytes(path: Path) -> bytes:
    return path.read_bytes()
