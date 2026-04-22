from __future__ import annotations

from pathlib import Path

from vuln_prioritizer.inputs import InputLoader, InputSpec


def test_input_loader_load_many_applies_global_dedupe_and_max_cves(tmp_path: Path) -> None:
    first_input = tmp_path / "cves-a.txt"
    second_input = tmp_path / "cves-b.txt"
    first_input.write_text("CVE-2021-44228\nCVE-2024-3094\n", encoding="utf-8")
    second_input.write_text("CVE-2021-44228\nCVE-2023-44487\n", encoding="utf-8")

    parsed = InputLoader().load_many(
        [
            InputSpec(path=first_input, input_format="cve-list"),
            InputSpec(path=second_input, input_format="cve-list"),
        ],
        max_cves=2,
    )

    assert parsed.unique_cves == ["CVE-2021-44228", "CVE-2024-3094"]
    assert [item.cve_id for item in parsed.occurrences] == [
        "CVE-2021-44228",
        "CVE-2024-3094",
        "CVE-2021-44228",
    ]
    assert parsed.input_paths == [str(first_input), str(second_input)]
    assert parsed.merged_input_count == 2
    assert parsed.duplicate_cve_count == 1
    assert parsed.input_format == "cve-list"
    assert any("Applied --max-cves 2" in warning for warning in parsed.warnings)
