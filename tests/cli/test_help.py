from __future__ import annotations


def test_cli_analyze_help_lists_all_supported_formats(compact_output, format_help_block) -> None:
    help_block = compact_output(format_help_block("analyze"))

    assert "--format" in help_block
    assert "[markdown|json|sarif|table]" in help_block


def test_cli_compare_help_omits_sarif_format(compact_output, format_help_block) -> None:
    help_block = compact_output(format_help_block("compare"))

    assert "--format" in help_block
    assert "[markdown|json|table]" in help_block
    assert "[markdown|json|sarif|table]" not in help_block


def test_cli_doctor_help_lists_only_table_and_json_formats(
    compact_output,
    format_help_block,
) -> None:
    help_block = compact_output(format_help_block("doctor"))

    assert "--format" in help_block
    assert "[table|json]" in help_block
    assert "[markdown|json|sarif|table]" not in help_block


def test_cli_snapshot_create_help_lists_only_snapshot_export_formats(
    compact_output,
    format_help_block,
) -> None:
    help_block = compact_output(format_help_block("snapshot", "create"))

    assert "--format" in help_block
    assert "[json|markdown]" in help_block
    assert "[markdown|json|sarif|table]" not in help_block


def test_cli_data_status_help_lists_only_table_and_json_formats(
    compact_output,
    format_help_block,
) -> None:
    help_block = compact_output(format_help_block("data", "status"))

    assert "--format" in help_block
    assert "[table|json]" in help_block
    assert "--quiet" in help_block


def test_cli_data_update_help_lists_only_table_and_json_formats(
    compact_output,
    format_help_block,
) -> None:
    help_block = compact_output(format_help_block("data", "update"))

    assert "--format" in help_block
    assert "[table|json]" in help_block
    assert "--quiet" in help_block


def test_cli_data_verify_help_lists_only_table_and_json_formats(
    compact_output,
    format_help_block,
) -> None:
    help_block = compact_output(format_help_block("data", "verify"))

    assert "--format" in help_block
    assert "[table|json]" in help_block
    assert "--quiet" in help_block
