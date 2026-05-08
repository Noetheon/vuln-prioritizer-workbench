from __future__ import annotations

from app.api.errors import redact_request_safe_value
from vuln_prioritizer.security_redaction import (
    redact_text,
    redact_value,
    redacted_database_url,
    should_redact_string,
)


def test_redact_text_covers_container_posix_and_windows_paths_with_spaces() -> None:
    value = (
        'parser failed at "/app/workbench-reports/private report.json"; '
        "source=/home/alice/My Project/secret-cves.txt; "
        "workspace=/workspace/project/private report.json; "
        "service=/srv/workbench/imports/private report.json; "
        "opt=/opt/vpw/private report.json; "
        "state=/var/lib/vpw/private report.json; "
        r"mirror=C:\Users\Alice\My Project\secret-cves.txt; "
        "finding=/api/v1/findings/123; "
        "env=NVD_API_KEY"
    )

    redacted = redact_text(value)

    assert "/app/" not in redacted
    assert "/home/alice" not in redacted
    assert "/workspace/project" not in redacted
    assert "/srv/workbench" not in redacted
    assert "/opt/vpw" not in redacted
    assert "/var/lib/vpw" not in redacted
    assert r"C:\Users\Alice" not in redacted
    assert "My Project" not in redacted
    assert "private report.json" not in redacted
    assert redacted.count("[REDACTED-PATH]") == 7
    assert "finding=/api/v1/findings/123" in redacted
    assert "env=NVD_API_KEY" in redacted


def test_redact_value_and_api_error_projection_covers_embedded_container_paths() -> None:
    payload = {
        "nvd_api_key_env": "NVD_API_KEY",
        "detail": "failed while opening /app/workbench-import-uploads/input files/cves.txt",
        "source_path": "/app/workbench-reports/private report.json",
    }

    redacted, paths = redact_value(payload)
    api_safe = redact_request_safe_value(
        'Upload failed for "/app/workbench-import-uploads/input files/cves.txt".'
    )

    assert redacted["nvd_api_key_env"] == "NVD_API_KEY"
    assert redacted["detail"] == "[REDACTED]"
    assert redacted["source_path"] == "[REDACTED]"
    assert sorted(paths) == ["detail", "source_path"]
    assert "/app/" not in api_safe
    assert "input files" not in api_safe
    assert "[REDACTED-PATH]" in api_safe


def test_database_url_and_string_redaction_edge_cases() -> None:
    assert redacted_database_url("postgresql://user:secret@localhost:5432/db") == (
        "postgresql://user:***@localhost:5432/db"
    )
    assert redacted_database_url("postgresql://localhost/db") == "postgresql://localhost/db"
    assert redacted_database_url("postgresql://[broken") == "<set>"
    assert should_redact_string("") is False
    assert should_redact_string("/tmp/private.txt", redact_paths=False) is False
    assert should_redact_string("https://user:pass@example.test/path") is True
