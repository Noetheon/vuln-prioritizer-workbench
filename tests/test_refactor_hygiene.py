from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _imported_modules(path: str) -> set[str]:
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def test_workbench_web_routes_do_not_import_api_routes_private_helpers() -> None:
    imports = _imported_modules("src/vuln_prioritizer/web/routes.py")

    assert "vuln_prioritizer.api.routes" not in imports
    assert "vuln_prioritizer.api.workbench_support" in imports


def test_workbench_support_does_not_reexport_from_api_routes() -> None:
    imports = _imported_modules("src/vuln_prioritizer/api/workbench_support.py")

    assert "vuln_prioritizer.api.routes" not in imports
    assert {
        "vuln_prioritizer.api.workbench_detection",
        "vuln_prioritizer.api.workbench_findings",
        "vuln_prioritizer.api.workbench_providers",
        "vuln_prioritizer.api.workbench_uploads",
        "vuln_prioritizer.api.workbench_waivers",
    }.issubset(imports)


def test_workbench_analysis_uses_cli_independent_analysis_service() -> None:
    imports = _imported_modules("src/vuln_prioritizer/services/workbench_analysis.py")

    assert "vuln_prioritizer.cli_support.analysis" not in imports
    assert "vuln_prioritizer.services.analysis" in imports


def test_reporter_facade_reexports_private_reporting_renderers() -> None:
    imports = _imported_modules("src/vuln_prioritizer/reporter.py")

    assert "vuln_prioritizer.reporting_html" in imports
    assert "vuln_prioritizer.reporting_markdown" in imports
    assert "vuln_prioritizer.reporting_snapshot" in imports
    assert "vuln_prioritizer.reporting_state" in imports


def test_workbench_repository_uses_artifact_mixin_boundary() -> None:
    imports = _imported_modules("src/vuln_prioritizer/db/repositories.py")
    tree = ast.parse((ROOT / "src/vuln_prioritizer/db/repositories.py").read_text())
    classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
    repository = classes["WorkbenchRepository"]
    base_names = {base.id for base in repository.bases if isinstance(base, ast.Name)}

    assert "vuln_prioritizer.db.repository_assets" in imports
    assert "vuln_prioritizer.db.repository_artifacts" in imports
    assert "vuln_prioritizer.db.repository_providers" in imports
    assert {
        "ArtifactRepositoryMixin",
        "AssetWaiverRepositoryMixin",
        "ProviderSnapshotRepositoryMixin",
    }.issubset(base_names)


def test_models_facade_reexports_focused_model_modules() -> None:
    imports = _imported_modules("src/vuln_prioritizer/models.py")

    assert "vuln_prioritizer.model_base" in imports
    assert "vuln_prioritizer.models_artifacts" in imports
    assert "vuln_prioritizer.models_attack" in imports
    assert "vuln_prioritizer.models_input" in imports
    assert "vuln_prioritizer.models_provider" in imports
    assert "vuln_prioritizer.models_remediation" in imports
    assert "vuln_prioritizer.models_state" in imports
    assert "vuln_prioritizer.models_waivers" in imports


def test_dependency_audit_requirements_include_dev_gate_tools() -> None:
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    package_names = {line.split(">", 1)[0].split("[", 1)[0] for line in requirements if line}

    assert {"mkdocs", "playwright", "pytest-cov"}.issubset(package_names)


def test_sdist_manifest_excludes_partial_test_tree() -> None:
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")

    assert "prune tests" in manifest
