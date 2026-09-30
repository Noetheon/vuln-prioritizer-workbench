"""Negative controls for the agent-guidance drift check."""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "agent_skills_check", REPO / "scripts/check_agent_skills.py"
)
assert SPEC and SPEC.loader
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class GuidanceChecks(unittest.TestCase):
    """Exercise drift on isolated files instead of the user's working tree."""

    def setUp(self) -> None:
        """Build a minimal checkout with valid discovery and runner contracts."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for path in (".agents/skills", ".claude/skills", "frontend", "docs"):
            (self.root / path).mkdir(parents=True)
        (self.root / "AGENTS.md").write_text("[State](docs/state.md)\nRun `make check`.\n")
        (self.root / "CLAUDE.md").write_text("@AGENTS.md\n")
        (self.root / ".agents/MAINTENANCE.md").write_text("Owned by the project maintainer.\n")
        (self.root / "docs/state.md").write_text("Current scope.\n")
        (self.root / "Makefile").write_text("check:\n\t@true\n")
        (self.root / "frontend/package.json").write_text(
            json.dumps(
                {"scripts": {"test": "playwright test", "test:unit": "node --test tests/*.test.ts"}}
            )
        )
        self.skill = self.root / ".agents/skills/vpw-example/SKILL.md"
        self.skill.parent.mkdir()
        self.skill.write_text("---\nname: vpw-example\ndescription: Review VPW examples.\n---\n")
        self.assertEqual(CHECKER.check(self.root, sync_claude=True), [])

    def test_valid_guidance_is_read_only(self) -> None:
        """A check must not silently repair or rewrite the user's instructions."""
        before = {
            p.relative_to(self.root): p.read_bytes() for p in self.root.rglob("*") if p.is_file()
        }
        self.assertEqual(CHECKER.check(self.root), [])
        after = {
            p.relative_to(self.root): p.read_bytes() for p in self.root.rglob("*") if p.is_file()
        }
        self.assertEqual(before, after)

    def test_removed_reference_is_detected(self) -> None:
        """Catch the stale-path failure seen in the original installed skills."""
        (self.root / "docs/state.md").unlink()
        self.assertTrue(any("broken local reference" in e for e in CHECKER.check(self.root)))

    def test_removed_make_target_is_detected(self) -> None:
        """Reject commands whose implementation was removed."""
        (self.root / "Makefile").write_text("replacement:\n\t@true\n")
        self.assertTrue(any("unknown Make target check" in e for e in CHECKER.check(self.root)))

    def test_runner_change_is_detected(self) -> None:
        """A browser runner cannot silently replace the documented unit runner."""
        (self.root / "frontend/package.json").write_text(
            json.dumps({"scripts": {"test": "playwright test", "test:unit": "playwright test"}})
        )
        self.assertTrue(any("test:unit: runner changed" in e for e in CHECKER.check(self.root)))

    def test_description_change_requires_loader_refresh(self) -> None:
        """Keep both agents' discovery metadata tied to the same source."""
        self.skill.write_text(
            self.skill.read_text().replace("Review VPW examples.", "Review VPW fixtures.")
        )
        self.assertTrue(any("loader drift" in e for e in CHECKER.check(self.root)))
        self.assertEqual(CHECKER.check(self.root, sync_claude=True), [])

    def test_renamed_skill_does_not_leave_a_silent_old_loader(self) -> None:
        """Retired skills must not remain discoverable through an old loader."""
        shutil.rmtree(self.skill.parent)
        self.assertTrue(any("orphaned project loader" in e for e in CHECKER.check(self.root)))

    def test_invalid_metadata_is_detected(self) -> None:
        """A body without discovery fields is not an installable skill."""
        self.skill.write_text("Instructions without discovery metadata.\n")
        self.assertTrue(any("missing YAML frontmatter" in e for e in CHECKER.check(self.root)))

    def test_ordinary_prose_is_not_a_make_command(self) -> None:
        """Avoid blocking a valid instruction that happens to use the verb make."""
        (self.root / "AGENTS.md").write_text("Beta does not make local data disposable.\n")
        self.assertEqual(CHECKER.check(self.root), [])


if __name__ == "__main__":
    unittest.main()
