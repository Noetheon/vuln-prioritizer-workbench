from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, precondition, rule
from utils.decision_scenarios import DecisionScenario
from utils.property_profiles import property_settings
from utils.workbench_env import create_workbench_api_env

pytestmark = pytest.mark.property


class DecisionHistoryMachine(RuleBasedStateMachine):
    """Compare generated public actions with an independent small lifecycle model."""

    def __init__(self) -> None:
        super().__init__()
        self.resources = ExitStack()
        try:
            root = Path(self.resources.enter_context(TemporaryDirectory(prefix="vpw-stateful-")))
            monkeypatch = self.resources.enter_context(pytest.MonkeyPatch.context())
            monkeypatch.setenv("WORKBENCH_FIXED_NOW", "2030-05-10T12:00:00+00:00")
            env, cleanup = create_workbench_api_env(database_path=root / "workbench.db")
            self.resources.callback(cleanup)
            self.scenario = DecisionScenario(env, root)
            self.original_run = self.scenario.import_rows(2)["id"]
            findings = self.scenario.findings()
            self.identities = {item["id"] for item in findings}
            self.selected = findings[0]["id"]
            self.peer = findings[1]["id"]
            self.original_findings = self.scenario.analysis_report(self.original_run)[0]["findings"]
            self.peer_score = self.scenario.detail(self.peer)["risk_score"]
            self.owner = "original-owner"
            self.exposure = "internal"
            self.waiver_id: str | None = None
            self.waived = False
        except BaseException:
            self.resources.close()
            raise

    @rule(
        owner=st.sampled_from(["owner-alpha", "owner-beta"]),
        exposure=st.sampled_from(["internal", "internet-facing"]),
    )
    def change_asset_and_reevaluate(self, owner: str, exposure: str) -> None:
        detail = self.scenario.detail(self.selected)
        response = self.scenario.env.client.patch(
            f"/api/v1/assets/{detail['asset_id']}",
            json={"owner": owner, "exposure": exposure},
        )
        assert response.status_code == 200, response.text
        self.scenario.evaluate([self.selected])
        self.owner, self.exposure = owner, exposure

    @rule()
    def reevaluate_without_new_observation(self) -> None:
        before = self.scenario.detail(self.selected)
        counts = self.scenario.revision_counts()
        self.scenario.evaluate([self.selected])
        after = self.scenario.detail(self.selected)
        assert after["last_seen_at"] == before["last_seen_at"]
        assert after["risk_score"] == before["risk_score"]
        assert self.scenario.revision_counts() == {
            **counts,
            self.selected: counts[self.selected] + 1,
        }

    @rule()
    def reimport_preserves_identity_and_current_context(self) -> None:
        run = self.scenario.import_rows(2, context=False)
        assert run["created_findings"] == 0
        assert run["updated_findings"] == 2

    @precondition(lambda self: self.waiver_id is None)
    @rule()
    def accept_risk_in_one_scope(self) -> None:
        response = self.scenario.env.client.post(
            f"/api/v1/projects/{self.scenario.project_id}/waivers/",
            json={
                "finding_id": self.selected,
                "owner": "risk-owner",
                "reason": "Generated scoped acceptance",
                "expires_at": "2099-12-31",
            },
        )
        assert response.status_code == 200, response.text
        self.waiver_id = response.json()["id"]
        self.waived = True

    @precondition(lambda self: self.waiver_id is not None and self.waived)
    @rule()
    def expire_acceptance(self) -> None:
        response = self.scenario.env.client.post(f"/api/v1/waivers/{self.waiver_id}/expire")
        assert response.status_code == 200, response.text
        self.waived = False

    @precondition(lambda self: self.waiver_id is not None)
    @rule()
    def remove_acceptance(self) -> None:
        response = self.scenario.env.client.delete(f"/api/v1/waivers/{self.waiver_id}")
        assert response.status_code == 204, response.text
        self.waiver_id = None
        self.waived = False

    @rule()
    def cancellation_then_retry_publishes_exactly_once(self) -> None:
        client = self.scenario.env.client
        counts = self.scenario.revision_counts()
        response = client.post(
            f"/api/v1/projects/{self.scenario.project_id}/evaluations",
            json={"finding_ids": [self.selected]},
        )
        assert response.status_code == 200, response.text
        queued = response.json()
        workflow_id = queued["workflow"]["id"]
        cancelled = client.post(f"/api/v1/workflows/{workflow_id}/cancel")
        assert cancelled.status_code == 200, cancelled.text
        self.scenario.drain()
        assert client.get(f"/api/v1/workflows/{workflow_id}").json()["status"] == "cancelled"
        assert self.scenario.revision_counts() == counts
        retry = client.post(f"/api/v1/workflows/{workflow_id}/retry")
        assert retry.status_code == 200, retry.text
        self.scenario.drain()
        retry_id = retry.json()["id"]
        assert retry_id != workflow_id
        assert client.get(f"/api/v1/workflows/{workflow_id}").json()["status"] == "cancelled"
        assert client.get(f"/api/v1/workflows/{retry_id}").json()["status"] == "succeeded"
        expected = {**counts, self.selected: counts[self.selected] + 1}
        assert self.scenario.revision_counts() == expected
        self.scenario.drain()
        assert self.scenario.revision_counts() == expected

    @invariant()
    def current_decisions_match_the_model_and_history_remains_recorded(self) -> None:
        assert {item["id"] for item in self.scenario.findings()} == self.identities
        current = self.scenario.detail(self.selected)
        peer = self.scenario.detail(self.peer)
        assert current["waived"] is self.waived
        observations = current["evidence"]["evaluation_input"]["observations"]
        assert all(item["asset_owner"] == self.owner for item in observations)
        assert all(item["asset_exposure"] == self.exposure for item in observations)
        assert peer["waived"] is False
        assert peer["risk_score"] == self.peer_score
        assert (
            self.scenario.analysis_report(self.original_run)[0]["findings"]
            == self.original_findings
        )

    def teardown(self) -> None:
        self.resources.close()


TestDecisionHistory = DecisionHistoryMachine.TestCase
TestDecisionHistory.settings = property_settings(stateful=True)
