"""Stage B verification is time-gated.

Ingestion, rule evaluation and SOAR case creation settle at different speeds.
Querying a stage before it is due returns an empty result that is
indistinguishable from a real negative — which is how a coverage gap gets
reported that does not exist.

These tests pin the timeline so it cannot drift back to "poll and hope".
"""

from __future__ import annotations

import time

import pytest

from purple_agent import tools
from conftest import run_tool


@pytest.fixture
def run_id():
    rid = tools.start_run()["run_id"]
    yield rid
    tools._RUNS.pop(rid, None)


def age(run_id: str, seconds: int) -> None:
    """Pretend the ingest happened `seconds` ago."""
    tools._RUNS[run_id]["ingested_at"] = time.time() - seconds


class TestClockMustBeStarted:
    def test_status_without_ingest_is_an_error_not_a_default(self, run_id):
        """Silently assuming t=0 would let the agent verify a run it never
        ingested, and read the emptiness as a finding."""
        status = tools.verification_status(run_id)
        assert "error" in status
        assert "record_ingest" in status["hint"]

    def test_record_ingest_starts_the_clock(self, run_id):
        tools.record_ingest(run_id)
        assert tools.verification_status(run_id)["elapsed_seconds"] >= 0


class TestGating:
    @pytest.mark.parametrize(
        "elapsed,parse,detection,verdict",
        [
            (0,   False, False, False),
            (60,  False, False, False),
            (121, True,  False, False),   # parsing only
            (299, True,  False, False),   # still too early for detections
            (301, True,  True,  False),   # 5-minute mark
            (599, True,  True,  False),   # still no verdict
            (601, True,  True,  True),    # 10-minute floor
        ],
    )
    def test_stage_readiness(self, run_id, elapsed, parse, detection, verdict):
        tools.record_ingest(run_id)
        age(run_id, elapsed)
        status = tools.verification_status(run_id)
        assert status["parse_check_due"] is parse
        assert status["detection_and_case_check_due"] is detection
        assert status["verdict_allowed"] is verdict

    def test_cases_are_gated_at_five_minutes(self, run_id):
        """The specific requirement: no case/alert query before 5 minutes."""
        tools.record_ingest(run_id)
        age(run_id, 4 * 60)
        assert tools.verification_status(run_id)["detection_and_case_check_due"] is False
        age(run_id, 5 * 60 + 1)
        assert tools.verification_status(run_id)["detection_and_case_check_due"] is True

    def test_verdict_is_never_allowed_before_detections(self, run_id):
        """A verdict that outruns the evidence is the failure mode being
        prevented, so the floors must stay ordered."""
        assert tools._PARSE_CHECK_SECONDS < tools._DETECTION_CHECK_SECONDS
        assert tools._DETECTION_CHECK_SECONDS < tools._VERDICT_FLOOR_SECONDS


class TestGuidance:
    def test_next_step_warns_off_early_case_queries(self, run_id):
        tools.record_ingest(run_id)
        age(run_id, 150)  # parsing due, detections not
        step = tools.verification_status(run_id)["next_step"].lower()
        assert "do not" in step and "cases" in step

    def test_next_step_releases_the_verdict_at_the_end(self, run_id):
        tools.record_ingest(run_id)
        age(run_id, 700)
        assert "verdict may now be stated" in tools.verification_status(run_id)["next_step"]
