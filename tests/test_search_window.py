"""Verification searches must use a window the tool supplies, not one the model
derives.

Regression cover for a live failure on run 3928DBA7. The run generated a valid
Sysmon Event 10, the tenant parsed it, a rule fired, and SOAR opened a HIGH
case -- and the agent reported "no events found -> PARSER problem -> FAIL".

Root cause: UDM filters on the EVENT's own timestamp, and generated events are
backdated a few minutes (synth.scenario.new_scenario). The model derived a
startTime of 17:50:00Z from the run start; the event was stamped 17:49:05Z. It
missed its own event by 55 seconds. Detections carry the event's timestamp too,
so the same window hid the detection as well -- one slip, two false negatives.

The hostname half of that failure is already fixed upstream by the query ladder
(`marking.udm_query_ladder`, covered in test_marking.py). The window half is
independent of it: every rung of the ladder still returns nothing if the time
range excludes the event.
"""

from __future__ import annotations

import pytest

from purple_agent import tools
from conftest import run_tool


# The real numbers from run 3928DBA7.
INGESTED_AT = 1785952414.0                  # 2026-08-05T17:53:34Z
EVENT_STAMP = "2026-08-05T17:49:05Z"        # 4m29s earlier -- backdated
MODEL_CHOSE = "2026-08-05T17:50:00Z"        # what the agent picked, and lost with


@pytest.fixture(autouse=True)
def clean_runs():
    tools._RUNS.clear()
    yield
    tools._RUNS.clear()


class TestSearchWindow:
    def test_window_contains_a_backdated_event(self):
        w = tools._search_window(INGESTED_AT)
        assert w["startTime"] <= EVENT_STAMP <= w["endTime"]

    def test_window_starts_before_the_model_derived_one_that_failed(self):
        """The exact regression: the old window began after the event."""
        w = tools._search_window(INGESTED_AT)
        assert MODEL_CHOSE > EVENT_STAMP        # the bug, restated
        assert w["startTime"] < EVENT_STAMP     # the fix

    def test_padding_before_ingest_clears_backdating_without_reaching_a_prior_run(self):
        """This assertion used to read `>= 1800`, on the reasoning that a wide
        pad is free. It is not free on the way back. An hour of lead-in spans any
        earlier run in the same session, and a later run claimed one of those
        detections and reported PASS for a technique nothing had detected.

        The invariant is a range, not a floor: wide enough to cover this run's
        own backdated events, tight enough to exclude the previous run's.
        See tests/test_detection_attribution.py for the failure itself.
        """
        assert 180 < tools._SEARCH_PAD_BEFORE_SECONDS <= 900

    def test_window_brackets_the_ingest_moment(self):
        w = tools._search_window(INGESTED_AT)
        assert w["startTime"] < tools._iso(INGESTED_AT) < w["endTime"]

    def test_window_tells_the_model_not_to_compute_its_own(self):
        assert "Do NOT compute your own" in tools._search_window(INGESTED_AT)["note"]


class TestWindowIsAlwaysInFrontOfTheModel:
    """Every tool that reports run progress carries the window, so the model
    never has a turn where deriving one looks like the only option."""

    def test_record_ingest_returns_it(self):
        assert "search_window" in tools.record_ingest("R1")

    def test_verification_status_returns_it(self):
        tools.record_ingest("R1")
        assert "search_window" in tools.verification_status("R1")

    def test_await_stage_returns_it(self):
        tools._RUNS["R1"] = {"ingested_at": INGESTED_AT}   # long since due
        assert "search_window" in run_tool(tools.await_stage("R1", "parse"))
