"""await_stage collapses the Stage B poll loop into one call per stage.

The point is token cost: instead of polling verification_status turn by turn
(each a full model turn replaying the whole context), the model
calls await_stage once per stage and it blocks server-side until the stage is
due. These tests drive a virtual clock so nothing actually sleeps.
"""

from __future__ import annotations

import asyncio
import inspect
import time as real_time

import pytest

from purple_agent import tools
from conftest import run_tool


class VirtualClock:
    """time.time() reads a mutable now; sleeping advances it."""

    def __init__(self, start=1000.0):
        self.now = start

    def time(self):
        return self.now

    def sleep(self, d):
        self.now += d


@pytest.fixture
def clock(monkeypatch):
    clk = VirtualClock()
    fake_time = type("T", (), {"time": clk.time, "sleep": clk.sleep})()
    monkeypatch.setattr(tools, "time", fake_time)

    # await_stage yields with asyncio.sleep, not time.sleep, so that a waiting
    # session does not stall every other session sharing the event loop. The
    # virtual clock has to intercept that call instead, or these tests block for
    # the real five minutes.
    async def fake_sleep(d):
        clk.sleep(d)

    monkeypatch.setattr(
        tools, "asyncio", type("A", (), {"sleep": staticmethod(fake_sleep)})()
    )
    return clk


@pytest.fixture(autouse=True)
def clean_runs():
    tools._RUNS.clear()
    yield
    tools._RUNS.clear()


def ingest_at(clock, run_id="RUN"):
    tools._RUNS[run_id] = {"ingested_at": clock.now}
    return run_id


class TestBlockingWait:
    def test_parse_waits_to_threshold(self, clock):
        rid = ingest_at(clock)
        r = run_tool(tools.await_stage(rid, "parse"))
        assert r["due"] is True
        assert r["waited_seconds"] == tools._PARSE_CHECK_SECONDS
        assert r["parse_check_due"] is True

    def test_detections_after_parse_waits_only_the_remainder(self, clock):
        rid = ingest_at(clock)
        run_tool(tools.await_stage(rid, "parse"))            # advances clock to 120
        r = run_tool(tools.await_stage(rid, "detections"))   # 120 -> 300
        assert r["due"] is True
        assert r["waited_seconds"] == tools._DETECTION_CHECK_SECONDS - tools._PARSE_CHECK_SECONDS
        assert r["detection_and_case_check_due"] is True

    def test_already_due_returns_immediately(self, clock):
        rid = ingest_at(clock)
        clock.now += tools._VERDICT_FLOOR_SECONDS + 5   # everything already due
        r = run_tool(tools.await_stage(rid, "parse"))
        assert r["due"] is True
        assert r["waited_seconds"] == 0

    def test_aliases_map_to_detections(self, clock):
        rid = ingest_at(clock)
        for alias in ("detection", "cases", "DETECTIONS"):
            tools._RUNS[rid]["ingested_at"] = clock.now  # reset clock origin
            r = run_tool(tools.await_stage(rid, alias))
            assert r["due"] is True
            assert r["detection_and_case_check_due"] is True


class TestSkipAheadIsCapped:
    def test_verdict_from_t0_hits_the_cap(self, clock):
        rid = ingest_at(clock)
        r = run_tool(tools.await_stage(rid, "verdict"))   # needs 600s, cap is 300s
        assert r["due"] is False
        assert r["waited_seconds"] == tools._AWAIT_CAP_SECONDS
        assert "await_stage again" in r["next_step"]

    def test_never_blocks_longer_than_the_cap(self, clock):
        rid = ingest_at(clock)
        r = run_tool(tools.await_stage(rid, "verdict"))
        assert r["waited_seconds"] <= tools._AWAIT_CAP_SECONDS

    def test_repeated_calls_eventually_become_due(self, clock):
        rid = ingest_at(clock)
        r = run_tool(tools.await_stage(rid, "verdict"))
        while not r["due"]:
            r = run_tool(tools.await_stage(rid, "verdict"))
        assert r["verdict_allowed"] is True


class TestErrors:
    def test_unknown_stage(self, clock):
        rid = ingest_at(clock)
        r = run_tool(tools.await_stage(rid, "nope"))
        assert "error" in r
        assert "parse" in r["valid_stages"]

    def test_no_ingest_recorded(self, clock):
        r = run_tool(tools.await_stage("never-ingested", "parse"))
        assert "error" in r
        assert "record_ingest" in r["hint"]

    def test_does_not_raise_on_odd_input(self, clock):
        ingest_at(clock, "RUN")
        run_tool(tools.await_stage("RUN", ""))        # empty stage
        run_tool(tools.await_stage("RUN", "PARSE "))  # whitespace/case tolerated


class TestSharedReadiness:
    def test_status_and_await_agree(self, clock):
        """Both read the same _stage_readiness, so their verdicts can't drift."""
        rid = ingest_at(clock)
        clock.now += 330  # 5m30s: parse+detections due, verdict not
        status = tools.verification_status(rid)
        awaited = run_tool(tools.await_stage(rid, "parse"))   # already due, no wait
        for key in ("parse_check_due", "detection_and_case_check_due", "verdict_allowed"):
            assert status[key] == awaited[key]


class TestDoesNotStallTheEventLoop:
    """Waiting must not block the process, only the session doing the waiting.

    ADK invokes a synchronous tool inline on the event loop -- there is no
    thread pool (function_tool.py returns `target(**args)` directly when the
    target is not a coroutine). A blocking sleep in await_stage therefore
    freezes every other session sharing the process, and on a hosted deployment
    it also freezes the health endpoint: the platform reads that as a wedged
    container, restarts it, and the in-process run store dies mid-run, leaving
    the next ingest_run to report a run that "has no built events".
    """

    def test_the_waiting_tools_are_coroutines(self):
        for fn in (tools.await_stage, tools.ingest_run):
            assert inspect.iscoroutinefunction(fn), f"{fn.__name__} is not async"

    def test_other_work_overlaps_the_wait(self):
        """Deliberately real sleeps -- a virtual clock cannot show the stall.

        The run is set up one second short of the parse threshold, so await_stage
        genuinely sleeps ~1s instead of returning immediately.
        """
        rid = "REALCLOCK"
        tools._RUNS[rid] = {
            "ingested_at": real_time.time() - (tools._PARSE_CHECK_SECONDS - 1)
        }

        async def scenario():
            started = real_time.monotonic()

            async def other_session():
                for _ in range(5):
                    await asyncio.sleep(0.1)

            await asyncio.gather(tools.await_stage(rid, "parse"), other_session())
            return real_time.monotonic() - started

        elapsed = asyncio.run(scenario())
        # Overlapped: ~1.0s. Serialised behind a blocking sleep: ~1.5s.
        assert elapsed < 1.3, f"the wait stalled the event loop ({elapsed:.2f}s)"
