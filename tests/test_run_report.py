"""report.md + usage.json are saved into the ingested run's folder.

The report is the model's final message. It must reach disk WITHOUT the model
re-emitting it (which would reinflate the response toward the token cap), so it
is captured in the after-model callback and written in the after-agent callback.
And it is saved only for runs that were actually ingested.
"""

from __future__ import annotations

import json

import pytest

from purple_agent import config, platform_core, tools, usage
from conftest import run_tool


class FakeContent:
    def __init__(self, text):
        class P:
            def __init__(self, t):
                self.text = t
        self.parts = [P(text)]


class FakeResp:
    def __init__(self, text=None, meta=None):
        self.content = FakeContent(text) if text is not None else None
        self.usage_metadata = meta


class FakeSession:
    def __init__(self, sid):
        self.id = sid


class FakeCtx:
    def __init__(self, sid):
        self.session = FakeSession(sid)


# Every test in this file models ONE conversation. The focused run is keyed by
# session, so the tools and save_run_report must agree on which one.
CTX = FakeCtx("s")


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    usage._sessions.clear()
    usage._reports.clear()
    tools._RUNS.clear()

    # secops_rest.import_logs is the only write; conftest blocks the transport.
    async def accepted(log_type, logs, forwarder_id):
        return {}  # import_logs success = empty body

    monkeypatch.setattr(tools.secops_rest, "import_logs", accepted)
    monkeypatch.setattr(tools.config, "FORWARDER_ID", "fwd-1", raising=False)
    yield
    tools._RUNS.clear()


def _ingested_run(ctx=None):
    """A run built and ingested by ONE conversation.

    Every tool takes the same context, because the focused run is per-session:
    a helper that focused under a different session than the one saving the
    report would test nothing at all.
    """
    from purple_agent.corpus import retrieve
    ids = [r.sigma_id for r in retrieve.search("mimikatz lsass", product="windows",
                                               category="process_access", limit=2)]
    run = tools.start_run(tool_context=ctx)
    plan = tools.plan_events(ids)
    tools.build_events(run_id=run["run_id"], hostname=run["hostname"],
                       steps_json=json.dumps(plan["steps"]), sigma_ids=ids,
                       tool_context=ctx)
    run_tool(tools.ingest_run(run["run_id"], tool_context=ctx))
    return run["run_id"]


class TestReportCapture:
    def test_model_text_is_buffered_not_required_from_the_model(self):
        platform_core.track_usage(FakeCtx("s"), FakeResp(text="## Verdict\nPASS"))
        assert usage.get_report("s") == "## Verdict\nPASS"

    def test_empty_text_does_not_clobber_a_buffered_report(self):
        platform_core.track_usage(FakeCtx("s"), FakeResp(text="real report"))
        platform_core.track_usage(FakeCtx("s"), FakeResp(text=None))       # tool-only turn
        platform_core.track_usage(FakeCtx("s"), FakeResp(text="   "))      # whitespace
        assert usage.get_report("s") == "real report"


class TestSavedForIngestedRuns:
    def test_report_and_usage_written_to_the_run_folder(self):
        run_id = _ingested_run(CTX)
        usage.record("s", type("M", (), {"prompt_token_count": 100,
                     "candidates_token_count": 20,
                     "cached_content_token_count": 0})(), config.MODEL)
        usage.buffer_report("s", "## Scenario\nx\n## Verdict\nPARTIAL")
        tools.save_run_report(FakeCtx("s"))

        folder = config.OUT_DIR / run_id
        assert (folder / "report.md").read_text(encoding="utf-8").startswith("## Scenario")
        saved = json.loads((folder / "usage.json").read_text(encoding="utf-8"))
        assert saved["total_tokens"] == 120

    def test_sits_beside_the_ingested_logs(self):
        run_id = _ingested_run(CTX)
        usage.buffer_report("s", "report body")
        tools.save_run_report(FakeCtx("s"))
        files = {p.name for p in (config.OUT_DIR / run_id).iterdir()}
        assert {"report.md", "usage.json", "events.json", "manifest.json"} <= files
        assert any(f.endswith(".xml") for f in files)

    def test_final_turn_overwrites_interim_report(self):
        run_id = _ingested_run(CTX)
        usage.buffer_report("s", "interim: ingested, waiting")
        tools.save_run_report(FakeCtx("s"))
        usage.buffer_report("s", "## Verdict\nFINAL")
        tools.save_run_report(FakeCtx("s"))
        assert (config.OUT_DIR / run_id / "report.md").read_text(encoding="utf-8") == "## Verdict\nFINAL"


class TestNotSavedForDryRuns:
    def test_stage_a_only_writes_no_report(self):
        from purple_agent.corpus import retrieve
        ids = [r.sigma_id for r in retrieve.search("mimikatz", product="windows",
                                                   category="process_access", limit=1)]
        run = tools.start_run(tool_context=CTX)
        plan = tools.plan_events(ids)
        tools.build_events(run_id=run["run_id"], hostname=run["hostname"],
                           steps_json=json.dumps(plan["steps"]), sigma_ids=ids,
                           tool_context=CTX)
        usage.buffer_report("s", "dry-run text")
        tools.save_run_report(FakeCtx("s"))
        assert not (config.OUT_DIR / run["run_id"] / "report.md").exists()

    def test_no_ingested_run_is_a_noop(self):
        # Must not raise and must find nothing to save.
        assert tools._run_to_persist("s") is None
        tools.save_run_report(FakeCtx("s"))


class TestArtefactsGoToTheRunTheTurnWorkedOn:
    """A turn's artefacts belong to the run that turn was about.

    Regression for a lost report. `save_run_report` targeted the most recently
    INGESTED run, which is a different question from "which run is this turn
    about". After a run was ingested and reported, a later Stage-A-only turn
    about a different rule was written into the first run's folder, replacing
    its report.md with text about the other run.
    """

    def _stage_a_only_run(self):
        from purple_agent.corpus import retrieve
        ids = [r.sigma_id for r in retrieve.search("mimikatz", product="windows",
                                                   category="process_access", limit=1)]
        run = tools.start_run(tool_context=CTX)
        plan = tools.plan_events(ids)
        tools.build_events(run_id=run["run_id"], hostname=run["hostname"],
                           steps_json=json.dumps(plan["steps"]), sigma_ids=ids,
                           tool_context=CTX)
        return run["run_id"]

    def test_a_later_dry_run_does_not_clobber_an_ingested_report(self):
        ingested = _ingested_run(CTX)
        usage.buffer_report("s", "## Verdict\nthe real report")
        tools.save_run_report(FakeCtx("s"))

        # A second turn, about a different run, that never reaches ingest.
        dry = self._stage_a_only_run()
        assert dry != ingested
        usage.buffer_report("s", "text about a completely different rule")
        tools.save_run_report(FakeCtx("s"))

        saved = (config.OUT_DIR / ingested / "report.md").read_text(encoding="utf-8")
        assert saved == "## Verdict\nthe real report"
        assert not (config.OUT_DIR / dry / "report.md").exists()

    def test_focus_follows_the_run_the_tools_were_called_on(self):
        first = _ingested_run(CTX)
        second = _ingested_run(CTX)
        assert tools._run_to_persist("s") == second

        # Touching the first run again moves focus back to it.
        tools.verification_status(first, tool_context=CTX)
        assert tools._run_to_persist("s") == first

    def test_an_unignested_focus_writes_nowhere_rather_than_elsewhere(self):
        _ingested_run(CTX)
        self._stage_a_only_run()
        assert tools._run_to_persist("s") is None


class TestReportBufferPrefersTheReport:
    """The model ends a turn with the structured report, then a short sign-off.
    Keeping the latest text saved the sign-off; an observed run left a 908-byte
    report.md holding a summary paragraph instead of the tables."""

    def test_the_longest_text_of_a_turn_wins(self):
        usage.buffer_report("s", "## Scenario\nfull structured report with tables")
        usage.buffer_report("s", "Done -- no rule covered it.")
        assert usage.get_report("s").startswith("## Scenario")

    def test_the_buffer_is_cleared_at_turn_end(self):
        run_id = _ingested_run(CTX)
        usage.buffer_report("s", "turn one, quite a long report indeed")
        tools.save_run_report(FakeCtx("s"))
        assert usage.get_report("s") == ""

        # A shorter report in a later turn must still win, which only works
        # because the buffer was cleared.
        usage.buffer_report("s", "## Verdict\nFINAL")
        tools.save_run_report(FakeCtx("s"))
        assert (config.OUT_DIR / run_id / "report.md").read_text(
            encoding="utf-8") == "## Verdict\nFINAL"

    def test_buffer_is_cleared_even_when_nothing_is_written(self):
        usage.buffer_report("s", "dry-run text")
        tools.save_run_report(FakeCtx("s"))     # no focused ingested run
        assert usage.get_report("s") == ""


class TestNeverRaises:
    def test_callback_swallows_errors(self, monkeypatch):
        _ingested_run(CTX)
        usage.buffer_report("s", "x")
        # Force a write failure; the callback must not propagate it.
        monkeypatch.setattr(tools.config, "OUT_DIR", config.OUT_DIR / "\0invalid")
        tools.save_run_report(FakeCtx("s"))  # should not raise
