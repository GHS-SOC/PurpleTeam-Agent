"""Several people can use one hosted instance without crossing each other.

The lab runs a single Cloud Run instance, because the run store is in-process.
One instance still serves many conversations at once, so every piece of shared
state has to be keyed by something that distinguishes them.

The bug this pins: `_focused_run` was one module-level variable, on the stated
assumption of "one conversation at a time". Hosting broke that assumption. Two
testers a minute apart, and whoever called a run-scoped tool last owned the
variable -- so the first one's report was written into the second one's folder,
overwriting it. The report is the deliverable, so that is data loss, not a
cosmetic mix-up.
"""

from __future__ import annotations

import json

import pytest

from purple_agent import config, tools, usage
from conftest import run_tool


class FakeSession:
    def __init__(self, sid):
        self.id = sid


class FakeCtx:
    """Stands in for ADK's ToolContext, which carries the session."""

    def __init__(self, sid):
        self.session = FakeSession(sid)


ALICE = FakeCtx("alice-session")
BOB = FakeCtx("bob-session")


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    usage._sessions.clear()
    usage._reports.clear()
    tools._RUNS.clear()

    async def accepted(log_type, logs, forwarder_id):
        return {}

    monkeypatch.setattr(tools.secops_rest, "import_logs", accepted)
    monkeypatch.setattr(tools.config, "FORWARDER_ID", "fwd-1", raising=False)
    yield
    tools._RUNS.clear()


def _build_and_ingest(ctx):
    from purple_agent.corpus import retrieve

    ids = [
        r.sigma_id
        for r in retrieve.search("mimikatz lsass", product="windows",
                                 category="process_access", limit=1)
    ]
    run = tools.start_run(tool_context=ctx)
    plan = tools.plan_events(ids)
    tools.build_events(run_id=run["run_id"], hostname=run["hostname"],
                       steps_json=json.dumps(plan["steps"]), sigma_ids=ids,
                       tool_context=ctx)
    run_tool(tools.ingest_run(run["run_id"], tool_context=ctx))
    return run["run_id"]


class TestTwoPeopleAtOnce:
    def test_each_session_keeps_its_own_focused_run(self):
        alice = _build_and_ingest(ALICE)
        bob = _build_and_ingest(BOB)

        assert alice != bob
        assert tools._run_to_persist("alice-session") == alice
        assert tools._run_to_persist("bob-session") == bob

    def test_a_report_lands_in_its_own_authors_folder(self):
        """The regression guard. With one global focus, Alice's report was
        written into Bob's folder and overwrote his."""
        alice = _build_and_ingest(ALICE)
        bob = _build_and_ingest(BOB)          # moves the old global focus to Bob

        usage.buffer_report("alice-session", "## Verdict\nALICE PASS")
        usage.buffer_report("bob-session", "## Verdict\nBOB FAIL")

        tools.save_run_report(ALICE)
        tools.save_run_report(BOB)

        assert (config.OUT_DIR / alice / "report.md").read_text(encoding="utf-8") \
            == "## Verdict\nALICE PASS"
        assert (config.OUT_DIR / bob / "report.md").read_text(encoding="utf-8") \
            == "## Verdict\nBOB FAIL"

    def test_interleaved_turns_do_not_steal_focus(self):
        """Realistic ordering: both build, then both verify, then both report."""
        alice = _build_and_ingest(ALICE)
        bob = _build_and_ingest(BOB)

        tools.verification_status(alice, tool_context=ALICE)
        tools.verification_status(bob, tool_context=BOB)
        tools.verification_status(alice, tool_context=ALICE)

        assert tools._run_to_persist("bob-session") == bob
        assert tools._run_to_persist("alice-session") == alice

    def test_one_persons_dry_run_does_not_silence_anothers_report(self):
        """A Stage-A-only turn writes nothing -- for its OWN session only."""
        alice = _build_and_ingest(ALICE)

        from purple_agent.corpus import retrieve
        ids = [r.sigma_id for r in retrieve.search("mimikatz", product="windows",
                                                   category="process_access", limit=1)]
        run = tools.start_run(tool_context=BOB)
        plan = tools.plan_events(ids)
        tools.build_events(run_id=run["run_id"], hostname=run["hostname"],
                           steps_json=json.dumps(plan["steps"]), sigma_ids=ids,
                           tool_context=BOB)

        assert tools._run_to_persist("bob-session") is None      # never ingested
        assert tools._run_to_persist("alice-session") == alice   # untouched


class TestRunStoreIsAlreadyPerRun:
    """_RUNS is keyed by run_id, so it never needed session scoping -- but say so
    in a test, because "one instance" invites the assumption that it did."""

    def test_two_sessions_runs_coexist(self):
        alice = _build_and_ingest(ALICE)
        bob = _build_and_ingest(BOB)
        assert {alice, bob} <= set(tools._RUNS)
        assert tools._RUNS[alice]["run"].run_id == alice
        assert tools._RUNS[bob]["run"].run_id == bob

    def test_ingest_targets_the_run_id_it_was_given(self):
        """No session state decides what gets ingested, so a busy instance can
        never send one person's events under another person's run."""
        alice = _build_and_ingest(ALICE)
        bob = _build_and_ingest(BOB)
        assert tools._RUNS[alice]["run"].hostname != tools._RUNS[bob]["run"].hostname


class TestModelSurfaceUnchanged:
    """tool_context is plumbing, injected by ADK. The model must never see it --
    if it leaks into a declaration the model starts inventing session ids."""

    @pytest.mark.parametrize("fn_name", [
        "start_run", "build_events", "ingest_run",
        "verification_status", "await_stage",
    ])
    def test_tool_context_is_hidden_from_the_model(self, fn_name):
        from google.adk.tools.function_tool import FunctionTool

        decl = FunctionTool(getattr(tools, fn_name))._get_declaration()
        schema = getattr(decl, "parameters_json_schema", None)
        if schema is None and decl.parameters is not None:
            schema = {"properties": decl.parameters.properties or {}}
        assert "tool_context" not in (schema or {}).get("properties", {})

    def test_run_scoped_tools_still_accept_a_context(self):
        """The other half: if ADK stops injecting it, every session silently
        collapses back onto one key and the bug returns."""
        import inspect

        for fn_name in ("start_run", "build_events", "ingest_run",
                        "verification_status", "await_stage"):
            params = inspect.signature(getattr(tools, fn_name)).parameters
            assert "tool_context" in params, f"{fn_name} lost its tool_context"
