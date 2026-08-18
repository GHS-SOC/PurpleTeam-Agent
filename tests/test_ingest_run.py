"""Server-side ingest keeps event XML out of the model's output.

The bug this prevents: the model re-emitting kilobytes of generated XML into an
import_logs tool-call, exhausting the per-response token budget (MAX_TOKENS) and
truncating the call into malformed XML the parser silently drops.

ingest_run reads the XML from the run store and calls the Chronicle import
from Python. These tests pin that the payload never travels through the model:
build_events returns no XML, and ingest_run takes only a run_id.
"""

from __future__ import annotations

import json

import pytest

from purple_agent import platform_core, tools
from conftest import run_tool
from purple_agent.corpus import retrieve


@pytest.fixture
def built_run(monkeypatch):
    """A run that has been through build_events, with a fixed forwarder."""
    monkeypatch.setattr(platform_core.config, "FORWARDER_ID", "fwd-test-0001", raising=False)
    monkeypatch.setattr(tools.config, "FORWARDER_ID", "fwd-test-0001", raising=False)
    ids = [
        r.sigma_id
        for r in retrieve.search("mimikatz lsass", product="windows",
                                 category="process_access", limit=2)
    ]
    run = tools.start_run()
    plan = tools.plan_events(ids)
    tools.build_events(
        run_id=run["run_id"], hostname=run["hostname"],
        steps_json=json.dumps(plan["steps"]), sigma_ids=ids,
    )
    yield run["run_id"], run["hostname"]
    tools._RUNS.pop(run["run_id"], None)


@pytest.fixture
def capture_mcp(monkeypatch):
    """Record every import_logs and return a benign accepted response."""
    calls = []

    async def fake(log_type, logs, forwarder_id):
        calls.append({"logType": log_type, "logs": logs,
                      "forwarderId": forwarder_id})
        return {}  # import success = empty body

    monkeypatch.setattr(tools.secops_rest, "import_logs", fake)
    return calls


class TestNoXmlThroughTheModel:
    def test_build_events_returns_no_raw_xml(self, built_run):
        run_id, hostname = built_run
        # Rebuild to capture the return value directly.
        ids = [r.sigma_id for r in retrieve.search("mimikatz lsass", product="windows",
                                                    category="process_access", limit=2)]
        plan = tools.plan_events(ids)
        result = tools.build_events(run_id=run_id, hostname=hostname,
                                    steps_json=json.dumps(plan["steps"]), sigma_ids=ids)
        assert "groups" not in result
        blob = json.dumps(result)
        assert "<Event" not in blob, "raw event XML leaked into build_events output"

    def test_build_events_payload_is_small(self, built_run):
        """The regression guard. It was 8.6 KB with XML; must stay well under."""
        run_id, hostname = built_run
        ids = [r.sigma_id for r in retrieve.search("mimikatz lsass", product="windows",
                                                    category="process_access", limit=2)]
        plan = tools.plan_events(ids)
        result = tools.build_events(run_id=run_id, hostname=hostname,
                                    steps_json=json.dumps(plan["steps"]), sigma_ids=ids)
        assert len(json.dumps(result)) < 3072

    def test_ingest_run_takes_only_run_id(self):
        """Asserted against the DECLARATION, not the Python signature.

        What matters is the surface the model is offered: if it can pass logs or
        a forwarder id, it will eventually try, and a truncated XML argument is
        malformed XML the parser drops silently. `tool_context` is injected by
        ADK and never shown to the model, so it belongs in the signature and not
        in this assertion.
        """
        from google.adk.tools.function_tool import FunctionTool

        decl = FunctionTool(tools.ingest_run)._get_declaration()
        schema = getattr(decl, "parameters_json_schema", None)
        if schema is None and decl.parameters is not None:
            schema = {"properties": decl.parameters.properties or {}}
        assert list((schema or {}).get("properties", {})) == ["run_id"]

    def test_ingest_run_returns_no_xml(self, built_run, capture_mcp):
        run_id, _ = built_run
        result = run_tool(tools.ingest_run(run_id))
        assert "<Event" not in json.dumps(result)


class TestIngestRunBehaviour:
    def test_one_import_call_per_log_type(self, built_run, capture_mcp):
        run_id, _ = built_run
        groups = tools._RUNS[run_id]["groups"]
        run_tool(tools.ingest_run(run_id))
        assert len(capture_mcp) == len(groups)

    def test_import_carries_the_stored_xml(self, built_run, capture_mcp):
        run_id, _ = built_run
        groups = tools._RUNS[run_id]["groups"]
        run_tool(tools.ingest_run(run_id))
        sent = {c["logType"]: c["logs"] for c in capture_mcp}
        for log_type, logs in groups.items():
            assert sent[log_type] == logs
            assert all(x.startswith("<Event") for x in sent[log_type])

    def test_import_includes_the_forwarder(self, built_run, capture_mcp):
        """Tenant identity is no longer per-call: the REST path builds it into
        the URL from config, so the forwarder is the argument to check."""
        run_id, _ = built_run
        run_tool(tools.ingest_run(run_id))
        assert capture_mcp[0]["forwarderId"] == "fwd-test-0001"

    def test_starts_the_verification_clock(self, built_run, capture_mcp):
        run_id, _ = built_run
        assert "error" in tools.verification_status(run_id)  # not yet ingested
        run_tool(tools.ingest_run(run_id))
        status = tools.verification_status(run_id)
        assert "error" not in status
        assert status["elapsed_seconds"] >= 0


class TestIngestRunGuards:
    def test_unbuilt_run_errors(self, capture_mcp):
        result = run_tool(tools.ingest_run("NEVER-BUILT"))
        assert "error" in result
        assert not capture_mcp, "must not call import_logs for an unbuilt run"

    def test_refuses_a_run_marking_reported_unsafe(self, built_run, capture_mcp):
        """The actual enforcement of "unmarked synthetic data must never be
        ingested". build_events computing marking.safe_to_ingest and returning
        it as advisory text is not the same as ingest_run refusing to act on a
        False value -- this is the gate that makes it one."""
        run_id, _ = built_run
        tools._RUNS[run_id]["safe_to_ingest"] = False

        result = run_tool(tools.ingest_run(run_id))

        assert "error" in result
        assert not capture_mcp, "must not call import_logs for a run marked unsafe"

    def test_missing_forwarder_errors_before_calling(self, built_run, monkeypatch, capture_mcp):
        run_id, _ = built_run
        monkeypatch.setattr(tools.config, "FORWARDER_ID", "", raising=False)
        result = run_tool(tools.ingest_run(run_id))
        assert "error" in result and "FORWARDER_ID" in result["error"]
        assert not capture_mcp

    def test_transport_error_is_reported_not_swallowed(self, built_run, monkeypatch):
        run_id, _ = built_run

        async def failing(log_type, logs, forwarder_id):
            return {"error": "HTTP 503", "detail": "backend unavailable"}

        monkeypatch.setattr(tools.secops_rest, "import_logs", failing)
        result = run_tool(tools.ingest_run(run_id))
        assert "error" in result
        assert all(r["status"] == "error" for r in result["results"])


class TestModelSurface:
    """The log import is reachable, but never by the model directly.

    ingest_run takes a run_id and reads the XML from the run store. If the raw
    import were exposed instead, the model would have to carry kilobytes of event
    XML into a tool call -- exhausting the response budget, and truncating into
    malformed XML the parser drops in silence.
    """

    def test_the_raw_import_is_not_an_agent_tool(self):
        from purple_agent import agent

        names = {getattr(t, "__name__", "") for t in agent.root_agent.tools}
        assert "import_logs" not in names
        assert "ingest_run" in names

    def test_the_import_is_permitted_by_the_transport_guard(self):
        """Writing log DATA is allowed -- it is simply invoked from Python, not
        offered to the model. Only configuration writes are refused."""
        from purple_agent import secops_rest

        secops_rest._check("POST", "logTypes/WINDOWS_SYSMON/logs:import")
        with pytest.raises(secops_rest.ForbiddenRequest):
            secops_rest._check("POST", "rules")
