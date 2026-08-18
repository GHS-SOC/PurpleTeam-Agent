"""Verification results are bounded before they enter the context window.

Regression for a context-length 400 (not MAX_TOKENS): a single udm_search at
maxEvents=100 is ~63k tokens of full UDM objects, and a few retries in history
exceed the 202,752-token window. The model needs event types, timestamps and
hostnames -- not whole UDM events -- so heavy results are projected down.

Since the move to the Chronicle REST transport the projections are applied inside
the tools in purple_agent.tools, not in the after-tool callback: those tools
return plain dicts, and trim_tool_result only ever unwrapped MCP-shaped
responses. The projection FUNCTIONS are unchanged and still live in
platform_core, so they are tested directly here, plus the size ceiling that
backstops anything they do not cover.
"""

from __future__ import annotations

import json

from purple_agent import platform_core as pc


class Tool:
    def __init__(self, name):
        self.name = name




class TestClampArgs:
    def test_udm_maxevents_capped(self):
        args = {"maxEvents": 100}
        pc.clamp_tool_args(Tool("udm_search"), args, None)
        assert args["maxEvents"] == pc.UDM_MAX_EVENTS

    def test_udm_maxevents_defaulted_when_absent(self):
        args = {"query": "x"}
        pc.clamp_tool_args(Tool("udm_search"), args, None)
        assert args["maxEvents"] == pc.UDM_MAX_EVENTS

    def test_small_request_is_left_alone(self):
        args = {"maxEvents": 5}
        pc.clamp_tool_args(Tool("udm_search"), args, None)
        assert args["maxEvents"] == 5

    def test_list_cases_pagesize_capped(self):
        args = {"pageSize": 500}
        pc.clamp_tool_args(Tool("list_cases"), args, None)
        assert args["pageSize"] == pc.LIST_PAGE_CAP

    def test_unrelated_tool_untouched(self):
        args = {"maxEvents": 100}
        pc.clamp_tool_args(Tool("get_case"), args, None)
        assert args["maxEvents"] == 100


class TestUdmProjection:
    def _big_event(self):
        return {
            "name": "projects/x/events/AAAA",
            "udm": {
                "metadata": {
                    "eventType": "PROCESS_OPEN", "productEventType": "10",
                    "eventTimestamp": "2026-08-02T22:00:00Z",
                    "logType": "WINDOWS_SYSMON", "junk": "z" * 2000,
                },
                "principal": {"hostname": "PT-LAB-A1B2C3D4.corp.local",
                              "process": {"file": {"fullPath": "C:\\x.exe"}}},
                "target": {"process": {"file": {"fullPath": "C:\\lsass.exe"}}},
                "noise": {"blob": "q" * 3000},
            },
        }

    def test_projection_shrinks_and_keeps_key_fields(self):
        raw = self._big_event()
        small = pc._project_udm_event(raw)
        assert len(json.dumps(small)) < len(json.dumps(raw)) / 10
        assert small["eventType"] == "PROCESS_OPEN"
        assert small["logType"] == "WINDOWS_SYSMON"
        assert small["eventTimestamp"] == "2026-08-02T22:00:00Z"

    def test_marker_hostname_survives_projection(self):
        """The marker is how a run is attributed. Losing it to a projection
        would make every verification look like someone else's data."""
        small = pc._project_udm_event(self._big_event())
        assert small["principalHostname"] == "PT-LAB-A1B2C3D4.corp.local"

    def test_empty_udm_result_is_safe(self):
        assert pc._project_udm_event({}) ["eventType"] is None


class TestCaseProjection:
    def test_cases_projected_to_report_fields(self):
        raw = {"name": "projects/x/locations/y/instances/z/cases/100000",
               "displayName": "Lab_Suspicious_Access_to_lsass_Process",
               "priority": "PRIORITY_MEDIUM", "stage": "Triage",
               "status": "OPENED", "createTime": "1786114710372",
               "alertCount": 1, "blob": "w" * 5000}
        small = pc._project_case(raw)
        assert small["caseId"] == "100000"
        assert small["status"] == "OPENED"
        assert "blob" not in small
        assert len(json.dumps(small)) < 400



class TestSizeCeiling:
    """The backstop for anything the projections do not cover."""

    def test_oversized_result_is_truncated_with_guidance(self):
        big = {"payload": "x" * (pc.RESULT_CEILING_CHARS + 5000)}
        out = pc.trim_tool_result(Tool("udm_search"), {}, None, big)
        assert out["truncated"] is True
        assert len(out["preview"]) <= pc.RESULT_CEILING_CHARS
        assert "Narrow the query" in out["instruction_to_model"]

    def test_compact_result_passes_through_untouched(self):
        assert pc.trim_tool_result(Tool("udm_search"), {}, None,
                                   {"event_count": 2}) is None

    def test_never_raises_on_garbage(self):
        for junk in (None, "text", 42, object()):
            pc.trim_tool_result(Tool("x"), {}, None, junk)
