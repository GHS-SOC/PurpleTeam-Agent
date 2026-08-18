"""Regression cover for the endless `get_rule` loop.

Observed live on session 72927cf9. Stage B reached the detection check, found
`list_rule_detections` needs a ruleId with no bulk form, could not name a
candidate PowerShell rule, and fell back to inspecting the rule inventory one id
at a time -- cycling the same 18 ids every ~88 seconds indefinitely.

Two faults made it possible, and both are covered here:

1. `list_rules` fell through to the generic character ceiling, which truncates
   raw JSON mid-object. A 41,049-char listing cut to 8,000 showed the model 19
   of 100 rules with the id at the cut point sliced mid-string -- so it called
   get_rule on ids missing their final character and got "invalid rule_id".
2. Nothing anywhere counted repeated calls.
"""

from __future__ import annotations

import json

import pytest

from purple_agent import platform_core as pc, tools
from conftest import run_tool


class Tool:
    def __init__(self, name):
        self.name = name


class Ctx:
    """Stands in for ADK's tool_context, which carries the session."""

    def __init__(self, session_id="S1"):
        self.session = type("S", (), {"id": session_id})()


@pytest.fixture(autouse=True)
def clean_counters():
    pc._repeat_counts.clear()
    pc._tool_counts.clear()
    yield
    pc._repeat_counts.clear()
    pc._tool_counts.clear()


class TestRuleProjection:
    """Exercised through tools.list_rules, which is where projection now happens.

    The failure being prevented: a raw listing hit the character ceiling and was
    cut mid-object, slicing a rule id's final character. The model then called
    get_rule on the broken id, got 'invalid rule_id', and re-enumerated the same
    ids indefinitely. Projecting per rule means every id stays whole whatever the
    page size.
    """

    def _listing(self, count):
        return {"rules": [
            {
                "name": f"projects/p/locations/l/instances/i/rules/ru_{i:08d}-0000-0000-0000-00000000000{i%10}",
                "displayName": f"Lab_Rule_{i}",
                "severity": {"displayName": "High"},
                "type": "SINGLE_EVENT",
                "alertingEnabled": True,
                "text": "rule x {" + "y" * 4000 + "}",   # the bulk that used to blow the ceiling
            }
            for i in range(count)
        ]}

    def _run(self, count, monkeypatch):
        async def fake(page_size=100):
            return self._listing(count)
        monkeypatch.setattr(tools.secops_rest, "list_rules", fake)
        return run_tool(tools.list_rules(pageSize=count))

    def test_every_rule_survives_projection(self, monkeypatch):
        out = self._run(100, monkeypatch)
        assert out["rule_count"] == 100
        assert len(out["rules"]) == 100

    def test_no_rule_id_is_ever_truncated(self, monkeypatch):
        """The exact failure: ids sliced mid-string by the character ceiling."""
        for rule in self._run(100, monkeypatch)["rules"]:
            assert len(rule["ruleId"]) == 39, rule["ruleId"]
            assert rule["ruleId"].startswith("ru_")

    def test_yaral_text_is_dropped(self, monkeypatch):
        assert "yyyy" not in json.dumps(self._run(20, monkeypatch))

    def test_projection_is_far_smaller_than_the_raw_listing(self, monkeypatch):
        raw = json.dumps(self._listing(100))
        assert len(json.dumps(self._run(100, monkeypatch))) < len(raw) / 10

    def test_identity_fields_the_model_needs_are_kept(self, monkeypatch):
        rule = self._run(3, monkeypatch)["rules"][0]
        assert rule["displayName"] == "Lab_Rule_0"
        assert rule["severity"] == "High"


class TestLoopGuard:
    def test_identical_calls_are_blocked_on_the_limit(self):
        tool, ctx = Tool("get_rule"), Ctx()
        args = {"ruleId": "ru_abc"}
        for _ in range(pc.REPEAT_CALL_LIMIT - 1):
            assert pc.clamp_tool_args(tool, dict(args), ctx) is None
        blocked = pc.clamp_tool_args(tool, dict(args), ctx)
        assert blocked is not None
        assert blocked["error"] == "repeated call blocked"
        assert "STOP calling this tool" in blocked["instruction_to_model"]

    def test_different_arguments_are_not_blocked(self):
        tool, ctx = Tool("get_rule"), Ctx()
        for i in range(10):
            assert pc.clamp_tool_args(tool, {"ruleId": f"ru_{i}"}, ctx) is None

    def test_a_varying_cycle_still_trips_the_per_tool_ceiling(self):
        """The observed loop varied its ruleId, so repeats alone are not enough."""
        tool, ctx = Tool("get_rule"), Ctx()
        blocked = None
        for i in range(pc.PER_TOOL_CALL_LIMIT + 5):
            blocked = pc.clamp_tool_args(tool, {"ruleId": f"ru_{i}"}, ctx)
            if blocked:
                break
        assert blocked is not None
        assert "diminishing returns" in blocked["reason"]

    def test_sessions_are_counted_separately(self):
        tool = Tool("get_rule")
        args = {"ruleId": "ru_abc"}
        for _ in range(pc.REPEAT_CALL_LIMIT):
            pc.clamp_tool_args(tool, dict(args), Ctx("S1"))
        assert pc.clamp_tool_args(tool, dict(args), Ctx("S2")) is None

    def test_missing_tool_context_does_not_raise(self):
        assert pc.clamp_tool_args(Tool("udm_search"), {"maxEvents": 5}, None) is None

    def test_clamping_still_happens(self):
        args = {"maxEvents": 500}
        pc.clamp_tool_args(Tool("udm_search"), args, Ctx())
        assert args["maxEvents"] == pc.UDM_MAX_EVENTS


class TestListRulesArgHandling:
    def test_broken_filter_is_dropped(self):
        """Filtered calls return {} even when matching rules exist, which the
        model reads as 'no such rule'."""
        args = {"pageSize": 50, "filter": 'display_name:"PowerShell"'}
        pc.clamp_tool_args(Tool("list_rules"), args, Ctx())
        assert "filter" not in args

    def test_page_size_is_capped(self):
        args = {"pageSize": 1000}
        pc.clamp_tool_args(Tool("list_rules"), args, Ctx())
        assert args["pageSize"] == pc.RULE_PAGE_CAP
