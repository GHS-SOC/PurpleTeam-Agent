"""Per-session LLM token accounting and the token_usage report tool."""

from __future__ import annotations

import pytest

from purple_agent import platform_core, tools, usage


class FakeMeta:
    def __init__(self, prompt=0, candidates=0, cached=0):
        self.prompt_token_count = prompt
        self.candidates_token_count = candidates
        self.cached_content_token_count = cached


class FakeSession:
    def __init__(self, sid):
        self.id = sid


class FakeToolContext:
    def __init__(self, sid):
        self.session = FakeSession(sid)


GLM = "openrouter/z-ai/glm-4.7-flash"


@pytest.fixture(autouse=True)
def clean_sessions():
    usage._sessions.clear()
    yield
    usage._sessions.clear()


class TestAccounting:
    def test_accumulates_across_calls(self):
        usage.record("s1", FakeMeta(100, 40, 8), GLM)
        usage.record("s1", FakeMeta(50, 20, 0), GLM)
        snap = usage.snapshot("s1")
        assert snap.calls == 2
        assert snap.prompt_tokens == 150
        assert snap.completion_tokens == 60
        assert snap.cached_tokens == 8
        assert snap.total_tokens == 210

    def test_sessions_are_isolated(self):
        usage.record("a", FakeMeta(100, 10), GLM)
        assert usage.snapshot("b").total_tokens == 0

    def test_snapshot_of_unused_session_is_zero(self):
        snap = usage.snapshot("never")
        assert snap.calls == 0 and snap.total_tokens == 0

    def test_none_token_fields_are_tolerated(self):
        usage.record("s", FakeMeta(None, None, None), GLM)
        assert usage.snapshot("s").total_tokens == 0

    def test_reset_forgets_a_session(self):
        usage.record("s", FakeMeta(10, 10), GLM)
        usage.reset("s")
        assert usage.snapshot("s").total_tokens == 0


class TestCost:
    def test_known_model_has_a_cost(self):
        usage.record("s", FakeMeta(1_000_000, 1_000_000), GLM)
        cost = usage.snapshot("s").cost_usd
        assert cost == pytest.approx(0.06 + 0.40)  # 6e-8 + 4e-7 per token

    def test_unknown_model_reports_no_cost(self):
        """A swapped-in model must not show a confidently wrong dollar figure."""
        usage.record("s", FakeMeta(1000, 1000), "some/other-model")
        assert usage.snapshot("s").cost_usd is None
        assert "cost n/a" in usage.snapshot("s").format()


class TestTrackUsageCallback:
    class Ctx:
        def __init__(self, sid):
            self.session = FakeSession(sid)

    class Resp:
        def __init__(self, meta):
            self.usage_metadata = meta

    def test_callback_records_and_returns_none(self):
        out = platform_core.track_usage(self.Ctx("cb"), self.Resp(FakeMeta(30, 5)))
        assert out is None  # never overrides the response
        assert usage.snapshot("cb").prompt_tokens == 30

    def test_missing_metadata_is_a_noop(self):
        platform_core.track_usage(self.Ctx("cb"), self.Resp(None))
        assert usage.snapshot("cb").calls == 0


class TestTokenUsageTool:
    def test_reads_the_calling_session(self):
        usage.record("live", FakeMeta(200, 90, 4), GLM)
        result = tools.token_usage(FakeToolContext("live"))
        assert result["llm_calls"] == 1
        assert result["total_tokens"] == 290
        assert result["estimated_cost_usd"] is not None
        assert "note" in result

    def test_zeroed_before_any_call(self):
        result = tools.token_usage(FakeToolContext("fresh"))
        assert result["total_tokens"] == 0
