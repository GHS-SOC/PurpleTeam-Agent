"""Per-session LLM token and cost accounting.

Token usage is inherently per-session: each request to the provider is stateless,
and what gets billed on a turn is the system instruction plus the tool schemas
plus that session's own conversation history. Nothing accumulates server-side.
This module makes the running local total visible, which is otherwise invisible
until the bill arrives.

Adapted from SampleV2/secops_agent/usage.py -- the accounting is model-agnostic;
only the pricing table is specific to the configured model.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

# USD per token. Source: the provider's model pricing (OpenRouter `pricing`
# object). Only models with an entry get a cost estimate; anything else reports
# "cost n/a" rather than a confidently wrong number.
PRICING = {
    "openrouter/z-ai/glm-4.7-flash": {"prompt": 6e-8, "completion": 4e-7},
}


@dataclass
class SessionUsage:
    """Running LLM totals for one session."""

    model: str = ""
    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cached_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    @property
    def cost_usd(self) -> float | None:
        """Estimated spend, or None when the model has no pricing entry."""
        rates = PRICING.get(self.model)
        if rates is None:
            return None
        return (
            self.prompt_tokens * rates["prompt"]
            + self.completion_tokens * rates["completion"]
        )

    def format(self) -> str:
        """One-line summary, e.g. '7 calls · 38,204 in / 1,102 out · ~$0.0027'."""
        parts = [
            f"{self.calls} call{'s' if self.calls != 1 else ''}",
            f"{self.prompt_tokens:,} in / {self.completion_tokens:,} out",
        ]
        if self.cached_tokens:
            parts.append(f"{self.cached_tokens:,} cached")
        cost = self.cost_usd
        parts.append(f"~${cost:.4f}" if cost is not None else "cost n/a")
        return " · ".join(parts)

    def to_dict(self) -> dict:
        cost = self.cost_usd
        return {
            "model": self.model,
            "llm_calls": self.calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "cached_tokens": self.cached_tokens,
            "total_tokens": self.total_tokens,
            "estimated_cost_usd": round(cost, 6) if cost is not None else None,
            "summary": self.format(),
        }


_sessions: dict[str, SessionUsage] = {}
# adk web serves concurrent requests, so the table needs guarding.
_lock = threading.Lock()

# The current turn's most substantial model text per session. The agent's report
# is captured here from the after-model callback so it can be written to disk
# after the turn WITHOUT the model re-emitting it (which would reinflate the
# response and risk the very token cap we designed around).
#
# Cleared at the end of each turn by the after-agent callback, so "this turn"
# really means this turn -- see buffer_report for why that matters.
_reports: dict[str, str] = {}


def buffer_report(session_id: str, text: str) -> None:
    """Keep the most substantial model text seen so far this turn.

    Longest wins, not latest. A turn typically ends with the structured report
    followed by a one-line sign-off ("Done -- no rule covered this behaviour."),
    and keeping the latest saved the sign-off over the report: an observed run
    left a 908-byte report.md holding a summary paragraph instead of the
    Scenario/Oracle/Verdict tables.

    Across turns the later report must still win, which is what makes clearing
    the buffer at turn end part of this contract rather than housekeeping.
    """
    if not text or not text.strip():
        return
    with _lock:
        current = _reports.get(session_id, "")
        if len(text.strip()) > len(current.strip()):
            _reports[session_id] = text


def get_report(session_id: str) -> str:
    """The buffered model text for the current turn, or ''."""
    with _lock:
        return _reports.get(session_id, "")


def clear_report(session_id: str) -> None:
    """Drop the buffered text. Called at turn end so the next turn starts clean."""
    with _lock:
        _reports.pop(session_id, None)


def record(session_id: str, usage_metadata, model: str) -> SessionUsage:
    """Add one model call's usage to a session's totals and return a copy."""
    with _lock:
        totals = _sessions.setdefault(session_id, SessionUsage(model=model))
        if not totals.model:
            totals.model = model
        totals.calls += 1
        totals.prompt_tokens += getattr(usage_metadata, "prompt_token_count", 0) or 0
        totals.completion_tokens += (
            getattr(usage_metadata, "candidates_token_count", 0) or 0
        )
        totals.cached_tokens += (
            getattr(usage_metadata, "cached_content_token_count", 0) or 0
        )
        return SessionUsage(**vars(totals))


def snapshot(session_id: str) -> SessionUsage:
    """Current totals for a session; zeroed if it has made no calls yet."""
    with _lock:
        totals = _sessions.get(session_id)
        return SessionUsage(**vars(totals)) if totals else SessionUsage()


def reset(session_id: str) -> None:
    """Forget a session's totals and buffered report."""
    with _lock:
        _sessions.pop(session_id, None)
        _reports.pop(session_id, None)
