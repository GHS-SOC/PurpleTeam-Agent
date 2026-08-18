"""Offline mode lets Stage A run with no tenant, without opening a hole.

`require_live_tools` normally refuses to start the agent when SecOps is
unreachable, so that a model cannot be asked a SOC question it has no data
for and answer anyway. That gate also made it impossible to try Stage A --
which touches no tenant at all -- without a configured tenant.

PURPLE_OFFLINE=1 skips the gate and moves the enforcement to
`secops_rest.call`, the single function every Chronicle operation goes
through. The property to protect is that this trade is not a weakening: in
offline mode Stage B must be *impossible*, not merely awkward, and every
attempt must produce an explicit error the model has to report.
"""

from __future__ import annotations

import httpx
import pytest

from purple_agent import config, platform_core, secops_rest
from conftest import run_tool

# Captured at import, before conftest's autouse no_live_tenant_calls fixture
# replaces it. These tests have to exercise the REAL secops_rest.call, because
# the refusal being tested lives inside it -- stubbing it would test the stub.
_REAL_CALL = secops_rest.call


@pytest.fixture
def offline(monkeypatch):
    monkeypatch.setattr(config, "OFFLINE", True)
    monkeypatch.setattr(secops_rest.config, "OFFLINE", True, raising=False)
    monkeypatch.setattr(platform_core.config, "OFFLINE", True, raising=False)

    # Put the real implementation back, then take the network away underneath
    # it. conftest blocks the tenant by stubbing `call`; that protection is
    # replaced here rather than dropped, one layer lower. If offline mode ever
    # stops short-circuiting, these tests fail on a refused connection instead
    # of quietly writing to a production SIEM -- the incident conftest exists
    # for in the first place.
    monkeypatch.setattr(secops_rest, "call", _REAL_CALL)

    def no_network(*_args, **_kwargs):
        raise AssertionError(
            "offline mode let a request reach the network -- it must return "
            "before any client is constructed")

    monkeypatch.setattr(httpx, "AsyncClient", no_network)


class TestOfflineLetsTheAgentStart:
    def test_health_gate_does_not_block(self, offline):
        """The whole point: `adk run` works with no tenant configured."""
        class Ctx:
            agent_name = "purple_team_agent"

        assert run_tool(platform_core.require_live_tools(Ctx())) is None

    def test_gate_does_not_even_probe(self, offline, monkeypatch):
        """A probe would still cost a credential lookup and a timeout on a
        machine with no tenant -- the slow first response the gate's own
        docstring warns about."""
        async def explode():
            raise AssertionError("offline mode must not probe SecOps")

        monkeypatch.setattr(secops_rest, "health", explode)

        class Ctx:
            agent_name = "purple_team_agent"

        assert run_tool(platform_core.require_live_tools(Ctx())) is None


class TestOfflineMakesStageBImpossible:
    """The gate is skipped, so this is now the only thing standing between the
    model and a fabricated detection result. It has to hold for every
    operation, not just the log import."""

    @pytest.mark.parametrize("method,path", [
        ("GET", ":udmSearch"),
        ("GET", "rules"),
        ("GET", "cases"),
        ("GET", "legacy:legacySearchDetections"),
        ("POST", "logTypes/WINDOWS_SYSMON/logs:import"),
    ])
    def test_every_chronicle_call_is_refused(self, offline, method, path):
        result = run_tool(secops_rest.call(method, path))
        assert "error" in result
        assert "offline" in result["error"].lower()

    def test_refusal_happens_before_any_network_call(self, offline):
        """Refusing after the request is built would still reach the tenant --
        and on a machine with real credentials, the log import is a live write.
        The `offline` fixture makes httpx.AsyncClient raise, so this passing
        means no client was ever constructed."""
        result = run_tool(
            secops_rest.call("POST", "logTypes/WINDOWS_SYSMON/logs:import"))
        assert "error" in result

    def test_the_error_says_what_to_do(self, offline):
        """A bare failure invites the model to treat it as 'nothing found'.
        The error has to name the cause and the fix."""
        result = run_tool(secops_rest.call("GET", "rules"))
        detail = result.get("detail", "")
        assert "PURPLE_OFFLINE" in detail
        assert "Stage A" in detail


class TestDefaultIsUnchanged:
    def test_offline_is_off_unless_asked_for(self):
        """A real deployment must not land in offline mode by accident."""
        assert config.OFFLINE is False

    def test_the_gate_still_blocks_when_not_offline(self, monkeypatch):
        """The original guarantee, unchanged: no tenant, no agent."""
        monkeypatch.setattr(config, "OFFLINE", False)
        monkeypatch.setattr(platform_core.config, "OFFLINE", False, raising=False)

        async def unreachable():
            return "DefaultCredentialsError: not found"

        monkeypatch.setattr(platform_core, "_unreachable_reason", unreachable)

        class Ctx:
            agent_name = "purple_team_agent"

        blocked = run_tool(platform_core.require_live_tools(Ctx()))
        assert blocked is not None
        assert "unreachable" in blocked.parts[0].text.lower()
