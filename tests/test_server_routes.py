"""The hosted app must not expose the ADK agent builder.

`get_fast_api_app(web=True)` calls `_register_builder_endpoints`, which registers
`POST /builder/save` -- an endpoint that writes agent YAML into the agents
directory. It is skipped only when python-multipart is absent, and google-adk
declares python-multipart as a hard dependency, so it is always live.

If these fail, anyone who can reach the lab URL can author or replace an agent
definition inside a service that holds credentials to a production SIEM.
"""

from __future__ import annotations

import pytest

server = pytest.importorskip("server", reason="server.py needs google-adk + ADC")


def _paths():
    return [str(getattr(r, "path", "")) for r in server.app.router.routes]


class TestBuilderEndpointsAreGone:
    def test_no_builder_routes(self):
        offenders = [p for p in _paths() if p.startswith("/builder")]
        assert not offenders, f"agent-builder endpoints exposed: {offenders}"

    def test_no_dev_app_routes(self):
        offenders = [p for p in _paths() if p.startswith("/dev/apps")]
        assert not offenders, f"dev endpoints exposed: {offenders}"

    def test_every_blocked_prefix_is_actually_absent(self):
        """Pins the filter to the constant, so adding a prefix adds coverage."""
        for prefix in server.BLOCKED_ROUTE_PREFIXES:
            assert not [p for p in _paths() if p.startswith(prefix)]


class TestTheAppStillWorks:
    """The pruning must not take the agent surface with it."""

    def test_core_routes_survive(self):
        paths = _paths()
        for required in ("/health", "/list-apps", "/run", "/run_sse"):
            assert required in paths, f"{required} was removed"

    def test_the_agent_is_importable(self):
        """server.py imports purple_agent eagerly so a bad config fails the
        revision instead of a tester's first message."""
        import purple_agent

        assert purple_agent.agent.root_agent.name == "purple_team_agent"


class TestBrowserCanActuallyUseIt:
    """CORS is load-bearing, not decoration.

    get_fast_api_app installs the CORS middleware only when allow_origins is
    passed. Without it, every request the Angular UI makes carries an Origin
    header and comes back 403 -- while the identical request from curl succeeds,
    because CORS is a browser concern. The symptom is a UI that loads perfectly
    and then reports "Failed to create new session", which points nowhere near
    the cause.

    Removed once as an unused configuration knob. It is not one.
    """

    def _client(self):
        from fastapi.testclient import TestClient

        return TestClient(server.app)

    def test_session_create_survives_an_origin_header(self):
        r = self._client().post(
            "/apps/purple_agent/users/user/sessions", json={},
            headers={"Origin": "http://localhost:8080"},
        )
        assert r.status_code == 200, "the browser UI cannot create a session"

    def test_preflight_is_answered(self):
        r = self._client().options(
            "/apps/purple_agent/users/user/sessions",
            headers={"Origin": "http://localhost:8080",
                     "Access-Control-Request-Method": "POST"},
        )
        assert r.status_code == 200, "no CORS middleware -- allow_origins is missing"
        assert r.headers.get("access-control-allow-origin")
