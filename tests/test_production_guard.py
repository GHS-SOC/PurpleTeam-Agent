"""The tenant is production. This tool never changes its configuration.

These tests exist because a guard alone is not a guarantee: it stops paths being
added carelessly, but not deliberately by someone who does not know the
environment is production.

The guard moved when the transport did. It used to be a denylist of MCP tool
NAMES, checkable at toolset construction because the server defined the tools.
The agent now composes its own Chronicle REST requests, so the only place a guard
can exist is where a request is issued: secops_rest._ALLOWED, a (method, path)
allowlist enforced by secops_rest._check before any socket opens.

The asymmetry it encodes is unchanged. Writing event DATA is the entire point of
the agent and is gated behind user confirmation. Writing CONFIGURATION -- parsers,
rules, feeds, reference lists, data tables -- and touching the state of cases and
alerts analysts are working is never in scope, at any confirmation level.
"""

from __future__ import annotations

import asyncio

import pytest

from purple_agent import secops_rest

# Captured at import, before conftest's no_live_tenant_calls fixture replaces it.
# These tests must exercise the REAL transport to prove the guard runs inside it;
# the conftest stub would short-circuit before _check ever executed.
_REAL_CALL = secops_rest.call


def refused(method: str, path: str) -> bool:
    """True when the guard rejects the request before it is issued."""
    try:
        secops_rest._check(method, path)
        return False
    except secops_rest.ForbiddenRequest:
        return True


class TestConfigurationIsUnreachable:
    """Each of these is a real Chronicle endpoint with a destructive effect."""

    @pytest.mark.parametrize("method,path", [
        ("POST", "parsers"),                     # create a parser
        ("POST", "parsers/p1:activate"),         # activate one
        ("DELETE", "parsers/p1"),
        ("POST", "rules"),                       # author a detection rule
        ("PATCH", "rules/ru_abc"),
        ("DELETE", "rules/ru_abc"),
        ("POST", "feeds"),
        ("POST", "referenceLists"),
        ("POST", "dataTables"),
        ("POST", "forwarders"),
        ("POST", "watchlists"),
    ])
    def test_configuration_writes_are_refused(self, method, path):
        assert refused(method, path), f"{method} {path} reached the transport"

    @pytest.mark.parametrize("method,path", [
        ("POST", "cases/100000"),                # close or reassign a case
        ("PATCH", "cases/100000"),
        ("POST", "cases/100000/caseAlerts/1"),
        ("POST", "cases:executeBulkClose"),      # the bulk form, same effect
    ])
    def test_analyst_owned_state_is_refused(self, method, path):
        """Humans are working these. Observed live: 30 synthetic cases sat in a
        Tier-1 queue, and closing them was still not this tool's decision."""
        assert refused(method, path), f"{method} {path} reached the transport"


class TestAllowedSurface:
    @pytest.mark.parametrize("path", [
        ":udmSearch", "rules", "rules/ru_abc", "legacy:legacySearchDetections",
        "cases", "cases/100000", "cases/100000/caseAlerts", "forwarders",
    ])
    def test_verification_reads_are_permitted(self, path):
        assert not refused("GET", path)

    def test_log_import_is_the_only_write(self):
        assert not refused("POST", "logTypes/WINDOWS_SYSMON/logs:import")
        writes = [(m, p) for m, p in secops_rest._ALLOWED if m != "GET"]
        assert writes == [("POST", r"logTypes/[A-Z0-9_]+/logs:import")], (
            f"a non-GET path other than the log import was allowed: {writes}"
        )

    def test_import_path_cannot_be_widened_by_a_crafted_log_type(self):
        """The pattern is anchored, so a log type cannot smuggle in a path."""
        assert refused("POST", "logTypes/X/logs:import/../../rules")
        assert refused("POST", "logTypes/lowercase/logs:import")

    def test_a_trailing_newline_does_not_slip_past_the_allowlist(self):
        """`$` in a compiled pattern matches just before a single trailing
        newline, not strictly end-of-string -- `re.match` with a `^...$`
        pattern would let "rules/abc\\n" through an allowlist meant only for
        "rules/abc". `_check` must use `fullmatch`, not `match`."""
        assert refused("GET", "rules/ru_abc\n")
        assert refused("GET", "cases/100000\n")


class TestGuardRunsBeforeTheNetwork:
    def test_call_raises_without_issuing_a_request(self, monkeypatch):
        """If the guard ran after the request were built, a refused call could
        still have side effects. It must raise first."""
        def explode(*a, **k):  # any network use fails the test
            raise AssertionError("a refused call still touched the network")

        monkeypatch.setattr(secops_rest.httpx, "AsyncClient", explode)
        with pytest.raises(secops_rest.ForbiddenRequest):
            asyncio.run(_REAL_CALL("POST", "rules"))

    def test_forbidden_is_not_swallowed_into_an_error_dict(self):
        """Every other failure returns {"error": ...} for the model to read. A
        guard violation is a coding defect, not a runtime condition, so it must
        surface as an exception instead of a result the model can work around."""
        with pytest.raises(secops_rest.ForbiddenRequest):
            asyncio.run(_REAL_CALL("DELETE", "rules/ru_abc"))
