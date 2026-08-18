"""Stage A must not require Google credentials.

`platform_core` used to resolve Application Default Credentials at import
time (`google.auth.default()` as a module-level statement). Stage A -- corpus
search, generation, the oracle -- is all local and never calls SecOps, but
merely importing `purple_agent` on a machine with no Google credentials
configured raised `DefaultCredentialsError` before a single line of Stage A
code ran. Verified live: the README's own "no Google Cloud credentials
needed" claim for Stage A was false until this was fixed.
"""

from __future__ import annotations

from purple_agent import platform_core


class TestCredentialsAreResolvedLazily:
    def test_credentials_are_not_resolved_until_first_use(self, monkeypatch):
        monkeypatch.setattr(platform_core, "_credentials", None)
        called = []

        def fake_default(scopes=None):
            called.append(scopes)
            raise AssertionError("should not be called by import alone")

        monkeypatch.setattr(platform_core.google.auth, "default", fake_default)

        # Importing/using the module without calling _fresh_token() must not
        # touch google.auth.default at all.
        assert platform_core._credentials is None
        assert called == []

    def test_fresh_token_resolves_credentials_on_first_call_only(self, monkeypatch):
        monkeypatch.setattr(platform_core, "_credentials", None)
        calls = []

        class FakeCredentials:
            valid = True
            token = "fake-token"

            def refresh(self, request):
                pass

        def fake_default(scopes=None):
            calls.append(scopes)
            return FakeCredentials(), "fake-project"

        monkeypatch.setattr(platform_core.google.auth, "default", fake_default)

        assert platform_core._fresh_token() == "fake-token"
        assert len(calls) == 1, "google.auth.default must be called exactly once"

        platform_core._fresh_token()
        assert len(calls) == 1, "a second call must reuse the resolved credentials"
