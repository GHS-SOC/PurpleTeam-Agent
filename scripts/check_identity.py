"""Ask Chronicle what the CURRENT credential is allowed to do.

    python scripts/check_identity.py

Run it twice: once as yourself, once impersonating whatever service account a
deployment will actually run as. Access is granted to a principal, not to a
project, so your own access says nothing about whether a service account has
any.

Two outcomes, and they are not the same problem:

  identity unknown    ADC is not configured at all
  probe call fails     the identity cannot reach Chronicle -- no grant on the
                       tenant, the wrong quota project, or the Chronicle API is
                       not enabled on the project

Unlike the retired MCP transport, direct REST has no separate discovery step:
`secops_rest.call` either succeeds or returns an error for the identity making
it, so there is one door to check, not two.

Read-only throughout. Calls list_rules(page_size=1), which touches no tenant
state.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from purple_agent import config, platform_core, secops_rest  # noqa: E402


def current_identity() -> str:
    """The email the token actually belongs to, asked of Google rather than
    inferred from the credential object -- impersonation and user credentials
    expose it differently, and the whole point here is to be sure."""
    try:
        token = platform_core._fresh_token()
    except Exception as exc:  # noqa: BLE001
        return f"<no credentials: {type(exc).__name__}: {exc}>"
    try:
        r = httpx.get(
            "https://oauth2.googleapis.com/tokeninfo",
            params={"access_token": token},
            timeout=10.0,
        )
        if r.status_code == 200:
            info = r.json()
            return info.get("email") or info.get("sub") or "<token has no email>"
        return f"<tokeninfo HTTP {r.status_code}>"
    except Exception as exc:  # noqa: BLE001
        return f"<tokeninfo failed: {type(exc).__name__}: {exc}>"


def main() -> int:
    print(f"identity   : {current_identity()}")
    print(f"quota proj : {config.PROJECT_ID}")
    print(f"tenant     : {config.CUSTOMER_ID[:8]}... ({config.REGION})")
    print()

    probed = asyncio.run(secops_rest.list_rules(page_size=1))
    if "error" in probed:
        print(f"probe      : FAILED -- {str(probed['error'])[:300]}")
        print()
        print("This identity cannot reach Chronicle. Either it holds no grant on")
        print("the tenant, the quota project (SECOPS_PROJECT_ID) is wrong for the")
        print("credential presented, or the Chronicle API is not enabled on the")
        print("project. Nothing downstream will work; fix this first.")
        return 1

    print("probe      : OK -- rules.list returned a result")
    print()
    print("This identity can reach Chronicle and read tenant data.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
