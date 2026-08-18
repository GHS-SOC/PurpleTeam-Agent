"""List Chronicle forwarders and print the id `import_logs` needs.

`import_logs` requires a forwarderId, but the MCP server exposes no forwarder
management tool -- this is the gap-filler. One authenticated GET, using the same
Application Default Credentials as the agent.

    python scripts/find_forwarder.py

Copy the id into SECOPS_FORWARDER_ID in purple_agent/.env.

Deliberately plain httpx rather than the `secops` SDK. The SDK was a dependency
of the whole project -- shipped in the runtime image -- for this single read.
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from purple_agent import config, platform_core  # noqa: E402

# The forwarders collection lives on the regional Chronicle host, which is a
# different hostname from the MCP endpoint in SECOPS_MCP_URL.
FORWARDERS_URL = (
    "https://{region}-chronicle.googleapis.com/v1alpha"
    "/projects/{project}/locations/{region}/instances/{customer}/forwarders"
)


def main() -> int:
    url = FORWARDERS_URL.format(
        region=config.REGION, project=config.PROJECT_ID, customer=config.CUSTOMER_ID
    )
    try:
        response = httpx.get(
            url,
            headers={
                "Authorization": f"Bearer {platform_core._fresh_token()}",
                "x-goog-user-project": config.PROJECT_ID,
            },
            timeout=30.0,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"Request failed: {type(exc).__name__}: {exc}")
        return 1

    if response.status_code != 200:
        print(f"HTTP {response.status_code}: {response.text[:300]}")
        return 1

    forwarders = response.json().get("forwarders", [])
    if not forwarders:
        print("No forwarders found. Create one in the SecOps console first.")
        return 1

    print(f"{len(forwarders)} forwarder(s) in {config.PROJECT_ID}:\n")
    for forwarder in forwarders:
        # name is a full resource path; the id is the last segment.
        forwarder_id = str(forwarder.get("name", "")).rsplit("/", 1)[-1]
        current = " <- currently configured" if forwarder_id == config.FORWARDER_ID else ""
        print(f"  {forwarder.get('displayName', '(no name)')}{current}")
        print(f"    SECOPS_FORWARDER_ID={forwarder_id}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
