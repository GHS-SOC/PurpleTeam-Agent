import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from purple_agent import config, secops_rest, tools  # noqa: E402


def run_tool(coro):
    """Drive an async tool to completion from a synchronous test.

    await_stage and ingest_run are coroutines because ADK runs a
    sync tool inline on the event loop, so a blocking sleep or HTTP call in one
    session stalls every other session in the process. Tests stay synchronous --
    a bare asyncio.run is cheaper here than a pytest-asyncio dependency.
    """
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def no_live_tenant_calls(monkeypatch):
    """Make it impossible for a test to reach the live SecOps tenant by accident.

    This is not hypothetical. There were briefly two transports; a fixture
    stubbed one, ingest_run used the other, and the suite quietly POSTed real
    import_logs at a PRODUCTION tenant. Ten synthetic runs landed and opened 30
    cases in an analyst queue before anyone noticed -- and nothing failed,
    because a successful live ingest looks exactly like a successful stub.

    secops_rest.call is the single chokepoint every Chronicle operation goes
    through, so one patch covers reads and the log import alike. A test that
    needs it stubs the specific operation; anything else raises here rather than
    dialling out. A test suite must not be able to write to the SIEM it
    evaluates.
    """
    async def blocked(*_args, **_kwargs):
        raise AssertionError(
            "a test tried to call the live Chronicle API. Stub the operation it "
            "uses on purple_agent.secops_rest in the test's own fixture. "
            "See tests/conftest.py::no_live_tenant_calls."
        )

    # secops_rest.call is the single chokepoint every operation goes through,
    # so blocking it covers reads and the log import alike.
    monkeypatch.setattr(secops_rest, "call", blocked)


@pytest.fixture(autouse=True)
def isolate_run_output(tmp_path, monkeypatch):
    """Point PURPLE_OUT_DIR at a temp directory for every test.

    Without this, any test that builds or ingests a run writes a real folder
    into out/ -- the same directory operators read run artefacts from. The suite
    had left 250+ folders there, each holding a few bytes of fixture text
    ("report body", "## Verdict\\nFINAL"), interleaved with genuine runs and
    indistinguishable from them at a glance.

    Both writers read config.OUT_DIR at call time (marking.save_run and
    tools.save_run_report), so patching the attribute is enough.
    """
    monkeypatch.setattr(config, "OUT_DIR", tmp_path / "out")


@pytest.fixture(autouse=True)
def reset_focused_run():
    """Clear the run-in-focus between tests.

    It is module-level state that save_run_report reads, so a run left focused
    by one test would decide where the next test's artefacts land.
    """
    tools._focused_runs.clear()
    yield
    tools._focused_runs.clear()
