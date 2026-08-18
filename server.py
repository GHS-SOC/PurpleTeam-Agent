"""Cloud Run entrypoint.

`adk web purple_agent` is the local equivalent. This is the hosted one: the same
ADK FastAPI app, minus the endpoints that let a visitor author agents, plus an
eager import so a misconfigured revision fails to deploy rather than failing on
a tester's first message.

Run it with a SINGLE uvicorn worker. The run store (tools._RUNS), the token
accounting (usage._sessions) and the MCP health cache are module-level dicts, so
a second worker is a second copy of all three: a run built by worker 1 is
invisible to worker 2, and ingest_run reports it as "has no built events".
"""

from __future__ import annotations

import logging
import os

from google.adk.cli.fast_api import get_fast_api_app

logging.basicConfig(level="INFO")
logger = logging.getLogger("purple_agent.server")

# The agent package lives at the repo root, so the root is the agents dir and
# `purple_agent` is discovered as an app by name.
AGENTS_DIR = os.environ.get("ADK_AGENTS_DIR", os.path.dirname(os.path.abspath(__file__)))

app = get_fast_api_app(
    agents_dir=AGENTS_DIR,
    web=True,
    # Sessions live in memory: with one pinned instance they last until the next
    # revision, which is honest for a lab. A database session store while the run
    # store is still in-process would be worse than both being ephemeral -- a
    # tester would resume yesterday's conversation and hit "run has no built
    # events" with no explanation available to anyone.
    session_service_uri="memory://",
    artifact_service_uri="memory://",
    memory_service_uri="memory://",
    # Default True writes a per-agent SQLite file next to the package. On Cloud
    # Run that path is tmpfs -- RAM that is never reclaimed and is lost on deploy.
    use_local_storage=False,
    # Not optional, despite looking like an unused knob. This is what installs
    # the CORS middleware, and the browser UI cannot work without it: every
    # request the Angular app makes carries an Origin header, and without the
    # middleware those are rejected with 403 while the same request from curl
    # succeeds. Symptom is "Failed to create new session" in a UI that otherwise
    # loads fine. Reaching the service still requires a Cloud Run IAM token, so
    # "*" here widens nothing.
    allow_origins=["*"],
    host="0.0.0.0",
    port=int(os.environ.get("PORT", "8080")),
)

# The dev UI ships writable agent-builder endpoints: get_fast_api_app calls
# _register_builder_endpoints, which registers POST /builder/save to write agent
# YAML into agents_dir. They are skipped only when python-multipart is missing,
# and google-adk depends on it, so they are always live -- removing the routes is
# the only way to drop them. Testers get the chat UI; they do not get to author
# agents inside a service that writes to a production SIEM.
BLOCKED_ROUTE_PREFIXES = ("/builder", "/dev/apps")

_before = len(app.router.routes)
app.router.routes = [
    r
    for r in app.router.routes
    if not str(getattr(r, "path", "")).startswith(BLOCKED_ROUTE_PREFIXES)
]
logger.info("removed %d builder route(s)", _before - len(app.router.routes))

# Fail the revision, not the tester's first message. ADK's agent loader imports
# lazily on first request, so a bad SECOPS_* value or missing credentials would
# otherwise surface as a 500 several minutes after a green deploy.
# purple_agent/__init__.py does `from . import agent`, so this single import
# exercises config.py's os.environ reads, platform_core's google.auth.default(),
# and the agent's tool construction.
import purple_agent  # noqa: E402,F401

# Which principal did this container actually resolve? With a mounted service
# account key the answer depends on GOOGLE_APPLICATION_CREDENTIALS pointing at a
# file that exists -- and a wrong path fails softly, falling back to whatever
# other ADC source is available. Naming the identity at startup turns "the tools
# 403 for some reason" into a one-line answer.
try:
    _creds = purple_agent.platform_core._credentials
    logger.info(
        "credential: %s (source: %s)",
        getattr(_creds, "service_account_email", None) or type(_creds).__name__,
        os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "metadata server / gcloud ADC"),
    )
except Exception:  # noqa: BLE001 - never block startup on a log line
    logger.exception("could not determine the runtime credential")

# Probe both halves of hybrid search separately, because the vector half fails
# OPEN: corpus/retrieve._semantic_ranking catches every exception from Chroma and
# returns []. Chroma downloads its 166 MB ONNX model to $HOME/.cache/chroma on
# first use, so an image built with a different HOME -- or without the cache --
# degrades to keyword-only search in total silence, and nobody finds out except
# as worse results. A combined search() probe would still pass, since the keyword
# half alone returns hits. Hence two probes.
try:
    from purple_agent.corpus import retrieve

    _probe = "credential dumping lsass"
    _keyword = retrieve.search(_probe, limit=3)
    _semantic = retrieve._semantic_ranking(_probe, limit=3)

    if not _keyword:
        logger.error("sigma index EMPTY -- data/sigma.db is missing or unbuilt")
    elif not _semantic:
        logger.error(
            "sigma index is keyword-ONLY: the vector layer returned nothing. "
            "Check that data/chroma and $HOME/.cache/chroma are in the image and "
            "that HOME matches the build stage."
        )
    else:
        logger.info(
            "sigma index OK: %d keyword hit(s), %d semantic hit(s)",
            len(_keyword),
            len(_semantic),
        )
except Exception:  # noqa: BLE001 - never block startup on the probe itself
    logger.exception("sigma index probe failed")
