"""Environment-driven configuration.

Loaded from `purple_agent/.env`. Required tenant settings are read with
`os.environ[...]` on purpose -- a missing tenant value should fail loudly at
import time rather than surface later as a confusing 404 from the API.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

PACKAGE_DIR = Path(__file__).parent
PROJECT_DIR = PACKAGE_DIR.parent

load_dotenv(PACKAGE_DIR / ".env")

# --- Model ------------------------------------------------------------------
MODEL = os.environ.get("PURPLE_MODEL", "gemini-2.5-flash")
MAX_TOKENS = int(os.environ.get("PURPLE_MAX_TOKENS", "16384"))
# Low by default: this agent reports on whether detections fired. Creative
# variance in that verdict is a defect, not a feature.
TEMPERATURE = float(os.environ.get("PURPLE_TEMPERATURE", "0.2"))

# --- SecOps tenant ----------------------------------------------------------
MCP_URL = os.environ["SECOPS_MCP_URL"]
PROJECT_ID = os.environ["SECOPS_PROJECT_ID"]
CUSTOMER_ID = os.environ["SECOPS_CUSTOMER_ID"]
REGION = os.environ["SECOPS_REGION"]

# Required by import_logs. Not fatal at import: everything except live ingest
# works without it, so the failure belongs at the point of use.
FORWARDER_ID = os.environ.get("SECOPS_FORWARDER_ID", "")

# Offline mode -- run Stage A with no tenant at all.
#
# Stage A (find the rule, invert it, build the events, check them against the
# rule) never touches SecOps. Without this flag you still cannot try it
# conversationally, because the health gate refuses to start the agent when the
# tenant is unreachable -- a guard against a model answering a SOC question with
# no data behind it.
#
# Setting this does not weaken that guard, it inverts how it is enforced: every
# Chronicle call is refused at the transport chokepoint instead, so Stage B
# becomes impossible rather than merely unreachable, and the model receives an
# explicit error it has to report. Opt-in and off by default, so a real
# deployment cannot land in it by accident.
OFFLINE = os.environ.get("PURPLE_OFFLINE", "").strip().lower() in {"1", "true", "yes"}

# --- Synthetic data marking -------------------------------------------------
HOST_PREFIX = os.environ.get("PURPLE_HOST_PREFIX", "PT-LAB-")

# Domain and account used inside generated events. Set these to match the
# environment you are testing so the telemetry looks native; the defaults are
# deliberately generic so no tenant identifier is baked into the source.
DNS_DOMAIN = os.environ.get("PURPLE_DNS_DOMAIN", "corp.local")
NETBIOS_DOMAIN = os.environ.get("PURPLE_NETBIOS_DOMAIN", "CORP")
ACTOR_USERNAME = os.environ.get("PURPLE_ACTOR_USER", "svc_backup")

# --- Sigma corpus -----------------------------------------------------------
def _resolve(value: str) -> Path:
    """Resolve a configured path relative to the project root."""
    path = Path(value)
    return path if path.is_absolute() else PROJECT_DIR / path


SIGMA_REPO_DIR = _resolve(os.environ.get("SIGMA_REPO_DIR", "vendor/sigma"))
SIGMA_INDEX_DIR = _resolve(os.environ.get("SIGMA_INDEX_DIR", "data"))
SIGMA_DB_PATH = SIGMA_INDEX_DIR / "sigma.db"
CHROMA_DIR = SIGMA_INDEX_DIR / "chroma"
CHROMA_COLLECTION = "sigma_rules"

# Rule directories indexed from the SigmaHQ repo. `rules-compliance` and
# `rules-placeholder` are excluded: compliance rules are not threat detections,
# and placeholder rules only gain meaning after backend-specific substitution,
# so neither can be used to drive or validate log generation.
SIGMA_RULE_DIRS = ("rules", "rules-threat-hunting", "rules-emerging-threats")

# Where generated event payloads are written. Every Stage A run drops a
# self-contained folder here: the raw XML per log type (ready to replay or
# ingest by hand), the structured events, and a manifest.
OUT_DIR = _resolve(os.environ.get("PURPLE_OUT_DIR", "out"))
