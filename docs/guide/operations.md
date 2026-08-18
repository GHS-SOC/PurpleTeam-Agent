# Operations

Finding a run again after ingest, what each run leaves on disk, token accounting, and the
platform gotchas worth knowing before you hit them.

- [Finding a run is a ladder, not one query](#finding-a-run-is-a-ladder-not-one-query)
- [What each run leaves on disk](#what-each-run-leaves-on-disk)
- [Token usage](#token-usage)
- [Notes and gotchas](#notes-and-gotchas)

---

## Finding a run is a ladder, not one query

Every run pins a host named `PT-LAB-<run_id>`, and the marking check blocks the import if
any event lacks it (see [Synthetic data is always marked](../../README.md#synthetic-data-is-always-marked)).
Finding those events again afterwards is the part that surprises people.

Events carry the FQDN in `<Computer>` (`PT-LAB-6F719380.corp.local`), and Chronicle
normalises that whole string into `principal.hostname`, so the obvious exact match on the
short marker hostname returns nothing on a run that ingested perfectly — a miss that reads
exactly like a parse failure. `start_run` and `ingest_run` therefore return `udm_queries`,
tried in order and stopped at the first hit:

| # | Query | Hits when |
|---|---|---|
| 1 | `principal.hostname = "PT-LAB-6F719380.corp.local"` | normal — the FQDN survived normalisation |
| 2 | `principal.hostname = /PT-LAB-6F719380/` | the suffix is not what was assumed |
| 3 | `principal.hostname = "PT-LAB-6F719380"` | the domain was stripped on the way in |

Only an empty result from **all three**, after the full verification window, is evidence
that the logs did not parse. The suffix comes from the events that were actually built
(`PURPLE_DNS_DOMAIN`), not from config at query time, so an old run stays searchable after
the setting changes.

Events are stamped a few minutes in the past. Live Chronicle rules evaluate near-real-time
data, so backdating further means nothing fires.

---

## What each run leaves on disk

Every `build_events` writes a folder to `out/<run_id>/` (path configurable via
`PURPLE_OUT_DIR`). A **dry run** leaves the first three files; a run you **import** gains
the last two:

| File | Written when | Contents |
|---|---|---|
| `<LOG_TYPE>.xml` | every run | Raw Windows Event XML, one event per line — replayable, re-ingestable |
| `events.json` | every run | Structured events plus the field view the oracle saw |
| `manifest.json` | every run | run_id, marker hostname, per-log-type counts, the `udm_query` |
| `report.md` | after import | The agent's final report for the run |
| `usage.json` | after import | Token totals for the session |

`report.md` and `usage.json` are saved by an `after_agent_callback` at the end of each
turn, only once the run has been ingested. The report is captured from the model's output
in the callback — it is **not** re-emitted by the model into a tool call, which would
reinflate the response toward the token cap the whole Stage B redesign exists to avoid.

One subtlety worth knowing: `usage.json` is written *after* the final response's tokens are
recorded, so it is the **complete** total — larger than the Token Usage line inside
`report.md`, which necessarily excludes the response that contains it.

Run folders accumulate and are not auto-pruned (they are gitignored). Each is a few KB.

---

## Token usage

Every Stage B report ends with a **Token Usage** section: LLM calls, prompt / completion /
total tokens, cached tokens, and an estimated cost. An `after_model_callback` accumulates
`usage_metadata` from each model turn per session (`purple_agent/usage.py`), and the
`token_usage` tool reads the running total for the report.

Two honest caveats, both stated in the output:

- The total covers the **whole session** — Stage A and Stage B — since it is one conversation.
- It **excludes the closing response** that contains it: a model cannot count the tokens of
  the message it is still writing. The figure is "everything up to this final turn".

Cost is an estimate from a per-token rate for the configured model
(`PRICING` in `usage.py`); a model with no entry reports `cost n/a` rather than a wrong
number. Update the rate if you change models or the provider's pricing changes.

### Two different token walls, two different fixes

Both were hit in practice, and they fail differently enough that one fix does not address
the other. The shapes are worth knowing whatever model you run:

- **The per-response output cap** — hit by re-emitting event XML into `import_logs` calls.
  A truncated import is malformed XML the parser drops silently, so this fails as missing
  data rather than as an error. Fixed by ingesting server-side (`ingest_run`), so the XML
  never enters the model's output at all.
- **The total context window** — hit by verification results piling up in history. One raw
  `udm_search` at `maxEvents=100` is tens of thousands of tokens of full UDM objects, and a
  couple of retries exhaust the window. Fixed by a `before_tool_callback` that clamps page
  sizes and an `after_tool_callback` that projects heavy results down to the fields
  verification actually reads (`platform_core.clamp_tool_args` / `trim_tool_result`).
  Measured: a 252 KB `udm_search` becomes 6 KB, with event types, timestamps and the marker
  hostname intact.

---

## Notes and gotchas

**The agent will not start against an unreachable tenant.** `require_live_tools` refuses
rather than letting a model answer a SOC question with nothing behind it. `PURPLE_OFFLINE=1`
is the deliberate exception: it skips that check and refuses every Chronicle request at the
transport instead, so Stage A runs and Stage B is impossible. `tool_error_response` turns a
failed call into an explicit error the model has to repeat rather than paper over.

**Rule authoring is excluded on purpose.** `generate_rules` / `create_rule` would let the
agent close a coverage gap by writing a YARA-L rule. Auto-authoring detection content into
a live tenant is a far larger blast radius than writing logs, so it is not in the allowlist.

**`import_logs` needs a forwarder id**, and no tool lists them. Find one with
`python scripts/find_forwarder.py` and set `SECOPS_FORWARDER_ID`.

**Chronicle's own generation tools are not used.** `generate_threat_detection_opportunity`,
`generate_synthetic_events` and `evaluate_rule_coverage` exist, but need a separately
entitled SecOps feature. Where that entitlement exists they can be added to
`platform_core.GENERATE_TOOLS` and used ahead of local generation.

**`mcp` is pinned below 2.0** in `requirements.txt` — 2.0 removed `McpHttpClientFactory`,
which `google-adk` imports at startup whether or not an app uses MCP tools. This project's
SecOps calls go through `secops_rest.py` directly.
