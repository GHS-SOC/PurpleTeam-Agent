# Purple Team Agent

![Purple Team Agent — AI-assisted detection validation: a detection rule becomes synthetic
telemetry, which becomes an alert or case you can investigate.](docs/assets/hero.jpg)

Ask it in plain language — *"generate Windows logs for mimikatz"* — and it will find the
real detection logic for that threat, generate Windows telemetry that satisfies it, import
it into Google SecOps, and tell you honestly whether the SIEM caught it and opened a case.

```
you: generate windows logs for mimikatz and tell me if a case was created
```

The point is to find where detection coverage is missing. **"No rule fired" is a successful
run, not a failed one.**

![The run, end to end: Stage A finds the rule, inverts it into field values, writes Windows
Event XML and checks it against the rule locally — then stops for your confirmation before
Stage B imports into the live SIEM and verifies on a clock.](docs/assets/pipeline.gif)

---

## What this does not do

- **It does not execute anything.** No attack tooling runs, on this host or any other. It
  writes Windows Event XML that satisfies a Sigma rule's logic, and sends that directly to
  Chronicle's log-import endpoint.
- **It does not touch the collection tier.** Real Sysmon config, EDR agents, forwarders and
  ingest filters are all bypassed — a PASS proves the parser, the detection logic and the
  alert/case path *on ideal input*, not that a real attacker's traffic would have looked
  like this or survived your actual sensors.
- **It does not author or change detections.** Every write it can make is a synthetic log
  event, gated behind your explicit confirmation. Parsers, rules, feeds, forwarders,
  reference lists and the state of cases and alerts are read-only, enforced in code — see
  [Production safety](#production-safety).
- **It does not cover every rule shape.** Single-event Sigma logic only; correlation and
  aggregation rules come back `UNSUPPORTED`, never guessed at.
  ([Supported rule shapes](docs/guide/coverage.md#supported-rule-shapes).)

---

## How it works

**Stage A writes nothing to the tenant.** It generates the events and checks them locally,
so you can run it freely.

**Stage B needs your confirmation.** It imports into a live SIEM and can raise real alerts
and cases a human will work. The agent will not start it without an explicit yes.

**Verification is time-gated.** The three things you verify settle at different speeds, and
querying one before it is due returns an empty result that is indistinguishable from a real
negative:

| Elapsed | What becomes meaningful |
|---|---|
| ~2 min | **Parsing** — `udm_search` for the marker hostname |
| ~5 min | **Detections, alerts and cases** — rule evaluation and SOAR case creation lag ingestion |
| 10 min | **Verdict** — the earliest point any failure may be declared |

This is enforced, not advisory. `await_stage(run_id, "parse" | "detections" | "verdict")`
blocks server-side until a stage is actually due, so the model cannot query cases at minute
one and misread the empty result as a coverage gap — the single easiest way to produce a
confident wrong answer.

Generation is local and deterministic; the model chooses *what* to simulate and the library
controls *how* the XML is written. Why that split matters, and how rules are retrieved, is
in [How it works](docs/guide/how-it-works.md).

---

## Setup

Requires Python 3.11+ and [`uv`](https://docs.astral.sh/uv/getting-started/installation/).
`gcloud` is only needed once you reach Stage B; Stage A needs neither.

```bash
uv venv --python 3.11 .venv
```

```bash
# macOS / Linux
uv pip install --python .venv/bin/python -r requirements.txt
# Windows
uv pip install --python .venv/Scripts/python.exe -r requirements.txt
```

```bash
cp .env.example purple_agent/.env
```

`config.py` reads its settings at import time and raises if any are missing — so the file
must exist even for Stage A, but the dummy values already in `.env.example` are fine for
everything except a real import. You only need real values, and `gcloud auth
application-default login`, when you reach Stage B.

Clone the Sigma corpus and build the index (~3 minutes, one time):

```bash
# macOS / Linux
scripts/refresh_sigma.sh
# Windows
powershell -File scripts/refresh_sigma.ps1
```

```bash
python scripts/build_index.py
```

That is everything Stage A needs. Running it is next.

---

## Try it with no SIEM at all

It is an agent, so it needs a model — but it does not need a SIEM. With only a model key
set in `purple_agent/.env`:

```bash
PURPLE_OFFLINE=1 adk run purple_agent
```

```
you: generate windows logs for mimikatz — dry run only, do not import
```

It finds the real Sigma rules for the threat, inverts their selectors into concrete field
values, writes the Windows Event XML, and re-checks the finished events against the rules
they came from. `out/<run_id>/` then holds the raw XML, `events.json` and `manifest.json` —
nothing has left your machine.

`PURPLE_OFFLINE=1` refuses every SecOps request at the transport, so Stage B is *impossible*
rather than merely unconfigured: ask it to import and it reports the refusal instead of
guessing at a result. Drop the flag and supply tenant credentials when you want the real
thing.

Stage A is also a plain library if you would rather skip the model entirely — see
[How it works](docs/guide/how-it-works.md#code-layout) for the entry points.

---

## Usage

Against a real tenant, without the offline flag:

```bash
adk run purple_agent          # or: adk web purple_agent, for a browser UI
```

Dry run — generates and checks, imports nothing:

```
generate windows logs for mimikatz — dry run only, do not import
```

Full loop:

```
generate windows logs for kerberoasting, import them, and tell me if a case was created
```

Target a technique:

```
simulate T1003.001 and check whether the tenant's deployed rules cover it
```

---

## Reading the verdict

![Five outcomes look identical when the SIEM reports nothing, and only one of them is a
coverage gap.](docs/assets/figure-2-five-outcomes.svg)

Five outcomes look identical if you are careless. The agent is instructed to tell them
apart, and this is the main thing to check in its report:

| Symptom | Cause | What to do |
|---|---|---|
| Oracle says events satisfy no target rule | **Generation** — the logs were never going to match | Adjust the step fields and rebuild. Not a coverage gap. |
| `udm_search` empty, or cases queried before 5 min | **Not yet visible** — that stage has not settled | Keep waiting. This is not a finding. |
| `udm_search` empty after the full window | **Parser** — wrong log type, or the event was discarded | Run `scripts/validate_templates.py` |
| Events parsed, no rule matched | **Genuine coverage gap** | Write or enable a detection |
| Rule matched, no alert or case | Rule not alert-enabled, or no SOAR playbook | Check rule config and playbooks |

An oracle verdict of `UNSUPPORTED` means the rule uses an aggregation or correlation that
cannot be evaluated against a single event. That is "unknown" — never read it as either
success or a gap.

---

## Synthetic data is always marked

`import_logs` accepts no labels and no custom event time, so marking is in-band by
hostname. Every run pins a host named `PT-LAB-<run_id>`:

```
principal.hostname = /^PT-LAB-/          # everything this agent has ever written
principal.hostname = /PT-LAB-6F719380/   # one specific run
```

The marking check runs inside `build_events` and **blocks the import** if any event lacks
the marker. Unmarked synthetic data in a live SIEM is indistinguishable from a real
intrusion, and someone will work it as one.

Finding those events again afterwards takes an ordered ladder of three queries rather than
one — see [Finding a run](docs/guide/operations.md#finding-a-run-is-a-ladder-not-one-query).

---

## Production safety

Every Chronicle request passes `secops_rest._check` before a socket opens. This is the
whole allowlist it is checked against:

```python
("GET",  ":udmSearch"),
("GET",  "rules"),
("GET",  "rules/[\w.-]+"),
("GET",  "legacy:legacySearchDetections"),
("GET",  "cases"),
("GET",  "cases/\d+"),
("GET",  "cases/\d+/caseAlerts"),
("GET",  "forwarders"),
("POST", "logTypes/[A-Z0-9_]+/logs:import"),   # the only write
```

Anything else raises `ForbiddenRequest`. Parsers, detection rules, feeds, forwarders,
reference lists, data tables and case state have no entry, so they are unreachable rather
than merely unused. `test_log_import_is_the_only_write` asserts the shape of the tuple
itself, so adding a second write fails the suite rather than review.

The one write is synthetic events, sent after explicit confirmation and marked as above.

The repository ships no detection rules. Sigma content is cloned at build time into an
ignored directory; a tenant's own rules are read at runtime and never stored.

---

## Documentation

| | |
|---|---|
| [How it works](docs/guide/how-it-works.md) | Why generation is deterministic, the oracle and its pySigma cross-check, hybrid retrieval, and the code layout |
| [What can be generated](docs/guide/coverage.md) | Verified event types, validating templates against real parsers, supported rule shapes |
| [Operations](docs/guide/operations.md) | Finding a run after ingest, run artefacts, token accounting, platform gotchas |

---

## Status

Phase one, built and exercised in a SecOps lab tenant — a real one, with real ingestion,
rule evaluation and case creation, not a simulator. It is open source because the problem
is bigger than one team's view of it — feedback, issues and pull requests are all welcome.

See [CONTRIBUTING.md](CONTRIBUTING.md) to get set up. For anything that looks like a
security problem, [SECURITY.md](SECURITY.md) — please don't open a public issue.

## Licence

[MIT](LICENSE). Detection rules are consumed at runtime from
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma), which is licensed separately under the
Detection Rule License (DRL) 1.1; this repository does not redistribute them.
