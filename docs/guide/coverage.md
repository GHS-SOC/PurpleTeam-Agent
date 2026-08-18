# What can be generated

Which Windows events this project can produce, which are verified end to end, and how to
check a template against a tenant's real parsers before trusting a run.

- [Verified event types](#verified-event-types)
- [Validating templates](#validating-templates)
- [Supported rule shapes](#supported-rule-shapes)

---

## Verified event types

Verified end-to-end against a live SecOps tenant — generated, ingested, and confirmed
present in UDM, not just "template exists".

**Sysmon (`WINDOWS_SYSMON`) — 8/8 fully working.** 1 process create, 3 network, 7 image
load, 8 remote thread, **10 process access** (the LSASS event most credential-dumping
rules key on), 11 file create, 13 registry set, 22 DNS. All parse to the correct UDM
event type with the marker hostname intact, searchable ~2 minutes after ingest.

**Security channel (`WINEVTLOG_XML`) — ingests, but degraded on a tenant with a custom
parser active.** 4624, 4625, 4648, 4672, 4688, 4689, 4768, 4769, 4776. Where a tenant runs a
lightweight custom parser for this log type in place of Chronicle's full one, it may flatten
every Security event to `GENERIC_EVENT` with **no hostname and no extracted fields** — so
these events land but are invisible to `principal.hostname` and will not trigger
field-based detections. Find them with `metadata.log_type = "WINEVTLOG_XML"` instead, and
confirm with `scripts/validate_templates.py` (below) before assuming a coverage gap.

Against Chronicle's own default parser the same events resolve correctly
(`4688 → PROCESS_LAUNCH`, `4624 → USER_LOGIN`, hostname intact), so the templates
themselves are sound — a limitation like this lives entirely in how a given tenant is
configured, never in this tool.

**That configuration is out of scope for this tool and must stay that way.** A parser is
tenant-wide: changing one to suit this exercise changes how every real log source into that
tenant is parsed. The constraint is enforced in code rather than left to judgement — see
[Production safety](../../README.md#production-safety). In practice: **use Sysmon-backed
Sigma categories**, which cover credential access, execution, persistence, defense evasion
and C2 comfortably.

The two channels ingest under **different Chronicle log types** and need separate
`import_logs` calls; combining them silently yields nothing.

---

## Validating templates

A template can produce well-formed XML, pass every offline test, be accepted by
`import_logs` — and still be discarded by the parser, with no symptom except that
nothing ever appears in UDM. Downstream that reads as a coverage gap.

```bash
python scripts/validate_templates.py
```

Runs every template through the tenant's real parsers via `run_parser`. Ingests nothing,
answers in seconds, and reports the actual rejection reason:

```
field "SourcePort": strconv.Atoi: parsing "-": invalid syntax
field backstory.File.sha256 "..." too long for type HASH (66 bytes, max 64)
FILE_CREATION missing target.file field
```

Run it after changing anything in `purple_agent/synth/`. `OK` means parsed with a
hostname; `WEAK` means parsed but unfindable by marker (currently 4768/4769); `FAIL`
means rejected.

---

## Supported rule shapes

The generator inverts a Sigma rule's constraints into concrete field values. Not every
constraint can be inverted, and the ones that cannot are reported in `unresolved` for you
to fill in rather than guessed at.

| | |
|---|---|
| **Inverted automatically** | `contains`, `startswith`, `endswith`, `all`, `windash`, `cidr`, plain equality |
| **Reported as `unresolved`** | `re`, `fieldref`, `base64`, `base64offset`, `utf16`, `utf16le`, `utf16be`, `wide`, `expand` |
| **Not supported** | correlation and aggregation rules — the oracle returns `UNSUPPORTED` rather than guessing |
| **Single event only** | a rule whose logic spans several events cannot be satisfied by one generated event |

A rule's `logsource.category` must also appear in `synth/mapping.py`'s table. A category
with no mapping is **declined**, not approximated — emitting a neighbouring event type
would satisfy the oracle's field checks while never tripping the deployed rule, which is
precisely the false coverage gap this project exists to prevent.
