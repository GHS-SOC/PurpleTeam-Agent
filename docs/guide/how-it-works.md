# How it works

Why generation is deterministic rather than LLM-driven, how rules are retrieved, and where
each piece of that lives in the code.

- [Why generation is deterministic](#why-generation-is-deterministic-not-llm-driven)
- [Retrieval is hybrid, not plain RAG](#retrieval-is-hybrid-not-plain-rag)
- [Code layout](#code-layout)

---

## Why generation is deterministic, not LLM-driven

![The model interprets the request and coordinates the run; the telemetry itself is built,
checked and verified by deterministic code.](../assets/figure-1-ai-vs-deterministic.png)

The Sigma corpus does three jobs, and the middle one is the important one.

**1. Precision input.** A Sigma rule states a *constraint* —
`TargetImage|endswith: '\lsass.exe'`, `GrantedAccess: '0x1410'`,
`CallTrace|contains: 'dbgcore.dll'`. `satisfy.py` inverts each constraint into a concrete
value that provably satisfies it, then `winevt.py` writes valid Windows Event XML. The
model chooses *what* to simulate; the library controls *how* the XML is written, because
malformed XML is dropped silently by Chronicle parsers and you don't find out until an
ingest cycle has burned.

![Inverting a rule: what the rule expects — LSASS access, specific access rights, a
dump-related call trace, exclusions avoided — becomes one synthetic Sysmon Event ID 10,
with nothing executed.](../assets/figure-4-rule-to-event.jpg)

**2. The oracle.** After generation, the target rules are re-evaluated against the
generated events. If the events satisfy no rule, that is a **generation** failure. Without
this check it presents identically to a **coverage** gap, and someone goes hunting for a
detection problem that does not exist. Distinguishing those two is the whole point of the
exercise.

The oracle is also checked against itself: `scripts/crosscheck_oracle.py` scores a sample
of rules through [pySigma](https://github.com/SigmaHQ/pySigma), the reference
implementation, and compares its reading of each rule's `selection` block to this project's.
A verifier sharing a codebase with the thing it verifies measures agreement, not
correctness — this is the one check in the project that doesn't share that codebase. It
found a real bug: both the oracle and the constraint inverter took Sigma's `\*` escape
literally, so they silently agreed on a value no Windows host would ever emit.

```bash
python scripts/crosscheck_oracle.py --sample 150
```

**3. Coverage cross-reference.** "Sigma publishes 79 rules for T1003.001; SecOps matched 3."

Measured 2026-08-13 against SigmaHQ commit `226e0f8`: of the 2,855 Windows rules indexed,
429 are declined as *unmappable* rather than being silently generated as the wrong event
type. Of the 2,426 rules attempted, **89.9% (2,182) produce events that satisfy their own
rule**, with zero build errors; 241 are `NO_MATCH` and 3 are `UNSUPPORTED`
(aggregation/correlation the oracle cannot evaluate against a single event).

---

## Retrieval is hybrid, not plain RAG

Sigma rules are structured YAML, not prose. Chunking them into a vector store and
retrieving text blobs discards the `detection:` block — the only part that can drive
generation. So rules are parsed into a schema first, then indexed three ways and fused with
Reciprocal Rank Fusion:

| Layer | Store | Wins on |
|---|---|---|
| Structured filter | SQLite columns | `product=windows`, `category=process_access`, MITRE technique |
| Keyword / BM25 | SQLite FTS5 | `mimikatz`, `sekurlsa`, `lsass` — exact names, where embeddings are weakest |
| Semantic | ChromaDB | "dumping credentials from memory" — intent with no shared vocabulary |

RRF rather than score normalisation, because BM25 scores and cosine distances are not on
comparable scales; rank position is all they have in common.

Both stores are local files. Chroma's default embedder is a small ONNX MiniLM — offline,
free, no API key, no `torch`.

---

## Code layout

```
purple_agent/
  config.py         env-driven settings
  platform_core.py  ADC auth, loop guard, result ceiling, anti-fabrication guards
  secops_rest.py    Chronicle REST transport and the production allowlist
  agent.py          root_agent and the Stage A/B instruction
  tools.py          local FunctionTools
  marking.py        run ids and the PT-LAB- hostname convention
  usage.py          per-session token accounting
  corpus/
    loader.py       Sigma YAML -> structured SigmaRule
    index.py        SQLite (FTS5) + Chroma index builder
    retrieve.py     hybrid search with RRF fusion
    match.py        the oracle
  synth/
    mapping.py      Sigma logsource -> Windows channel + Event ID
    satisfy.py      Sigma selector -> concrete value that satisfies it
    scenario.py     host/user/SID/LogonId/PID coherence across a chain
    winevt.py       Windows Event XML emission
    planner.py      plan -> build -> verify
scripts/
  refresh_sigma.sh / .ps1  clone/update the corpus
  build_index.py           build the index
  find_forwarder.py        discover the forwarder id import_logs needs
  validate_templates.py    run every template through the tenant's real parsers
  crosscheck_oracle.py     score the oracle against pySigma (dev-only, see requirements-dev.txt)
  check_identity.py        preflight what a credential can reach before deploying
server.py           ADK FastAPI app, for the browser UI / Cloud Run
tests/              304 tests, no tenant or network required
out/<run_id>/       Per-run artefacts: raw XML, events.json, manifest.json (gitignored)
```

```bash
python -m pytest -q
```

`scripts/crosscheck_oracle.py` needs `requirements-dev.txt` (pySigma; not installed in the
runtime image):

```bash
uv pip install --python .venv/bin/python -r requirements-dev.txt
```
