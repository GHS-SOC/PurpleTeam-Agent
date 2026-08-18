"""Build and open the Sigma index: SQLite (structured + FTS5) and Chroma (vectors).

Two stores because they answer different questions. SQLite holds the parsed rule
and an FTS5 mirror for keyword search; Chroma holds embeddings for semantic
search. `retrieve.py` fuses them.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Iterable

from .. import config
from .loader import SigmaRule, load_rules

SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
    sigma_id            TEXT PRIMARY KEY,
    title               TEXT NOT NULL,
    description         TEXT,
    status              TEXT,
    level               TEXT,
    author              TEXT,
    date                TEXT,
    logsource_category  TEXT,
    logsource_product   TEXT,
    logsource_service   TEXT,
    detection_json      TEXT NOT NULL,
    condition           TEXT,
    tags_json           TEXT,
    falsepositives_json TEXT,
    references_json     TEXT,
    filepath            TEXT,
    rule_dir            TEXT
);

CREATE INDEX IF NOT EXISTS idx_rules_product  ON rules(logsource_product);
CREATE INDEX IF NOT EXISTS idx_rules_category ON rules(logsource_category);
CREATE INDEX IF NOT EXISTS idx_rules_level    ON rules(level);

CREATE TABLE IF NOT EXISTS techniques (
    sigma_id     TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    PRIMARY KEY (sigma_id, technique_id)
);
CREATE INDEX IF NOT EXISTS idx_tech ON techniques(technique_id);

-- Contentless-style mirror keyed by sigma_id. `unindexed` keeps the id
-- retrievable without it polluting match results.
CREATE VIRTUAL TABLE IF NOT EXISTS rules_fts USING fts5(
    sigma_id UNINDEXED,
    body,
    tokenize = 'unicode61'
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def connect(db_path: Path | None = None) -> sqlite3.Connection:
    """Open the rule database with dict-like rows."""
    path = db_path or config.SIGMA_DB_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def _chroma_collection(persist_dir: Path, create: bool = False):
    """Open (or create) the Chroma collection.

    Imported lazily -- chromadb pulls in a lot, and the SQLite-only paths
    (structured filters, keyword search, the oracle) must not pay for it.
    """
    import chromadb
    from chromadb.config import Settings

    client = chromadb.PersistentClient(
        path=str(persist_dir), settings=Settings(anonymized_telemetry=False)
    )
    if create:
        return client.get_or_create_collection(
            name=config.CHROMA_COLLECTION,
            # Cosine suits normalised sentence embeddings better than Chroma's
            # default L2.
            metadata={"hnsw:space": "cosine"},
        )
    return client.get_collection(name=config.CHROMA_COLLECTION)


def build(
    repo_dir: Path | None = None,
    index_dir: Path | None = None,
    with_vectors: bool = True,
    progress: bool = True,
) -> dict[str, Any]:
    """Parse the corpus and write both stores from scratch.

    Returns a summary dict with per-directory counts.
    """
    repo = repo_dir or config.SIGMA_REPO_DIR
    out_dir = index_dir or config.SIGMA_INDEX_DIR

    if not repo.is_dir():
        raise FileNotFoundError(
            f"Sigma corpus not found at {repo}. Run scripts/refresh_sigma.ps1 first."
        )

    out_dir.mkdir(parents=True, exist_ok=True)
    db_path = out_dir / "sigma.db"
    if db_path.exists():
        db_path.unlink()

    rules = list(load_rules(repo, config.SIGMA_RULE_DIRS))
    if not rules:
        raise RuntimeError(f"parsed 0 rules from {repo} -- is the clone complete?")

    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
        _insert_rules(conn, rules)
        conn.commit()
    finally:
        conn.close()

    per_dir: dict[str, int] = {}
    for rule in rules:
        per_dir[rule.rule_dir] = per_dir.get(rule.rule_dir, 0) + 1

    summary: dict[str, Any] = {
        "rules_indexed": len(rules),
        "per_directory": per_dir,
        "database": str(db_path),
        "vectors": False,
    }

    if with_vectors:
        summary["vectors"] = True
        summary["vector_count"] = _build_vectors(rules, out_dir / "chroma", progress)

    return summary


def _insert_rules(conn: sqlite3.Connection, rules: Iterable[SigmaRule]) -> None:
    columns = [
        "sigma_id", "title", "description", "status", "level", "author", "date",
        "logsource_category", "logsource_product", "logsource_service",
        "detection_json", "condition", "tags_json", "falsepositives_json",
        "references_json", "filepath", "rule_dir",
    ]
    placeholders = ", ".join(f":{c}" for c in columns)
    insert = f"INSERT INTO rules ({', '.join(columns)}) VALUES ({placeholders})"

    for rule in rules:
        conn.execute(insert, rule.to_row())
        conn.execute(
            "INSERT INTO rules_fts (sigma_id, body) VALUES (?, ?)",
            (rule.sigma_id, rule.searchable_text()),
        )
        for technique in rule.techniques:
            conn.execute(
                "INSERT OR IGNORE INTO techniques (sigma_id, technique_id) VALUES (?, ?)",
                (rule.sigma_id, technique),
            )


def _build_vectors(rules: list[SigmaRule], persist_dir: Path, progress: bool) -> int:
    """Embed rules into Chroma.

    Chroma's default embedding function is a small ONNX MiniLM: offline, free,
    no torch, and ample for ~3k short documents.
    """
    import shutil

    if persist_dir.exists():
        shutil.rmtree(persist_dir)
    persist_dir.mkdir(parents=True, exist_ok=True)

    collection = _chroma_collection(persist_dir, create=True)

    # The embedded document is title + description + tags, NOT the flattened
    # detection body. Detection blocks are dense literals (paths, hex masks)
    # that add noise to a semantic vector; keyword search already covers them,
    # and each layer should do the job it is good at.
    batch = 500
    total = 0
    for start in range(0, len(rules), batch):
        chunk = rules[start : start + batch]
        collection.add(
            ids=[r.sigma_id for r in chunk],
            documents=[
                "\n".join(p for p in (r.title, r.description, " ".join(r.tags)) if p)
                for r in chunk
            ],
            metadatas=[
                {
                    "product": r.logsource_product,
                    "category": r.logsource_category,
                    "service": r.logsource_service,
                    "level": r.level,
                }
                for r in chunk
            ],
        )
        total += len(chunk)
        if progress:
            print(f"  embedded {total}/{len(rules)}", flush=True)
    return total
