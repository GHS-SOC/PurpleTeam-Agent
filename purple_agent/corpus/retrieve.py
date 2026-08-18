"""Hybrid search over the Sigma index.

Three layers, fused with Reciprocal Rank Fusion:

- **structured filter** (SQLite columns) -- `product=windows`,
  `category=process_access`, MITRE technique. Does the heaviest lifting and is
  applied to the other two layers as a constraint, not a ranking signal.
- **keyword / BM25** (FTS5) -- `mimikatz`, `sekurlsa`, `lsass`. Exact tool and
  API names are where embeddings are weakest and literal matching is strongest.
- **semantic** (Chroma) -- "dumping credentials from memory". Intent that shares
  no vocabulary with the rule text.

RRF is used rather than score normalisation because BM25 scores and cosine
distances are not on comparable scales; rank position is the only thing the two
have in common.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Any

from .. import config
from .index import connect
from .loader import SigmaRule

# RRF damping. 60 is the value from the original Cormack et al. paper and is
# the usual default; it keeps any single layer from dominating on rank alone.
RRF_K = 60

_FTS_TOKEN = re.compile(r"[A-Za-z0-9_]+")


def _fts_query(text: str) -> str:
    """Build a safe FTS5 MATCH expression from free text.

    Tokenised and re-quoted rather than passed through: raw user text like
    `sekurlsa::logonpasswords` contains FTS5 operators and would otherwise raise
    a syntax error. OR (not the FTS5 default AND) keeps recall up -- precision
    comes from the RRF fusion and the structured filter.
    """
    tokens = _FTS_TOKEN.findall(text or "")
    return " OR ".join(f'"{t}"' for t in tokens)


def _filter_sql(
    product: str = "", category: str = "", technique_id: str = "", level: str = ""
) -> tuple[str, list[Any], bool]:
    """Build the shared WHERE clause. Returns (sql, params, needs_join)."""
    clauses: list[str] = []
    params: list[Any] = []

    if product:
        clauses.append("r.logsource_product = ?")
        params.append(product.lower())
    if category:
        clauses.append("r.logsource_category = ?")
        params.append(category.lower())
    if level:
        clauses.append("r.level = ?")
        params.append(level.lower())

    needs_join = bool(technique_id)
    if technique_id:
        clauses.append("t.technique_id = ?")
        params.append(technique_id.upper())

    sql = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return sql, params, needs_join


def _candidate_ids(conn: sqlite3.Connection, **filters: str) -> set[str] | None:
    """Ids passing the structured filter, or None when no filter was given."""
    where, params, needs_join = _filter_sql(**filters)
    if not where:
        return None
    join = " JOIN techniques t ON t.sigma_id = r.sigma_id" if needs_join else ""
    rows = conn.execute(
        f"SELECT DISTINCT r.sigma_id FROM rules r{join}{where}", params
    ).fetchall()
    return {row["sigma_id"] for row in rows}


def _keyword_ranking(
    conn: sqlite3.Connection, query: str, limit: int
) -> list[str]:
    """Ids ordered by BM25 relevance."""
    match = _fts_query(query)
    if not match:
        return []
    try:
        rows = conn.execute(
            "SELECT sigma_id FROM rules_fts WHERE rules_fts MATCH ? "
            "ORDER BY bm25(rules_fts) LIMIT ?",
            (match, limit),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    return [row["sigma_id"] for row in rows]


def _semantic_ranking(query: str, limit: int) -> list[str]:
    """Ids ordered by embedding similarity.

    Returns empty rather than raising when the vector store is missing -- an
    index built with --no-vectors should degrade to keyword search, not break.
    """
    if not query.strip() or not config.CHROMA_DIR.exists():
        return []
    try:
        from .index import _chroma_collection

        collection = _chroma_collection(config.CHROMA_DIR)
        result = collection.query(query_texts=[query], n_results=limit)
    except Exception:  # noqa: BLE001 - optional layer, never fatal
        return []
    ids = result.get("ids") or [[]]
    return list(ids[0])


def _rrf(rankings: list[list[str]], allowed: set[str] | None) -> list[tuple[str, float]]:
    """Fuse ranked id lists with Reciprocal Rank Fusion."""
    scores: dict[str, float] = {}
    for ranking in rankings:
        for position, sigma_id in enumerate(ranking):
            if allowed is not None and sigma_id not in allowed:
                continue
            scores[sigma_id] = scores.get(sigma_id, 0.0) + 1.0 / (RRF_K + position + 1)
    return sorted(scores.items(), key=lambda kv: kv[1], reverse=True)


def get_rule(sigma_id: str, conn: sqlite3.Connection | None = None) -> SigmaRule | None:
    """Fetch one rule by its Sigma id."""
    own = conn is None
    conn = conn or connect()
    try:
        row = conn.execute(
            "SELECT * FROM rules WHERE sigma_id = ?", (sigma_id,)
        ).fetchone()
        return SigmaRule.from_row(dict(row)) if row else None
    finally:
        if own:
            conn.close()


def search(
    query: str = "",
    product: str = "",
    category: str = "",
    technique_id: str = "",
    level: str = "",
    limit: int = 10,
) -> list[SigmaRule]:
    """Hybrid search. Any argument may be omitted.

    With no `query`, this degenerates to a pure structured lookup ordered by
    severity -- useful for "show me every process_access rule for T1003.001".
    """
    conn = connect()
    try:
        filters = {
            "product": product,
            "category": category,
            "technique_id": technique_id,
            "level": level,
        }
        allowed = _candidate_ids(conn, **filters)

        if not query.strip():
            if allowed is None:
                return []
            ordered = _order_by_severity(conn, allowed, limit)
            return [r for r in (get_rule(i, conn) for i in ordered) if r]

        # Over-fetch each layer: fusion needs depth, and the structured filter
        # may discard most of what a layer returns.
        depth = max(limit * 5, 50)
        rankings = [
            _keyword_ranking(conn, query, depth),
            _semantic_ranking(query, depth),
        ]

        fused = _rrf(rankings, allowed)
        return [r for r in (get_rule(i, conn) for i, _ in fused[:limit]) if r]
    finally:
        conn.close()


_SEVERITY_ORDER = "CASE r.level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 " \
                  "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"


def _order_by_severity(
    conn: sqlite3.Connection, allowed: set[str], limit: int
) -> list[str]:
    placeholders = ",".join("?" for _ in allowed)
    rows = conn.execute(
        f"SELECT r.sigma_id FROM rules r WHERE r.sigma_id IN ({placeholders}) "
        f"ORDER BY {_SEVERITY_ORDER}, r.title LIMIT ?",
        (*allowed, limit),
    ).fetchall()
    return [row["sigma_id"] for row in rows]


def rules_for_technique(technique_id: str, limit: int = 100) -> list[SigmaRule]:
    """Every indexed rule tagged with a MITRE technique.

    Used for the coverage cross-reference: "Sigma has N rules for this
    technique; SecOps managed rules matched M."
    """
    return search(technique_id=technique_id, limit=limit)


def stats() -> dict[str, Any]:
    """Index summary, for health checks and the README."""
    conn = connect()
    try:
        total = conn.execute("SELECT COUNT(*) AS n FROM rules").fetchone()["n"]
        techniques = conn.execute(
            "SELECT COUNT(DISTINCT technique_id) AS n FROM techniques"
        ).fetchone()["n"]
        per_dir = {
            row["rule_dir"]: row["n"]
            for row in conn.execute(
                "SELECT rule_dir, COUNT(*) AS n FROM rules GROUP BY rule_dir"
            )
        }
        return {
            "rules": total,
            "techniques": techniques,
            "per_directory": per_dir,
            "vectors_present": config.CHROMA_DIR.exists(),
        }
    finally:
        conn.close()
