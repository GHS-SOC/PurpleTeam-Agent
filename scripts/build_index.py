"""Build the Sigma index from the cloned corpus.

    python scripts/build_index.py            # SQLite + vectors
    python scripts/build_index.py --no-vectors

Run scripts/refresh_sigma.ps1 first to clone or update the corpus.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from purple_agent.corpus import index  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--no-vectors",
        action="store_true",
        help="Skip embeddings. Keyword and structured search still work; "
        "semantic search does not.",
    )
    args = parser.parse_args()

    started = time.monotonic()
    try:
        summary = index.build(with_vectors=not args.no_vectors)
    except (FileNotFoundError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    elapsed = time.monotonic() - started
    print(f"\nIndexed {summary['rules_indexed']} rules in {elapsed:.1f}s")
    for name, count in sorted(summary["per_directory"].items()):
        print(f"  {name:<26} {count:>5}")
    print(f"\n  database  {summary['database']}")
    if summary["vectors"]:
        print(f"  vectors   {summary['vector_count']} embedded")
    else:
        print("  vectors   skipped (semantic search unavailable)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
