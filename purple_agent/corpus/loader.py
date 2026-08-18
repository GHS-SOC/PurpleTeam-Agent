"""Parse SigmaHQ YAML rules into a structured form.

The point of parsing rather than treating rules as text: the `detection:` block
is the only part that can drive log generation or validate a generated event,
and it is structured data. Flattening it into prose for embedding would throw
away exactly what we need.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import yaml

# Rules in these states describe detections that no longer work or that only
# gain meaning after backend-specific substitution. Neither can be validated
# against a generated event, so they are not indexed.
SKIP_STATUSES = {"deprecated", "unsupported"}


@dataclass
class SigmaRule:
    """One Sigma rule, with its detection logic kept as structured data."""

    sigma_id: str
    title: str
    description: str
    status: str
    level: str
    author: str
    date: str
    logsource_category: str
    logsource_product: str
    logsource_service: str
    detection: dict[str, Any]
    condition: str
    tags: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    filepath: str = ""
    rule_dir: str = ""

    @property
    def logsource(self) -> dict[str, str]:
        return {
            "category": self.logsource_category,
            "product": self.logsource_product,
            "service": self.logsource_service,
        }

    def searchable_text(self) -> str:
        """The text indexed for keyword and semantic search.

        Includes the flattened detection body on purpose: tool names and API
        artefacts (`sekurlsa::logonpasswords`, `\\lsass.exe`, `0x1410`) usually
        appear only there, and they are the highest-signal search terms a user
        will type.
        """
        parts = [
            self.title,
            self.description,
            " ".join(self.tags),
            self.logsource_category,
            self.logsource_product,
            self.logsource_service,
            flatten_detection(self.detection),
        ]
        return "\n".join(p for p in parts if p)

    def to_row(self) -> dict[str, Any]:
        """Flatten to a SQLite row."""
        return {
            "sigma_id": self.sigma_id,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "level": self.level,
            "author": self.author,
            "date": self.date,
            "logsource_category": self.logsource_category,
            "logsource_product": self.logsource_product,
            "logsource_service": self.logsource_service,
            "detection_json": json.dumps(self.detection),
            "condition": self.condition,
            "tags_json": json.dumps(self.tags),
            "falsepositives_json": json.dumps(self.falsepositives),
            "references_json": json.dumps(self.references),
            "filepath": self.filepath,
            "rule_dir": self.rule_dir,
        }

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "SigmaRule":
        tags = json.loads(row["tags_json"])
        return cls(
            sigma_id=row["sigma_id"],
            title=row["title"],
            description=row["description"],
            status=row["status"],
            level=row["level"],
            author=row["author"],
            date=row["date"],
            logsource_category=row["logsource_category"],
            logsource_product=row["logsource_product"],
            logsource_service=row["logsource_service"],
            detection=json.loads(row["detection_json"]),
            condition=row["condition"],
            tags=tags,
            techniques=techniques_from_tags(tags),
            falsepositives=json.loads(row["falsepositives_json"]),
            references=json.loads(row["references_json"]),
            filepath=row["filepath"],
            rule_dir=row["rule_dir"],
        )


def techniques_from_tags(tags: list[str]) -> list[str]:
    """Extract MITRE technique IDs from Sigma tags.

    Sigma writes them lowercased as `attack.t1003.001`; callers and the ATT&CK
    matrix use `T1003.001`, so normalise to the uppercase form. Software tags
    (`attack.s0002`) and tactic tags are deliberately not returned here.
    """
    out = []
    for tag in tags:
        low = tag.lower()
        if not low.startswith("attack.t"):
            continue
        candidate = low[len("attack.") :].upper()
        head = candidate.split(".")[0]
        if len(head) >= 5 and head[1:].isdigit():
            out.append(candidate)
    return sorted(set(out))


def flatten_detection(detection: Any, depth: int = 0) -> str:
    """Render a detection block as flat `key value` text for indexing."""
    if depth > 6:
        return ""
    if isinstance(detection, dict):
        parts = []
        for key, value in detection.items():
            # Strip modifiers so "CommandLine|contains" indexes as "CommandLine".
            parts.append(str(key).split("|")[0])
            parts.append(flatten_detection(value, depth + 1))
        return " ".join(p for p in parts if p)
    if isinstance(detection, list):
        return " ".join(flatten_detection(v, depth + 1) for v in detection)
    if detection is None:
        return ""
    return str(detection)


def parse_rule(path: Path, repo_dir: Path) -> SigmaRule | None:
    """Parse one Sigma YAML file. Returns None if it is unusable or skipped."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError, UnicodeDecodeError):
        return None

    if not isinstance(raw, dict):
        return None

    detection = raw.get("detection")
    if not isinstance(detection, dict):
        return None

    status = str(raw.get("status", "") or "").lower()
    if status in SKIP_STATUSES:
        return None

    sigma_id = str(raw.get("id", "") or "").strip()
    if not sigma_id:
        # Without a stable id there is nothing for the agent to reference back
        # to, and no safe primary key.
        return None

    tags = [str(t) for t in (raw.get("tags") or []) if t is not None]
    relative = path.relative_to(repo_dir).as_posix()

    return SigmaRule(
        sigma_id=sigma_id,
        title=str(raw.get("title", "") or ""),
        description=str(raw.get("description", "") or "").strip(),
        status=status,
        level=str(raw.get("level", "") or "").lower(),
        author=str(raw.get("author", "") or ""),
        date=str(raw.get("date", "") or ""),
        logsource_category=str((raw.get("logsource") or {}).get("category", "") or ""),
        logsource_product=str((raw.get("logsource") or {}).get("product", "") or ""),
        logsource_service=str((raw.get("logsource") or {}).get("service", "") or ""),
        detection={k: v for k, v in detection.items() if k != "condition"},
        condition=str(detection.get("condition", "") or ""),
        tags=tags,
        techniques=techniques_from_tags(tags),
        falsepositives=[
            str(f) for f in (raw.get("falsepositives") or []) if f is not None
        ],
        references=[str(r) for r in (raw.get("references") or []) if r is not None],
        filepath=relative,
        rule_dir=relative.split("/")[0],
    )


def load_rules(repo_dir: Path, rule_dirs: tuple[str, ...]) -> Iterator[SigmaRule]:
    """Yield every parseable, non-deprecated rule under `rule_dirs`.

    Duplicate ids are dropped -- SigmaHQ occasionally carries the same rule in
    more than one tree, and a duplicate would break the SQLite primary key.
    """
    seen: set[str] = set()
    for name in rule_dirs:
        root = repo_dir / name
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.yml")):
            rule = parse_rule(path, repo_dir)
            if rule is None or rule.sigma_id in seen:
                continue
            seen.add(rule.sigma_id)
            yield rule
