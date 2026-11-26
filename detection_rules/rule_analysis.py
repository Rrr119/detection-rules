# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Semantic deduplication, conflict detection and coverage reporting for rules.

规则语义去重、冲突检测与覆盖度报告。

This module is deliberately additive and non-invasive:

* it does not change rule loading, validation or packaging, so normal rule
  builds are unaffected;
* it parses the existing TOML/JSON rule format directly and tolerates
  incomplete or schema-invalid fixtures (useful when duplicate/conflicting
  rules are injected for acceptance checks);
* it can also consume existing :class:`~detection_rules.rule.TOMLRule`
  objects and :class:`~detection_rules.rule_loader.RuleCollection`.

The main entry points are:

* :func:`load_records` -- load rule records from files/directories;
* :func:`analyze_rules` -- dedup + conflict + coverage in one report;
* :func:`detect_duplicates_and_conflicts` -- only the findings;
* :func:`build_coverage_report` -- coverage statistics.
"""

# The scoring engine is heuristic: thresholds and deeply branched category
# decisions are intentional, so relax magic-number/complexity lint here.
# ruff: noqa: PLR2004, PLR0912, PLR0913, PLR0915, PLR0917

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

try:  # Python 3.11+ standard library
    import tomllib as _tomllib
except ModuleNotFoundError:  # pragma: no cover - fallback for older runtimes
    _tomllib = None  # type: ignore[assignment]

import pytoml  # type: ignore[reportMissingTypeStubs]

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

# ---------------------------------------------------------------------------
# Constants / taxonomies
# ---------------------------------------------------------------------------

SEVERITY_ORDER: dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Canonical risk score shipped by this repository for each severity.
SEVERITY_RISK_SCORE: dict[str, int] = {"low": 21, "medium": 47, "high": 73, "critical": 99}

# Enterprise ATT&CK tactics in kill-chain order (used for coverage gaps).
ENTERPRISE_TACTICS: tuple[str, ...] = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)

RULE_FILE_SUFFIXES = {".toml", ".json", ".ndjson", ".jsonl"}

# Similarity thresholds (kept as named constants so callers/tests can tune).
EXACT_TOKEN_JACCARD = 0.97
SEMANTIC_TOKEN_JACCARD = 0.82
SEMANTIC_TOKEN_OVERLAP = 0.90
SEMANTIC_PREDICATE_OVERLAP = 0.75
CONFLICT_PREDICATE_OVERLAP = 0.5
CONFLICT_TOKEN_JACCARD = 0.5

# Structural query words / ubiquitous fields are ignored for similarity so
# that common boilerplate does not make unrelated rules look equivalent.
QUERY_STOPWORDS: set[str] = {
    "where",
    "and",
    "or",
    "not",
    "in",
    "by",
    "with",
    "within",
    "without",
    "sequence",
    "join",
    "until",
    "maxspan",
    "any",
    "all",
    "of",
    "none",
    "the",
    "a",
    "an",
    "as",
    "on",
    "to",
    "from",
    "for",
    "if",
    "then",
    "else",
    "while",
    "group",
    "asc",
    "desc",
    "sort",
    "limit",
    "tail",
    "head",
    "true",
    "false",
    "null",
    "exists",
    "event",
    "events",
    "ecs",
    "kind",
    "category",
    "outcome",
    "type",
    "host",
    "os",
    "platform",
    "name",
    "id",
}


# ---------------------------------------------------------------------------
# Loading / normalizing records
# ---------------------------------------------------------------------------


def _read_structured_file(path: Path) -> list[dict[str, Any]]:
    """Read a TOML/JSON/NDJSON file into one or more raw dictionaries."""
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()

    if suffix == ".toml":
        data = (
            _tomllib.loads(text)  # type: ignore[reportUnknownMemberType]
            if _tomllib is not None
            else pytoml.loads(text)
        )
        return [data] if isinstance(data, dict) else list(data)

    if suffix in (".ndjson", ".jsonl"):
        rows: list[dict[str, Any]] = []
        for raw_line in text.splitlines():
            stripped_line = raw_line.strip()
            if stripped_line:
                obj = json.loads(stripped_line)
                if isinstance(obj, dict):
                    rows.append(obj)
        return rows

    data = json.loads(text)
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        # A Kibana NDJSON export can wrap objects; JSON rule is just a dict.
        return [data]
    return []


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _rule_section(raw: dict[str, Any]) -> dict[str, Any]:
    """Return the mapping that holds rule fields for TOML and API shapes.

    Repository TOML files use ``[metadata]`` + ``[rule]`` while exported API
    objects place rule fields at the top level.
    """
    rule = raw.get("rule")
    if isinstance(rule, dict):
        return rule
    return raw


def _metadata_section(raw: dict[str, Any], rule: dict[str, Any]) -> dict[str, Any]:
    metadata = raw.get("metadata")
    if isinstance(metadata, dict):
        return metadata
    # API-shaped rules sometimes carry these fields on the rule object itself.
    return rule if isinstance(rule.get("integration"), (list, str)) else {}


_NON_ALNUM_RE = re.compile(r"[^a-z0-9_*?]+")


def normalize_text(value: str | None) -> str:
    """Lowercase and collapse punctuation for robust comparison."""
    if not value:
        return ""
    text = value.lower()
    # Preserve explicit inequality before punctuation is collapsed away.
    text = text.replace("!=", " not_eq ").replace("<>", " not_eq ")
    text = _NON_ALNUM_RE.sub(" ", text)
    return re.sub(r"\s+", " ", text).strip()


def _name_key(name: str | None) -> str:
    key = normalize_text(name or "")
    # Deprecated rules are renamed with a prefix; compare the underlying name.
    for prefix in ("deprecated ", "deprecated"):
        if key.startswith(prefix):
            key = key[len(prefix) :].strip()
    return key


_PREDICATE_RE = re.compile(
    r"(?P<field>[A-Za-z0-9_.@\-]+)\s*"
    r"(?P<op>==|!=|>=|<=|:|=|\bnot\s+in\b|\bin\b)\s*"
    r"(?P<val>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|\([^)]*\)|[^\s,)\]}]+)",
    re.IGNORECASE,
)


def _split_values(raw_value: str) -> list[str]:
    value = raw_value.strip()
    if value.startswith("(") and value.endswith(")"):
        value = value[1:-1]
    # KQL/EQL tuples can be comma and/or "or"/"and" separated.
    value = re.sub(r"\b(?:or|and)\b", ",", value, flags=re.IGNORECASE)
    parts = [part for part in re.split(r"[,\s]+", value) if part]
    cleaned: list[str] = []
    for part in parts:
        token_value = part.strip().strip("'\"")
        if not token_value or token_value.lower() in {"or", "and", "not"}:
            continue
        normalized = normalize_text(token_value).replace(" ", "_")
        if normalized and normalized not in {"or", "and", "not"}:
            cleaned.append(normalized)
    return cleaned


def _match_closing_paren(text: str, open_index: int) -> int:
    """Return the index of the ')' matching the '(' at ``open_index``."""
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return len(text) - 1


def _negated_ranges(query: str) -> list[tuple[int, int]]:
    """Find character ranges governed by ``not (...)`` groups."""
    ranges: list[tuple[int, int]] = []
    for match in re.finditer(r"\bnot\b", query, flags=re.IGNORECASE):
        index = match.end()
        while index < len(query) and query[index].isspace():
            index += 1
        if index < len(query) and query[index] == "(":
            ranges.append((match.start(), _match_closing_paren(query, index)))
    return ranges


def _is_negated(text: str, match_start: int, op: str) -> bool:
    if op in ("!=", "<>"):
        return True
    prefix = text[max(0, match_start - 60) : match_start]
    # Explicit "not field ..." or "and not (field ..." right before the field.
    if re.search(r"\bnot\s*\(?\s*$", prefix, re.IGNORECASE):
        return True
    # A lone "!" directly attached to the field, e.g. "!process.name:".
    before = text[max(0, match_start - 2) : match_start]
    return "!" in before


def extract_predicates(query: str | None) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    """Extract positive and negative ``(field, value)`` predicates.

    The extraction is heuristic on purpose: it works across KQL, EQL and
    ES|QL-like text without depending on every grammar parser being available.
    """
    positive: set[tuple[str, str]] = set()
    negative: set[tuple[str, str]] = set()
    if not query:
        return positive, negative

    neg_ranges = _negated_ranges(query)

    def in_negated_group(start: int) -> bool:
        return any(left <= start <= right for left, right in neg_ranges)

    for match in _PREDICATE_RE.finditer(query):
        field = match.group("field").lower()
        op = match.group("op").lower()
        if op in (">", "<", ">=", "<="):
            continue
        # Skip IPv6/CIDR literals such as "FE80::/10" that the field regex
        # can otherwise mistake for a "field:value" predicate.
        if re.fullmatch(r"[0-9a-f]*\d[0-9a-f]*", field) and len(field) >= 3 and "." not in field:
            continue
        values = _split_values(match.group("val"))
        if not values:
            continue
        negated = (
            op.replace(" ", "") in {"!=", "<>", "notin"}
            or in_negated_group(match.start("field"))
            or _is_negated(query, match.start("field"), op)
        )
        target = negative if negated else positive
        for value in values:
            target.add((field, value))
    return positive, negative


_WHERE_RE = re.compile(r"([a-z_][a-z0-9_]*)\s+where\b", re.IGNORECASE)
_EVENT_CATEGORY_RE = re.compile(r"event\.category\s*(?::|==|=)\s*\"?([a-z0-9_\-]+)", re.IGNORECASE)


def extract_categories(query: str | None) -> set[str]:
    categories: set[str] = set()
    if not query:
        return categories
    for match in _WHERE_RE.finditer(query):
        word = match.group(1).lower()
        if word not in {"where", "sequence", "by", "join", "any"}:
            categories.add(word)
    for match in _EVENT_CATEGORY_RE.finditer(query):
        categories.add(match.group(1).lower())
    return categories


def _collect_threat(threat: Any) -> tuple[list[str], list[str]]:
    tactics: list[str] = []
    techniques: list[str] = []
    for entry in _as_list(threat):
        if not isinstance(entry, dict):
            continue
        tactic = entry.get("tactic") or {}
        if isinstance(tactic, dict):
            name = tactic.get("name")
            if name:
                tactics.append(str(name))
            tactic_id = tactic.get("id")
            if tactic_id:
                tactics.append(str(tactic_id))
        for technique in _as_list(entry.get("technique")):
            if not isinstance(technique, dict):
                continue
            tech_id = technique.get("id")
            if tech_id:
                techniques.append(str(tech_id))
            techniques.extend(
                str(sub["id"])
                for sub in _as_list(technique.get("subtechnique"))
                if isinstance(sub, dict) and sub.get("id")
            )
    return tactics, techniques


def _collect_tags(tags: Any, prefix: str) -> list[str]:
    result: list[str] = []
    needle = prefix.lower()
    for tag in _as_list(tags):
        if not isinstance(tag, str):
            continue
        if tag.lower().startswith(needle):
            result.append(tag.split(":", 1)[1].strip())
    return result


@dataclass
class RuleRecord:
    """A format-tolerant view over a single detection rule."""

    name: str = ""
    rule_id: str | None = None
    path: str | None = None
    rule_type: str | None = None
    language: str | None = None
    query: str = ""
    indices: list[str] = field(default_factory=list)
    severity: str | None = None
    risk_score: int | None = None
    tags: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    integrations: list[str] = field(default_factory=list)
    maturity: str | None = None
    parse_error: str | None = None

    # Derived fingerprints (populated by :func:`prepare_record`).
    name_key: str = ""
    query_key: str = ""
    query_hash: str | None = None
    tokens: set[str] = field(default_factory=set)
    predicates_pos: set[tuple[str, str]] = field(default_factory=set)
    predicates_neg: set[tuple[str, str]] = field(default_factory=set)
    categories: set[str] = field(default_factory=set)

    @property
    def signed_predicates(self) -> set[str]:
        signed = {f"{f}={v}" for f, v in self.predicates_pos}
        signed.update(f"{f}!={v}" for f, v in self.predicates_neg)
        return signed

    def identity(self) -> dict[str, str | None]:
        return {"rule_id": self.rule_id, "name": self.name, "path": self.path}


def record_from_dict(raw: dict[str, Any], path: str | Path | None = None) -> RuleRecord:
    """Build a :class:`RuleRecord` from a raw TOML/JSON dictionary."""
    rule = _rule_section(raw)
    metadata = _metadata_section(raw, rule)

    threat_tactics, threat_techniques = _collect_threat(rule.get("threat"))
    tag_tactics = _collect_tags(rule.get("tags"), "tactic:")
    platforms = _collect_tags(rule.get("tags"), "platform:")
    os_tags = _collect_tags(rule.get("tags"), "os:")
    data_sources = _collect_tags(rule.get("tags"), "data source:")

    indices = [str(i) for i in _as_list(rule.get("index")) if i]
    integrations = [str(i) for i in _as_list(metadata.get("integration")) if i]
    integrations.extend(data_sources)

    risk_score = rule.get("risk_score")
    try:
        risk_score = int(risk_score) if risk_score is not None else None
    except (TypeError, ValueError):
        risk_score = None

    record = RuleRecord(
        name=str(rule.get("name") or raw.get("name") or ""),
        rule_id=(str(rule.get("rule_id") or raw.get("rule_id") or raw.get("id") or "") or None),
        path=str(path) if path is not None else None,
        rule_type=rule.get("type"),
        language=rule.get("language"),
        query=str(rule.get("query") or ""),
        indices=indices,
        severity=(str(rule.get("severity")).lower() if rule.get("severity") else None),
        risk_score=risk_score,
        tags=[str(t) for t in _as_list(rule.get("tags")) if isinstance(t, str)],
        tactics=sorted({*threat_tactics, *tag_tactics}),
        techniques=sorted(set(threat_techniques)),
        platforms=sorted({*platforms, *os_tags}),
        integrations=sorted(set(integrations)),
        maturity=(str(metadata.get("maturity")).lower() if metadata.get("maturity") else None),
    )

    if not record.platforms and path is not None:
        record.platforms = _platforms_from_path(Path(path))

    prepare_record(record)
    return record


def _platforms_from_path(path: Path) -> list[str]:
    parts = {p.lower() for p in path.parts}
    mapping = {
        "windows": "Windows",
        "linux": "Linux",
        "macos": "macOS",
        "aws": "AWS",
        "azure": "Azure",
        "gcp": "GCP",
        "okta": "Okta",
        "kubernetes": "Kubernetes",
        "network": "Network",
    }
    return [label for part, label in mapping.items() if part in parts]


def prepare_record(record: RuleRecord) -> RuleRecord:
    """Populate derived fingerprint fields in place."""
    record.name_key = _name_key(record.name)
    record.query_key = normalize_text(record.query)
    if record.query_key:
        # sha1 is used only as a non-adversarial content fingerprint, not for security.
        record.query_hash = hashlib.sha1(record.query_key.encode("utf-8"), usedforsecurity=False).hexdigest()[:16]
        record.tokens = set(record.query_key.split(" "))
    record.predicates_pos, record.predicates_neg = extract_predicates(record.query)
    record.categories = extract_categories(record.query)
    return record


def record_from_toml_rule(rule: Any) -> RuleRecord:
    """Adapt a :class:`~detection_rules.rule.TOMLRule` to a :class:`RuleRecord`."""
    contents = getattr(rule, "contents", None)
    as_dict: dict[str, Any]
    if contents is not None and hasattr(contents, "to_dict"):
        try:
            as_dict = contents.to_dict()
        except Exception:  # noqa: BLE001 - defensive: fall back to data attr
            as_dict = {}
        if not isinstance(as_dict, dict) or "rule" not in as_dict:
            data = getattr(contents, "data", None)
            as_dict = dict(data) if isinstance(data, dict) else _dataclass_to_dict(data)
    else:
        as_dict = _dataclass_to_dict(contents)

    path = getattr(rule, "path", None)
    return record_from_dict(as_dict, path=path)


def _dataclass_to_dict(obj: Any) -> dict[str, Any]:
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    try:
        from dataclasses import asdict

        return asdict(obj)
    except Exception:  # noqa: BLE001
        return {k: getattr(obj, k) for k in dir(obj) if not k.startswith("_") and not callable(getattr(obj, k))}


def iter_rule_files(paths: Sequence[str | Path], include_deprecated: bool = False) -> list[Path]:
    """Expand files/directories into supported rule file paths."""
    files: list[Path] = []

    def accepted(path: Path) -> bool:
        return path.suffix.lower() in RULE_FILE_SUFFIXES and (include_deprecated or "_deprecated" not in path.parts)

    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists():
            continue
        if path.is_file():
            if accepted(path):
                files.append(path)
        elif path.is_dir():
            files.extend(child for child in sorted(path.rglob("*")) if child.is_file() and accepted(child))
    # Stable + de-duplicated.
    return sorted(set(files))


def load_records(
    paths: str | Path | Sequence[str | Path],
    include_deprecated: bool = False,
) -> tuple[list[RuleRecord], list[dict[str, str]]]:
    """Load rule records from the given files/directories.

    Returns ``(records, errors)`` where each error describes an unreadable
    file; parsing never raises for a single bad file.
    """
    if isinstance(paths, (str, Path)):
        paths = [paths]

    records: list[RuleRecord] = []
    errors: list[dict[str, str]] = []

    for file_path in iter_rule_files(list(paths), include_deprecated=include_deprecated):
        try:
            rows = _read_structured_file(file_path)
        except Exception as exc:  # noqa: BLE001 - report and continue
            errors.append({"path": str(file_path), "error": f"{type(exc).__name__}: {exc}"})
            continue

        if not rows:
            errors.append({"path": str(file_path), "error": "no rule objects found"})
            continue

        for row_index, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            try:
                suffix = f"#{row_index}" if len(rows) > 1 else ""
                record = record_from_dict(row, path=Path(f"{file_path}{suffix}") if suffix else file_path)
            except Exception as exc:  # noqa: BLE001
                errors.append({"path": str(file_path), "error": f"{type(exc).__name__}: {exc}"})
                continue
            if not record.name and not record.query and not record.rule_id:
                errors.append({"path": str(file_path), "error": "missing name/query/rule_id"})
                continue
            records.append(record)

    return records, errors


def records_from_rules(rules: Iterable[Any]) -> list[RuleRecord]:
    """Adapt an iterable of ``TOMLRule``/dict objects into records."""
    records: list[RuleRecord] = []
    for item in rules:
        if isinstance(item, RuleRecord):
            records.append(item)
        elif isinstance(item, dict):
            records.append(record_from_dict(item))
        else:
            records.append(record_from_toml_rule(item))
    return records


# ---------------------------------------------------------------------------
# Similarity helpers
# ---------------------------------------------------------------------------


def _jaccard(a: set[Any], b: set[Any]) -> float:
    if not a or not b:
        return 0.0
    union = len(a | b)
    return len(a & b) / union if union else 0.0


def _overlap(a: set[Any], b: set[Any]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / min(len(a), len(b))


@dataclass
class PairScore:
    token_jaccard: float = 0.0
    token_overlap: float = 0.0
    predicate_jaccard: float = 0.0
    predicate_overlap: float = 0.0
    shared_predicates: int = 0
    name_jaccard: float = 0.0
    exact_query: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "token_jaccard": round(self.token_jaccard, 3),
            "token_overlap": round(self.token_overlap, 3),
            "predicate_jaccard": round(self.predicate_jaccard, 3),
            "predicate_overlap": round(self.predicate_overlap, 3),
            "shared_predicates": self.shared_predicates,
            "name_jaccard": round(self.name_jaccard, 3),
            "exact_query": self.exact_query,
        }


def score_pair(a: RuleRecord, b: RuleRecord) -> PairScore:
    """Compute the semantic similarity scores for two rules."""
    score = PairScore()
    score.exact_query = bool(a.query_hash and a.query_hash == b.query_hash and a.query_key)
    score.token_jaccard = _jaccard(a.tokens, b.tokens)
    score.token_overlap = _overlap(a.tokens, b.tokens)
    score.predicate_jaccard = _jaccard(a.signed_predicates, b.signed_predicates)
    score.predicate_overlap = _overlap(a.signed_predicates, b.signed_predicates)
    score.shared_predicates = len(a.signed_predicates & b.signed_predicates)

    name_a = set(a.name_key.split(" ")) if a.name_key else set()
    name_b = set(b.name_key.split(" ")) if b.name_key else set()
    score.name_jaccard = _jaccard(name_a, name_b)
    return score


class PairEvaluator:
    """Build document frequencies and judge rule pairs with precision.

    Common boilerplate predicates/tokens (e.g. ``event.type:start`` or
    ``host.os.type:windows`` across hundreds of rules) are down-weighted so
    that only distinctive detection logic drives duplicate/conflict calls.
    """

    def __init__(self, records: Sequence[RuleRecord]) -> None:
        self.records = records
        count = len(records)
        predicate_df: dict[tuple[str, str], int] = {}
        token_df: dict[str, int] = {}
        for record in records:
            unsigned = record.predicates_pos | record.predicates_neg
            for predicate in unsigned:
                predicate_df[predicate] = predicate_df.get(predicate, 0) + 1
            for token in record.tokens:
                token_df[token] = token_df.get(token, 0) + 1

        predicate_cutoff = max(25.0, 0.03 * count)
        token_cutoff = max(10.0, 0.25 * count)
        self.common_predicates = {p for p, df in predicate_df.items() if df > predicate_cutoff}
        self.common_tokens = {t for t, df in token_df.items() if df > token_cutoff}

    def filtered_tokens(self, record: RuleRecord) -> set[str]:
        return {
            token
            for token in record.tokens
            if token not in QUERY_STOPWORDS and token not in self.common_tokens and len(token) > 1
        }

    def distinctive_predicates(self, record: RuleRecord) -> set[tuple[str, str]]:
        return (record.predicates_pos | record.predicates_neg) - self.common_predicates

    def evaluate(self, i: int, j: int) -> dict[str, Any]:
        a, b = self.records[i], self.records[j]
        raw = score_pair(a, b)

        tokens_a = self.filtered_tokens(a)
        tokens_b = self.filtered_tokens(b)
        filtered_jaccard = _jaccard(tokens_a, tokens_b)
        filtered_overlap = _overlap(tokens_a, tokens_b)

        preds_a = self.distinctive_predicates(a)
        preds_b = self.distinctive_predicates(b)
        shared_distinctive = preds_a & preds_b
        distinctive_overlap = _overlap(preds_a, preds_b)

        unsigned_a = a.predicates_pos | a.predicates_neg
        unsigned_b = b.predicates_pos | b.predicates_neg
        shared_unsigned = unsigned_a & unsigned_b
        unsigned_overlap = _overlap(unsigned_a, unsigned_b)

        shared_positive = a.predicates_pos & b.predicates_pos
        positive_jaccard = _jaccard(a.predicates_pos, b.predicates_pos)
        positive_overlap = _overlap(a.predicates_pos, b.predicates_pos)

        exact = raw.exact_query
        has_distinctive = len(shared_distinctive) >= 1
        token_symmetric_diff = len(tokens_a ^ tokens_b)
        small_token_diff = token_symmetric_diff <= max(6, int(0.25 * max(1, min(len(tokens_a), len(tokens_b)))))

        # Near-verbatim / same predicate set => semantic duplicate.
        semantic_duplicate = False
        confidence = 0.0
        reason = ""
        category = "duplicate.semantic_query"

        if exact:
            semantic_duplicate = True
            confidence = 0.99
            category = "duplicate.exact_query"
            reason = "normalized queries are identical"
        elif filtered_jaccard >= 0.92 and small_token_diff and has_distinctive:
            semantic_duplicate = True
            confidence = 0.92
            reason = "query token sets are near-identical after removing boilerplate"
        elif positive_jaccard >= 0.85 and len(shared_positive) >= 1 and small_token_diff:
            semantic_duplicate = True
            confidence = 0.88
            category = "duplicate.semantic_predicate"
            reason = "positive selection predicates are essentially the same"
        elif positive_overlap >= 0.9 and len(shared_positive) >= 2 and filtered_jaccard >= 0.6:
            semantic_duplicate = True
            confidence = 0.82
            category = "duplicate.semantic_predicate"
            reason = "one rule's positive predicates are contained in the other's"
        elif distinctive_overlap >= 0.9 and len(shared_distinctive) >= 2 and filtered_jaccard >= 0.7:
            semantic_duplicate = True
            confidence = 0.74
            category = "duplicate.semantic_predicate"
            reason = "queries are built around the same distinctive predicate"

        # Strong same-behavior relation for metadata conflict checks.
        same_behavior = (
            semantic_duplicate
            or (positive_jaccard >= 0.8 and len(shared_positive) >= 2 and filtered_jaccard >= 0.6)
            or (distinctive_overlap >= 0.92 and len(shared_distinctive) >= 2 and filtered_jaccard >= 0.7)
        )

        # Polarity clash (require vs exclude the same predicate).
        polar_clash = sorted((a.predicates_pos & b.predicates_neg) | (a.predicates_neg & b.predicates_pos))
        distinctive_clash = [
            (field_name, value)
            for field_name, value in polar_clash
            if (field_name, value) not in self.common_predicates
        ]
        logic_conflict = bool(distinctive_clash) and (
            semantic_duplicate
            or (positive_jaccard >= 0.6 and filtered_jaccard >= 0.6)
            or (unsigned_overlap >= 0.6 and filtered_jaccard >= 0.7)
        )

        return {
            "raw": raw,
            "filtered_jaccard": filtered_jaccard,
            "filtered_overlap": filtered_overlap,
            "distinctive_overlap": distinctive_overlap,
            "shared_distinctive": len(shared_distinctive),
            "unsigned_overlap": unsigned_overlap,
            "shared_unsigned": len(shared_unsigned),
            "positive_jaccard": positive_jaccard,
            "positive_overlap": positive_overlap,
            "shared_positive": len(shared_positive),
            "semantic_duplicate": semantic_duplicate,
            "duplicate_confidence": confidence,
            "duplicate_category": category,
            "duplicate_reason": reason,
            "same_behavior": same_behavior,
            "polar_clash": [f"{field_name}={value}" for field_name, value in distinctive_clash[:10]],
            "logic_conflict": logic_conflict,
        }


# ---------------------------------------------------------------------------
# Dedup + conflict detection
# ---------------------------------------------------------------------------


def _finding(
    finding_id: str,
    kind: str,
    category: str,
    records: Sequence[RuleRecord],
    pair_indexes: Sequence[int],
    confidence: float,
    title: str,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "kind": kind,  # "duplicate" | "conflict"
        "category": category,
        "confidence": round(confidence, 2),
        "title": title,
        "evidence": evidence or {},
        "rules": [records[i].identity() | {"index": i} for i in pair_indexes],
        "rule_indexes": list(pair_indexes),
    }


def _pair_candidates(records: Sequence[RuleRecord]) -> Iterable[tuple[int, int]]:
    """Yield index pairs to compare.

    Small sets are compared exhaustively. Large sets use an inverted index on
    predicates/discriminative tokens so the full repository stays fast.
    """
    n = len(records)
    if n <= 400:
        for i in range(n):
            for j in range(i + 1, n):
                yield i, j
        return

    # Blocking for large collections.
    postings: dict[str, set[int]] = {}

    def add_feature(feature: str, idx: int) -> None:
        postings.setdefault(feature, set()).add(idx)

    for idx, record in enumerate(records):
        for field_name, value in record.predicates_pos | record.predicates_neg:
            add_feature(f"pred:{field_name}|{value}", idx)
            add_feature(f"field:{field_name}", idx)
        for token in record.tokens:
            if len(token) >= 6 and not token.startswith(("http", "www")):
                add_feature(f"token:{token}", idx)

    common_limit = max(50, n // 20)
    candidates: dict[tuple[int, int], int] = {}
    for owners in postings.values():
        if len(owners) > common_limit:
            continue
        owners_list = sorted(owners)
        for pos, i in enumerate(owners_list):
            for j in owners_list[pos + 1 :]:
                key = (i, j) if i < j else (j, i)
                candidates[key] = candidates.get(key, 0) + 1

    for (i, j), shared_features in candidates.items():
        if shared_features >= 1:
            yield i, j


def detect_duplicates_and_conflicts(
    records: Sequence[RuleRecord],
) -> list[dict[str, Any]]:
    """Detect and classify duplicate and conflicting rules.

    Every finding has ``kind`` in ``{"duplicate", "conflict"}`` and a more
    specific ``category`` string.
    """
    findings: list[dict[str, Any]] = []
    counter = 0

    def next_id(category: str) -> str:
        nonlocal counter
        counter += 1
        return f"{category}-{counter:03d}"

    # ---- Identity groupings: rule_id and normalized name -----------------
    by_rule_id: dict[str, list[int]] = {}
    by_name: dict[str, list[int]] = {}
    by_query_hash: dict[str, list[int]] = {}
    for idx, record in enumerate(records):
        if record.rule_id:
            by_rule_id.setdefault(record.rule_id, []).append(idx)
        if record.name_key and len(record.name_key) >= 4:
            by_name.setdefault(record.name_key, []).append(idx)
        if record.query_hash:
            by_query_hash.setdefault(record.query_hash, []).append(idx)

    seen_pairs: set[tuple[int, int, str]] = set()
    priority_pairs: set[tuple[int, int]] = set()

    def register_pair_finding(
        kind: str,
        category: str,
        pair: tuple[int, int],
        confidence: float,
        title: str,
        evidence: dict[str, Any] | None = None,
    ) -> None:
        dedup_key = (pair[0], pair[1], category)
        if dedup_key in seen_pairs:
            return
        seen_pairs.add(dedup_key)
        findings.append(_finding(next_id(category), kind, category, records, pair, confidence, title, evidence))

    for rule_id, indexes in by_rule_id.items():
        if len(indexes) < 2:
            continue
        for pos, i in enumerate(indexes):
            for j in indexes[pos + 1 :]:
                pair = (min(i, j), max(i, j))
                priority_pairs.add(pair)
                same_query = records[i].query_hash == records[j].query_hash and bool(records[i].query_hash)
                same_name = records[i].name_key == records[j].name_key
                if same_query and same_name:
                    register_pair_finding(
                        "duplicate",
                        "duplicate.rule_id",
                        pair,
                        0.98,
                        f"rule_id {rule_id} is reused by identical rules",
                        {"rule_id": rule_id},
                    )
                else:
                    register_pair_finding(
                        "conflict",
                        "conflict.rule_id",
                        pair,
                        0.97,
                        f"rule_id {rule_id} maps to different rule content",
                        {"rule_id": rule_id, "same_query": same_query, "same_name": same_name},
                    )

    for name_key, indexes in by_name.items():
        if len(indexes) < 2:
            continue
        for pos, i in enumerate(indexes):
            for j in indexes[pos + 1 :]:
                pair = (min(i, j), max(i, j))
                priority_pairs.add(pair)
                if records[i].rule_id and records[i].rule_id == records[j].rule_id:
                    continue  # already handled by rule_id grouping
                score = score_pair(records[i], records[j])
                category = "duplicate.exact_query" if score.exact_query else "duplicate.name"
                register_pair_finding(
                    "duplicate",
                    category,
                    pair,
                    0.98 if score.exact_query else 0.85,
                    "rules share the same normalized name but different rule_id",
                    {"normalized_name": name_key, "scores": score.as_dict()},
                )

    # Exact normalized-query duplicates are grouped globally so they are
    # detected even on large repositories regardless of pair blocking.
    for query_hash, indexes in by_query_hash.items():
        if len(indexes) < 2:
            continue
        for pos, i in enumerate(indexes):
            for j in indexes[pos + 1 :]:
                pair = (min(i, j), max(i, j))
                priority_pairs.add(pair)
                register_pair_finding(
                    "duplicate",
                    "duplicate.exact_query",
                    pair,
                    0.99,
                    "normalized queries are identical despite cosmetic differences",
                    {"query_hash": query_hash},
                )

    # ---- Query / semantic pair analysis ----------------------------------
    evaluator = PairEvaluator(records)
    candidate_pairs = set(_pair_candidates(records))
    candidate_pairs.update(priority_pairs)

    for pair in sorted(candidate_pairs):
        i, j = pair
        a, b = records[i], records[j]
        verdict = evaluator.evaluate(i, j)
        score = verdict["raw"]
        is_dup = verdict["semantic_duplicate"]

        if is_dup:
            register_pair_finding(
                "duplicate",
                verdict["duplicate_category"],
                pair,
                verdict["duplicate_confidence"],
                "semantically equivalent detection logic",
                {
                    "reason": verdict["duplicate_reason"],
                    "filtered_jaccard": round(verdict["filtered_jaccard"], 3),
                    "distinctive_overlap": round(verdict["distinctive_overlap"], 3),
                    "shared_distinctive_predicates": verdict["shared_distinctive"],
                    "scores": score.as_dict(),
                },
            )

        if not verdict["same_behavior"] and not verdict["logic_conflict"]:
            continue

        # Severity / risk-score contradiction on the same detection behavior.
        if a.severity and b.severity and a.severity != b.severity and verdict["same_behavior"]:
            expected_a = SEVERITY_RISK_SCORE.get(a.severity)
            expected_b = SEVERITY_RISK_SCORE.get(b.severity)
            risk_gap: int | None = None
            if a.risk_score is not None and b.risk_score is not None:
                risk_gap = abs(a.risk_score - b.risk_score)
            inconsistent_score = risk_gap is not None and risk_gap >= 20
            far_apart = abs(SEVERITY_ORDER.get(a.severity, 0) - SEVERITY_ORDER.get(b.severity, 0)) >= 2
            if is_dup or inconsistent_score or far_apart:
                register_pair_finding(
                    "conflict",
                    "conflict.severity",
                    pair,
                    0.9 if is_dup else 0.7,
                    "same behavior classified with contradictory severity/risk score",
                    {
                        "severity": [a.severity, b.severity],
                        "risk_score": [a.risk_score, b.risk_score],
                        "expected_risk_score": [expected_a, expected_b],
                        "risk_score_gap": risk_gap,
                        "filtered_jaccard": round(verdict["filtered_jaccard"], 3),
                        "scores": score.as_dict(),
                    },
                )

        # Predicate polarity contradiction (require vs exclude the same value).
        if verdict["logic_conflict"]:
            register_pair_finding(
                "conflict",
                "conflict.logic",
                pair,
                0.85,
                "queries contradict each other by requiring vs excluding the same condition",
                {
                    "contradictory_predicates": verdict["polar_clash"],
                    "filtered_jaccard": round(verdict["filtered_jaccard"], 3),
                    "scores": score.as_dict(),
                },
            )

        # Same detection logic shipped under incompatible rule type.
        if is_dup and a.rule_type and b.rule_type and a.rule_type != b.rule_type:
            register_pair_finding(
                "conflict",
                "conflict.rule_type",
                pair,
                0.65,
                "equivalent query uses different rule types which may alert differently",
                {"rule_type": [a.rule_type, b.rule_type], "language": [a.language, b.language]},
            )

    findings.sort(key=lambda item: (item["kind"], item["category"], item["id"]))
    return findings


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------


def _tactic_display(name: str) -> str:
    lowered = name.strip().lower().replace("_", " ").replace("-", " ")
    for canonical in ENTERPRISE_TACTICS:
        if lowered == canonical.lower():
            return canonical
    # ATT&CK tactic IDs (TA0001...) cannot be mapped without data; title-case.
    if re.fullmatch(r"ta\d+", lowered):
        return name
    return " ".join(part.capitalize() for part in lowered.split())


def build_coverage_report(records: Sequence[RuleRecord]) -> dict[str, Any]:
    """Aggregate rule coverage by tactic, platform, language, data source..."""
    by_type: dict[str, int] = {}
    by_language: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_maturity: dict[str, int] = {}
    by_platform: dict[str, int] = {}
    by_integration: dict[str, int] = {}
    by_index: dict[str, int] = {}
    tactic_counts: dict[str, int] = dict.fromkeys(ENTERPRISE_TACTICS, 0)
    extra_tactics: dict[str, int] = {}
    technique_counts: dict[str, int] = {}

    for record in records:
        if record.rule_type:
            by_type[record.rule_type] = by_type.get(record.rule_type, 0) + 1
        if record.language:
            by_language[record.language] = by_language.get(record.language, 0) + 1
        if record.severity:
            by_severity[record.severity] = by_severity.get(record.severity, 0) + 1
        if record.maturity:
            by_maturity[record.maturity] = by_maturity.get(record.maturity, 0) + 1
        for platform in record.platforms:
            by_platform[platform] = by_platform.get(platform, 0) + 1
        for integration in record.integrations:
            by_integration[integration] = by_integration.get(integration, 0) + 1
        for index in record.indices:
            by_index[index] = by_index.get(index, 0) + 1
        for tactic in record.tactics:
            display = _tactic_display(tactic)
            if display in tactic_counts:
                tactic_counts[display] += 1
            elif not re.fullmatch(r"TA\d+", tactic, flags=re.IGNORECASE):
                extra_tactics[display] = extra_tactics.get(display, 0) + 1
        for technique in record.techniques:
            technique_counts[technique] = technique_counts.get(technique, 0) + 1

    covered_tactics = [t for t, count in tactic_counts.items() if count > 0]
    missing_tactics = [t for t in ENTERPRISE_TACTICS if tactic_counts[t] == 0]

    return {
        "rules_considered": len(records),
        "by_rule_type": dict(sorted(by_type.items(), key=lambda kv: (-kv[1], kv[0]))),
        "by_language": dict(sorted(by_language.items(), key=lambda kv: (-kv[1], kv[0]))),
        "by_severity": dict(sorted(by_severity.items(), key=lambda kv: (-kv[1], kv[0]))),
        "by_maturity": dict(sorted(by_maturity.items(), key=lambda kv: (-kv[1], kv[0]))),
        "by_platform": dict(sorted(by_platform.items(), key=lambda kv: (-kv[1], kv[0]))),
        "by_integration": dict(sorted(by_integration.items(), key=lambda kv: (-kv[1], kv[0]))),
        "top_indices": dict(sorted(by_index.items(), key=lambda kv: (-kv[1], kv[0]))[:30]),
        "tactics": tactic_counts,
        "extra_tactics": extra_tactics,
        "tactics_covered": len(covered_tactics),
        "tactics_total": len(ENTERPRISE_TACTICS),
        "tactic_coverage_percent": round(100 * len(covered_tactics) / len(ENTERPRISE_TACTICS), 1),
        "tactics_with_zero_rules": missing_tactics,
        "technique_counts": dict(sorted(technique_counts.items())),
        "unique_techniques": len(technique_counts),
        "top_techniques": dict(sorted(technique_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:25]),
    }


# ---------------------------------------------------------------------------
# Combined analysis + per-rule classification
# ---------------------------------------------------------------------------


def classify_rules(records: Sequence[RuleRecord], findings: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build a per-rule detection/classification summary."""
    per_rule: list[dict[str, Any]] = [
        {
            "index": idx,
            "rule_id": record.rule_id,
            "name": record.name,
            "path": record.path,
            "detected": False,
            # Exclusive primary bucket: conflict takes precedence because a
            # conflicting pair is never a safe duplicate to silence.
            "classification": "unique",
            "verdict": "unique",
            "is_duplicate": False,
            "is_conflict": False,
            "classifications": [],
            "duplicate_categories": [],
            "conflict_categories": [],
            "finding_ids": [],
        }
        for idx, record in enumerate(records)
    ]

    for finding in findings:
        for idx in finding.get("rule_indexes", []):
            if idx >= len(per_rule):
                continue
            target = per_rule[idx]
            target["detected"] = True
            target["finding_ids"].append(finding["id"])
            category = finding["category"]
            if category not in target["classifications"]:
                target["classifications"].append(category)
            bucket = "duplicate_categories" if finding["kind"] == "duplicate" else "conflict_categories"
            if category not in target[bucket]:
                target[bucket].append(category)
            target["is_duplicate"] = bool(target["duplicate_categories"])
            target["is_conflict"] = bool(target["conflict_categories"])

    for target in per_rule:
        if target["is_duplicate"] and target["is_conflict"]:
            target["verdict"] = "both"
        elif target["is_duplicate"]:
            target["verdict"] = "duplicate"
        elif target["is_conflict"]:
            target["verdict"] = "conflict"

        if target["is_conflict"]:
            target["classification"] = "conflict"
        elif target["is_duplicate"]:
            target["classification"] = "duplicate"
    return per_rule


def analyze_rules(
    paths: str | Path | Sequence[str | Path] | None = None,
    *,
    records: Sequence[RuleRecord] | None = None,
    include_coverage: bool = True,
    include_deprecated: bool = False,
) -> dict[str, Any]:
    """Run dedup, conflict detection and coverage over rules.

    Provide either ``paths`` (files/directories, existing format) or pre-built
    ``records``. Returns a JSON-serializable report dictionary.
    """
    errors: list[dict[str, str]] = []
    if records is None:
        if paths is None:
            raise ValueError("analyze_rules requires either paths or records")
        records, errors = load_records(paths, include_deprecated=include_deprecated)

    findings = detect_duplicates_and_conflicts(records)
    rule_results = classify_rules(records, findings)

    category_counts: dict[str, int] = {}
    kind_counts = {"duplicate": 0, "conflict": 0}
    for finding in findings:
        category_counts[finding["category"]] = category_counts.get(finding["category"], 0) + 1
        kind_counts[finding["kind"]] = kind_counts.get(finding["kind"], 0) + 1

    detected_rules = [r for r in rule_results if r["detected"]]
    classification_counts = {"duplicate": 0, "conflict": 0, "unique": 0}
    for result in rule_results:
        classification_counts[result["classification"]] += 1
    report: dict[str, Any] = {
        "summary": {
            "rules_analyzed": len(records),
            "unparsed_files": errors,
            "findings_total": len(findings),
            "duplicate_findings": kind_counts["duplicate"],
            "conflict_findings": kind_counts["conflict"],
            "detected_rule_count": len(detected_rules),
            "duplicate_rule_count": sum(1 for r in rule_results if r["is_duplicate"]),
            "conflict_rule_count": sum(1 for r in rule_results if r["is_conflict"]),
            "both_rule_count": sum(1 for r in rule_results if r["verdict"] == "both"),
            "classification_counts": classification_counts,
            "category_counts": dict(sorted(category_counts.items())),
        },
        "rules": rule_results,
        "findings": findings,
    }

    if include_coverage:
        report["coverage"] = build_coverage_report(records)

    return report


# Friendly aliases for callers/tests discovering the API by common names.
generate_coverage_report = build_coverage_report
detect_duplicates = detect_duplicates_and_conflicts
run_analysis = analyze_rules


def report_to_json(report: dict[str, Any], indent: int = 2) -> str:
    return json.dumps(report, indent=indent, default=str, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------


def _rule_label(rule_ref: dict[str, Any]) -> str:
    name = rule_ref.get("name") or "(unnamed)"
    rule_id = rule_ref.get("rule_id") or "-"
    return f"{name} [{rule_id}]"


def finding_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Flat rows suited for a CLI table."""
    rows: list[dict[str, Any]] = []
    for finding in report.get("findings", []):
        labels = "\n".join(_rule_label(ref) for ref in finding.get("rules", []))
        paths = "\n".join(str(ref.get("path") or "") for ref in finding.get("rules", []))
        rows.append(
            {
                "id": finding["id"],
                "kind": finding["kind"],
                "category": finding["category"],
                "confidence": finding["confidence"],
                "rules": labels,
                "paths": paths,
                "title": finding.get("title", ""),
            }
        )
    return rows


def flagged_rule_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for rule in report.get("rules", []):
        if not rule["detected"]:
            continue
        rows.append(
            {
                "index": rule["index"],
                "classification": rule["classification"],
                "verdict": rule["verdict"],
                "rule_id": rule.get("rule_id") or "",
                "name": rule.get("name") or "",
                "categories": ", ".join(rule.get("classifications", [])),
                "path": rule.get("path") or "",
            }
        )
    return rows


def render_markdown(report: dict[str, Any]) -> str:
    """Render a human-readable Markdown report (dedup + conflict + coverage)."""
    summary = report["summary"]
    lines: list[str] = []
    lines.append("# Rule Semantic Analysis Report")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Rules analyzed: **{summary['rules_analyzed']}**")
    lines.append(f"- Rules detected with issues: **{summary['detected_rule_count']}**")
    lines.append(
        f"- Exclusive classification -> duplicate: {summary['classification_counts']['duplicate']}, "
        f"conflict: {summary['classification_counts']['conflict']}, "
        f"unique: {summary['classification_counts']['unique']}"
    )
    lines.append(
        f"- Findings: {summary['findings_total']} "
        f"({summary['duplicate_findings']} duplicate, {summary['conflict_findings']} conflict)"
    )
    if summary.get("category_counts"):
        lines.append("- Categories:")
        for category, count in summary["category_counts"].items():
            lines.append(f"  - `{category}`: {count}")
    lines.append("")

    findings = report.get("findings", [])
    if findings:
        lines.append("## Duplicates & Conflicts")
        lines.append("")
        for finding in findings:
            icon = "DUPLICATE" if finding["kind"] == "duplicate" else "CONFLICT"
            lines.append(f"### [{icon}] `{finding['category']}` ({finding['confidence']})")
            lines.append("")
            lines.append(finding.get("title", ""))
            lines.append("")
            lines.extend(f"- {_rule_label(ref)} — `{ref.get('path') or 'n/a'}`" for ref in finding.get("rules", []))
            evidence = finding.get("evidence") or {}
            if evidence:
                lines.append("")
                lines.append("Evidence:")
                lines.append("```json")
                lines.append(json.dumps(evidence, indent=2, default=str, ensure_ascii=False))
                lines.append("```")
            lines.append("")

    coverage = report.get("coverage")
    if coverage:
        lines.append("## Coverage")
        lines.append("")
        lines.append(
            f"- ATT&CK tactics covered: {coverage['tactics_covered']}/{coverage['tactics_total']} "
            f"({coverage['tactic_coverage_percent']}%)"
        )
        lines.append(f"- Unique ATT&CK techniques: {coverage['unique_techniques']}")
        if coverage.get("tactics_with_zero_rules"):
            lines.append(f"- Tactics with zero rules: {', '.join(coverage['tactics_with_zero_rules'])}")
        lines.append("")

        def _table(title: str, mapping: dict[str, Any], limit: int | None = None) -> None:
            if not mapping:
                return
            lines.append(f"### {title}")
            lines.append("")
            lines.append("| Name | Count |")
            lines.append("| --- | ---: |")
            items = list(mapping.items())
            if limit:
                items = items[:limit]
            for key, value in items:
                lines.append(f"| {key} | {value} |")
            lines.append("")

        _table("Tactics", coverage.get("tactics", {}))
        _table("Platforms", coverage.get("by_platform", {}))
        _table("Rule types", coverage.get("by_rule_type", {}))
        _table("Languages", coverage.get("by_language", {}))
        _table("Severity", coverage.get("by_severity", {}))
        _table("Top techniques", coverage.get("top_techniques", {}))
        _table("Integrations / data sources", coverage.get("by_integration", {}), limit=40)

    errors = summary.get("unparsed_files") or []
    if errors:
        lines.append("## Unparsed files")
        lines.append("")
        lines.extend(f"- `{error['path']}`: {error['error']}" for error in errors)
        lines.append("")

    return "\n".join(lines)


def render_coverage_markdown(coverage: dict[str, Any]) -> str:
    """Render only the coverage section as Markdown."""
    lines: list[str] = ["# Rule Coverage Report", ""]
    lines.append(
        f"- ATT&CK tactics covered: {coverage['tactics_covered']}/{coverage['tactics_total']} "
        f"({coverage['tactic_coverage_percent']}%)"
    )
    lines.append(f"- Unique ATT&CK techniques: {coverage['unique_techniques']}")
    if coverage.get("tactics_with_zero_rules"):
        lines.append(f"- Tactics with zero rules: {', '.join(coverage['tactics_with_zero_rules'])}")
    lines.append("")

    def _table(title: str, mapping: dict[str, Any], limit: int | None = None) -> None:
        if not mapping:
            return
        lines.append(f"## {title}")
        lines.append("")
        lines.append("| Name | Count |")
        lines.append("| --- | ---: |")
        items = list(mapping.items())
        if limit:
            items = items[:limit]
        for key, value in items:
            lines.append(f"| {key} | {value} |")
        lines.append("")

    _table("Tactics", coverage.get("tactics", {}))
    _table("Platforms", coverage.get("by_platform", {}))
    _table("Rule types", coverage.get("by_rule_type", {}))
    _table("Languages", coverage.get("by_language", {}))
    _table("Severity", coverage.get("by_severity", {}))
    _table("Maturity", coverage.get("by_maturity", {}))
    _table("Top techniques", coverage.get("top_techniques", {}))
    _table("Integrations / data sources", coverage.get("by_integration", {}), limit=50)
    _table("Top index patterns", coverage.get("top_indices", {}))
    return "\n".join(lines)
