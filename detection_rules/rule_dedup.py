# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Semantic rule deduplication and conflict detection.

规则语义去重与冲突检测。

This is a thin, well-named facade over :mod:`detection_rules.rule_analysis`.
It exposes the most common entry points under dedup-oriented names so the
capability is easy to discover and import.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .rule_analysis import (
    RuleRecord,
    analyze_rules,
    classify_rules,
    detect_duplicates,
    detect_duplicates_and_conflicts,
    load_records,
    record_from_dict,
    records_from_rules,
    report_to_json,
    score_pair,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

__all__ = [
    "RuleDeduplicator",
    "RuleRecord",
    "analyze_rules",
    "classify_rules",
    "detect_duplicate_rules",
    "detect_duplicates",
    "detect_duplicates_and_conflicts",
    "find_conflicts",
    "find_duplicates",
    "load_records",
    "record_from_dict",
    "records_from_rules",
    "report_to_json",
    "score_pair",
]


# Common verb-first aliases.
find_duplicates = detect_duplicates_and_conflicts
detect_duplicate_rules = detect_duplicates_and_conflicts


def find_conflicts(records: Sequence[RuleRecord]) -> list[dict[str, Any]]:
    """Return only findings whose ``kind`` is ``conflict``."""
    return [finding for finding in detect_duplicates_and_conflicts(records) if finding["kind"] == "conflict"]


class RuleDeduplicator:
    """Small object-oriented wrapper around the functional API.

    Example:
        >>> dedup = RuleDeduplicator.from_paths(["rules/windows"])
        >>> report = dedup.analyze()
        >>> len(report["findings"]) >= 0
        True
    """

    def __init__(self, records: Sequence[RuleRecord] | None = None) -> None:
        self.records: list[RuleRecord] = list(records or [])

    @classmethod
    def from_paths(cls, paths: str | Path | Sequence[str | Path], include_deprecated: bool = False) -> RuleDeduplicator:
        records, _errors = load_records(paths, include_deprecated=include_deprecated)
        return cls(records)

    @classmethod
    def from_rules(cls, rules: Sequence[Any]) -> RuleDeduplicator:
        return cls(records_from_rules(rules))

    def findings(self) -> list[dict[str, Any]]:
        return detect_duplicates_and_conflicts(self.records)

    def duplicates(self) -> list[dict[str, Any]]:
        return [f for f in self.findings() if f["kind"] == "duplicate"]

    def conflicts(self) -> list[dict[str, Any]]:
        return [f for f in self.findings() if f["kind"] == "conflict"]

    def classifications(self) -> list[dict[str, Any]]:
        return classify_rules(self.records, self.findings())

    def analyze(self, include_coverage: bool = True) -> dict[str, Any]:
        return analyze_rules(records=self.records, include_coverage=include_coverage)
