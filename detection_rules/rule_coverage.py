# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Coverage reporting for detection rules (覆盖度报告).

Thin facade over :mod:`detection_rules.rule_analysis`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .rule_analysis import (
    ENTERPRISE_TACTICS,
    RuleRecord,
    build_coverage_report,
    load_records,
    records_from_rules,
    render_coverage_markdown,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

__all__ = [
    "ENTERPRISE_TACTICS",
    "RuleCoverageReport",
    "RuleRecord",
    "build_coverage_report",
    "generate_coverage_report",
    "load_records",
    "records_from_rules",
    "render_coverage_markdown",
]


generate_coverage_report = build_coverage_report


class RuleCoverageReport:
    """Object-oriented helper for building coverage reports."""

    def __init__(self, records: Sequence[RuleRecord] | None = None) -> None:
        self.records: list[RuleRecord] = list(records or [])

    @classmethod
    def from_paths(cls, paths: str | Path | Sequence[str | Path]) -> RuleCoverageReport:
        records, _errors = load_records(paths)
        return cls(records)

    @classmethod
    def from_rules(cls, rules: Sequence[Any]) -> RuleCoverageReport:
        return cls(records_from_rules(rules))

    def build(self) -> dict[str, Any]:
        return build_coverage_report(self.records)

    def markdown(self) -> str:
        return render_coverage_markdown(self.build())
