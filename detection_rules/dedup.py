# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Short-name alias for :mod:`detection_rules.rule_dedup`.

规则语义去重与冲突检测。Prefer importing from :mod:`detection_rules.rule_dedup`
or :mod:`detection_rules.rule_analysis` in new code.
"""

from .rule_dedup import (
    RuleDeduplicator,
    classify_rules,
    detect_duplicate_rules,
    detect_duplicates,
    detect_duplicates_and_conflicts,
    find_conflicts,
    find_duplicates,
)

__all__ = [
    "RuleDeduplicator",
    "classify_rules",
    "detect_duplicate_rules",
    "detect_duplicates",
    "detect_duplicates_and_conflicts",
    "find_conflicts",
    "find_duplicates",
]
