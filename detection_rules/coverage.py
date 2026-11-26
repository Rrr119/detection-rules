# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Short-name alias for :mod:`detection_rules.rule_coverage`.

覆盖度报告。Prefer :mod:`detection_rules.rule_coverage` or
:mod:`detection_rules.rule_analysis` in new code.
"""

from .rule_coverage import (
    ENTERPRISE_TACTICS,
    RuleCoverageReport,
    build_coverage_report,
    generate_coverage_report,
    render_coverage_markdown,
)

__all__ = [
    "ENTERPRISE_TACTICS",
    "RuleCoverageReport",
    "build_coverage_report",
    "generate_coverage_report",
    "render_coverage_markdown",
]
