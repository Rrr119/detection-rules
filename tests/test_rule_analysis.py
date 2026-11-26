# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Acceptance tests for semantic dedup, conflict detection and coverage.

The headline acceptance criterion is covered here: inject exactly 20
duplicate/conflicting rules and assert that **all 20** are detected and
classified into the duplicate/conflict families. It also checks compatibility
with the existing on-disk rule format and that the CLI is registered.
"""

# Fixture specs read naturally as keyword dict() builders; helper mirrors the
# TOML field list and therefore has many keyword arguments.
# ruff: noqa: C408, PLR0913

from __future__ import annotations

import json
from pathlib import Path

import pytest

from detection_rules.rule_analysis import (
    analyze_rules,
    build_coverage_report,
    load_records,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = REPO_ROOT / "rules"


def _rule_toml(
    index: int,
    tag: str,
    *,
    rule_id: str,
    name: str,
    query: str,
    rule_type: str = "eql",
    language: str = "eql",
    severity: str = "medium",
    risk_score: int = 47,
) -> tuple[str, str]:
    body = f"""[metadata]
creation_date = "2026/01/01"
integration = ["endpoint"]
maturity = "production"
updated_date = "2026/01/01"

[rule]
author = ["Acceptance"]
description = "injected acceptance fixture"
risk_score = {risk_score}
rule_id = "{rule_id}"
severity = "{severity}"
name = "{name}"
type = "{rule_type}"
language = "{language}"
index = ["logs-endpoint.events.*"]
query = \'\'\'{query}\'\'\'
"""
    return f"{index:02d}_{tag}.toml", body


def _inject_twenty_rules(target: Path) -> list[Path]:
    """Create 10 related pairs = 20 injected rules.

    Indexes 0-9 are duplicate pairs, indexes 10-19 are conflict pairs.
    """

    fixed_id = "aaaaaaaa-0000-4000-8000-000000000060"
    specs: list[dict[str, object]] = [
        # -- Duplicates (5 pairs / 10 rules) --------------------------------
        dict(
            tag="dup_mimikatz_a",
            rule_id="11111111-0000-4000-8000-000000000001",
            name="Mimikatz Execution Detected",
            query='process where event.type == "start" and process.name : "mimikatz.exe"',
        ),
        dict(
            tag="dup_mimikatz_b",
            rule_id="11111111-0000-4000-8000-000000000002",
            name="Mimikatz Execution Detected",
            query="process where  event.type == 'start'  and PROCESS.NAME:\"mimikatz.exe\"",
        ),
        dict(
            tag="dup_encps_a",
            rule_id="11111111-0000-4000-8000-000000000003",
            name="Encoded PowerShell Command",
            language="kuery",
            rule_type="query",
            query='process.name : ("powershell.exe", "pwsh.exe") and process.command_line : "* -enc *"',
        ),
        dict(
            tag="dup_encps_b",
            rule_id="11111111-0000-4000-8000-000000000004",
            name="Encoded PowerShell Launch",
            language="kuery",
            rule_type="query",
            query='process.command_line : "* -enc *" and process.name : ("powershell.exe", "pwsh.exe")',
        ),
        dict(
            tag="dup_auth_a",
            rule_id="11111111-0000-4000-8000-000000000005",
            name="Authentication Failures Observed",
            language="kuery",
            rule_type="query",
            query="event.category:authentication and event.outcome:failure and source.ip:*",
        ),
        dict(
            tag="dup_auth_b",
            rule_id="11111111-0000-4000-8000-000000000006",
            name="Authentication Failures Observed",
            language="kuery",
            rule_type="query",
            query="event.category:AUTHENTICATION AND event.outcome:FAILURE AND source.ip:*",
        ),
        dict(
            tag="dup_lsass_a",
            rule_id="11111111-0000-4000-8000-000000000007",
            name="LSASS Dump File Created",
            query='file where event.action == "creation" and file.name : "lsass.dmp"',
        ),
        dict(
            tag="dup_lsass_b",
            rule_id="11111111-0000-4000-8000-000000000008",
            name="LSASS Memory Dump on Disk",
            query='file where event.action=="creation"   and file.name:"lsass.dmp"',
        ),
        dict(
            tag="dup_svc_a",
            rule_id="11111111-0000-4000-8000-000000000009",
            name="Persistent Service Creation X",
            query='process where process.name : "sc.exe" and process.args : "create"',
        ),
        dict(
            tag="dup_svc_b",
            rule_id="11111111-0000-4000-8000-000000000010",
            name="Persistent Service Creation X",
            query='process where process.name : "sc.exe" and process.args : "create" and process.args : "*badbin*"',
        ),
        # -- Conflicts (5 pairs / 10 rules) ---------------------------------
        # Same rule_id, divergent content -> conflict.rule_id
        dict(
            tag="cf_id_a",
            rule_id=fixed_id,
            name="Shared Identifier Alpha",
            query='process where process.name : "alpha_tool.exe"',
        ),
        dict(
            tag="cf_id_b",
            rule_id=fixed_id,
            name="Shared Identifier Beta Different",
            query='process where event.type == "start" and process.name : "beta_tool.exe"',
        ),
        # Identical behavior, contradictory severity/risk -> conflict.severity
        dict(
            tag="cf_sev1_a",
            rule_id="22222222-0000-4000-8000-000000000001",
            name="Secret Tool Memory Dump",
            severity="low",
            risk_score=21,
            query='process where process.name : "secrettool.exe" and process.command_line : "*dump*"',
        ),
        dict(
            tag="cf_sev1_b",
            rule_id="22222222-0000-4000-8000-000000000002",
            name="Secret Tool Memory Dump",
            severity="critical",
            risk_score=99,
            query='process where process.name : "secrettool.exe" and process.command_line : "*dump*"',
        ),
        dict(
            tag="cf_sev2_a",
            rule_id="22222222-0000-4000-8000-000000000003",
            name="Run Key Persistence Malware Q",
            severity="medium",
            risk_score=47,
            query='registry where registry.path : "*\\\\Run\\\\*" and process.name : "malq.exe"',
        ),
        dict(
            tag="cf_sev2_b",
            rule_id="22222222-0000-4000-8000-000000000004",
            name="Run Key Persistence Malware Q",
            severity="low",
            risk_score=21,
            query='registry where registry.path : "*\\\\Run\\\\*" and process.name : "malq.exe"',
        ),
        # Require vs exclude the same predicate -> conflict.logic
        dict(
            tag="cf_logic_a",
            rule_id="22222222-0000-4000-8000-000000000005",
            name="Probe Utility Execution Z",
            query='process where event.type == "start" and process.name : "probeutilz.exe"',
        ),
        dict(
            tag="cf_logic_b",
            rule_id="22222222-0000-4000-8000-000000000006",
            name="Probe Utility Exclusion Z",
            query='process where event.type == "start" and not process.name : "probeutilz.exe"',
        ),
        # Same query shipped as incompatible rule type -> conflict.rule_type
        dict(
            tag="cf_type_a",
            rule_id="22222222-0000-4000-8000-000000000007",
            name="Scheduled Task Creation Watch T",
            rule_type="eql",
            language="eql",
            query='process where process.name : "schtasks.exe" and process.args : "/create"',
        ),
        dict(
            tag="cf_type_b",
            rule_id="22222222-0000-4000-8000-000000000008",
            name="Scheduled Task Creation Watch T",
            rule_type="threshold",
            language="eql",
            query='process where process.name : "schtasks.exe" and process.args : "/create"',
        ),
    ]

    assert len(specs) == 20
    paths: list[Path] = []
    for index, spec in enumerate(specs):
        filename, content = _rule_toml(index, str(spec["tag"]), **{k: v for k, v in spec.items() if k != "tag"})
        path = target / filename
        path.write_text(content, encoding="utf-8")
        paths.append(path)
    return paths


@pytest.fixture
def injected_dir(tmp_path: Path) -> Path:
    target = tmp_path / "injected_rules"
    target.mkdir()
    _inject_twenty_rules(target)
    return target


def test_exactly_twenty_rules_injected(injected_dir: Path) -> None:
    records, errors = load_records(injected_dir)
    assert errors == []
    assert len(records) == 20


def test_all_twenty_detected_and_classified(injected_dir: Path) -> None:
    report = analyze_rules([injected_dir], include_coverage=True)
    summary = report["summary"]

    assert summary["rules_analyzed"] == 20
    # Headline acceptance assertion: every injected rule is flagged.
    assert summary["detected_rule_count"] == 20
    assert all(rule["detected"] for rule in report["rules"])

    # Every rule receives an exclusive duplicate/conflict classification.
    counts = summary["classification_counts"]
    assert counts["unique"] == 0
    assert counts["duplicate"] == 10
    assert counts["conflict"] == 10
    assert counts["duplicate"] + counts["conflict"] == 20

    # Both families and the main sub-categories are represented.
    categories = summary["category_counts"]
    assert any(key.startswith("duplicate.") for key in categories)
    assert any(key.startswith("conflict.") for key in categories)
    assert "duplicate.exact_query" in categories
    assert "duplicate.name" in categories
    assert "conflict.rule_id" in categories
    assert "conflict.severity" in categories
    assert "conflict.logic" in categories
    assert "conflict.rule_type" in categories

    # Every finding references at least two rules and is JSON serializable.
    assert report["findings"]
    for finding in report["findings"]:
        assert finding["kind"] in {"duplicate", "conflict"}
        assert finding["category"].startswith(finding["kind"] + ".")
        assert len(finding["rule_indexes"]) >= 2
    json.dumps(report)


def test_coverage_report_shape(injected_dir: Path) -> None:
    records, _ = load_records(injected_dir)
    coverage = build_coverage_report(records)
    assert coverage["rules_considered"] == 20
    assert coverage["tactics_total"] == 14
    assert "by_rule_type" in coverage
    assert "by_language" in coverage
    assert "tactics" in coverage


@pytest.mark.skipif(not RULES_DIR.exists(), reason="repository rules/ directory not present")
def test_existing_rule_format_compatible() -> None:
    # The analyzer must parse every shipped rule without errors, proving the
    # new feature is compatible with the existing rule format.
    records, errors = load_records(RULES_DIR)
    assert len(records) > 2000
    assert errors == []
    coverage = build_coverage_report(records)
    assert coverage["unique_techniques"] > 100
    assert coverage["tactics_covered"] == coverage["tactics_total"]


def test_cli_commands_registered() -> None:
    from click.testing import CliRunner

    from detection_rules.main import root

    for name in ("analyze-rules", "detect-duplicates", "coverage-report", "dedup", "coverage"):
        assert name in root.commands

    runner = CliRunner()
    result = runner.invoke(root, ["detect-duplicates", str(RULES_DIR / "does-not-exist")])
    assert result.exit_code != 0


def test_cli_detect_json_and_strict(injected_dir: Path) -> None:
    from click.testing import CliRunner

    from detection_rules.main import root

    runner = CliRunner()
    result = runner.invoke(root, ["detect-duplicates", str(injected_dir), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["summary"]["detected_rule_count"] == 20

    strict = runner.invoke(root, ["detect-duplicates", str(injected_dir), "--strict"])
    assert strict.exit_code == 1

    coverage = runner.invoke(root, ["coverage-report", str(injected_dir), "--json"])
    assert coverage.exit_code == 0, coverage.output
    assert json.loads(coverage.output)["coverage"]["rules_considered"] == 20
