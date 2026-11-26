# Rule semantic dedup, conflict detection and coverage

As the number of rules grows, the same behavior can be shipped multiple times
with cosmetic differences or contradictory settings. The rule analysis
tooling detects and classifies those cases and produces a coverage report.

It is **additive and format-compatible**: it reads the existing TOML/JSON rule
format directly, tolerates incomplete fixtures, and does not change rule
loading, validation or packaging.

## Commands

```bash
# full analysis: duplicates + conflicts + coverage
python -m detection_rules analyze-rules

# scan injected / custom rule files or directories (TOML/JSON/NDJSON)
python -m detection_rules analyze-rules ./injected_rules --json --output report.json

# duplicates & conflicts only
python -m detection_rules detect-duplicates ./injected_rules

# coverage report only
python -m detection_rules coverage-report --format markdown --output coverage.md
python -m detection_rules coverage-report --json
```

Convenient aliases: `rule-analysis`, `rule-health`, `analyze`, `dedup`,
`dedupe`, `duplicates`, `conflict-check`, `coverage`, `rule-coverage`.

Options:

- `PATHS...` / `--rules-dir/-d`: files or directories; defaults to the
  configured `rule_dirs` (the repository `rules/`).
- `--format {table,json,markdown}`, `--json`, `--output/-o`.
- `--strict`: exit `1` when any finding exists (opt-in, never affects builds).
- `--include-deprecated`: also scan `rules/_deprecated` (excluded by default).
- `--with-baseline`: compare explicit paths against the repository rules too.

## Classification

Every finding has a top-level `kind` of `duplicate` or `conflict` and a
specific `category`:

| Category | Meaning |
| --- | --- |
| `duplicate.exact_query` | normalized query identical (whitespace/case/quote-insensitive) |
| `duplicate.semantic_query` | near-identical query token set after boilerplate removal |
| `duplicate.semantic_predicate` | same distinctive selection predicates / detection logic |
| `duplicate.name` | same normalized rule name but different `rule_id` |
| `duplicate.rule_id` | identical `rule_id` and identical content |
| `conflict.rule_id` | same `rule_id` mapped to different content |
| `conflict.severity` | same behavior with contradictory `severity`/`risk_score` |
| `conflict.logic` | one query requires a predicate the other excludes |
| `conflict.rule_type` | equivalent query shipped as incompatible rule types |

The JSON report contains `summary`, pairwise `findings`, a per-rule `rules`
list and `coverage`. Each rule carries booleans `is_duplicate` /
`is_conflict`, the full `classifications` list, and an exclusive primary
`classification` (`duplicate`, `conflict` or `unique`, conflict priority).

## Programmatic API

```python
from detection_rules.rule_analysis import analyze_rules, load_records
from detection_rules.rule_dedup import RuleDeduplicator
from detection_rules.rule_coverage import RuleCoverageReport

report = analyze_rules(["./injected_rules"])
assert report["summary"]["detected_rule_count"] == 20

dedup = RuleDeduplicator.from_paths(["./rules/windows"])
coverage = RuleCoverageReport.from_paths(["./rules"]).build()
```

Thin alias modules `detection_rules.dedup` and `detection_rules.coverage`
re-export the same API. Existing `TOMLRule` / `RuleCollection` objects can be
adapted with `records_from_rules(...)`.

## Acceptance check

`tests/test_rule_analysis.py` injects exactly 20 rules (five duplicate pairs
and five conflict pairs) into a temporary directory and asserts that **all
20** are detected and split into 10 `duplicate` and 10 `conflict` primary
classifications, that every category above is represented, that all shipped
rules parse, and that the CLI JSON/strict modes work.

```bash
uv run python -m pytest tests/test_rule_analysis.py -q
```
