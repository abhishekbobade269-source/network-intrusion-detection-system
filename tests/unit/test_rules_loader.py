"""Exercises `load_rules`' defensive paths — a malformed rules directory
must never take the whole engine down; it should skip the bad input and
keep loading everything else.
"""

from __future__ import annotations

from pathlib import Path

from nids.rules.loader import load_rules


def test_missing_rules_dir_returns_empty_list_without_raising(tmp_path: Path) -> None:
    rules = load_rules(tmp_path / "does-not-exist")
    assert rules == []


def test_non_list_yaml_file_is_skipped_not_raised(tmp_path: Path) -> None:
    (tmp_path / "bad.yaml").write_text("just_a_string: true\n", encoding="utf-8")
    assert load_rules(tmp_path) == []


def test_invalid_yaml_syntax_is_skipped_not_raised(tmp_path: Path) -> None:
    (tmp_path / "broken.yaml").write_text("- id: [unterminated\n", encoding="utf-8")
    assert load_rules(tmp_path) == []


def test_rule_failing_schema_validation_is_skipped_not_raised(tmp_path: Path) -> None:
    (tmp_path / "invalid.yaml").write_text(
        "- id: MISSING_FIELDS\n  name: incomplete rule\n",  # no severity/description/conditions
        encoding="utf-8",
    )
    assert load_rules(tmp_path) == []


def test_duplicate_rule_id_across_files_keeps_only_the_first(tmp_path: Path) -> None:
    rule_yaml = """
- id: DUPLICATE_ID
  name: first definition
  severity: low
  description: kept
  conditions:
    - field: total_packets
      op: gte
      value: 1
"""
    (tmp_path / "a.yaml").write_text(rule_yaml, encoding="utf-8")
    (tmp_path / "b.yaml").write_text(
        rule_yaml.replace("first definition", "second definition"), encoding="utf-8"
    )

    rules = load_rules(tmp_path)

    assert len(rules) == 1
    assert rules[0].name == "first definition"


def test_one_bad_file_does_not_block_good_files_in_the_same_dir(tmp_path: Path) -> None:
    (tmp_path / "broken.yaml").write_text("[[[not yaml", encoding="utf-8")
    (tmp_path / "good.yaml").write_text(
        """
- id: GOOD_RULE
  name: a valid rule
  severity: high
  description: fine
  conditions:
    - field: total_packets
      op: gte
      value: 1
""",
        encoding="utf-8",
    )

    rules = load_rules(tmp_path)

    assert [r.id for r in rules] == ["GOOD_RULE"]
