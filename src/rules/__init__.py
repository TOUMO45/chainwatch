"""Chainwatch detection rules. Each rule module exposes RULE_ID and
run(before_path, after_path, case_meta) -> bool (True = rule fires)."""

from . import rule1, rule2a, rule2b, rule3a, rule3b, rule3c, rule4, rule5, rule6

ALL_RULES = [rule1, rule2a, rule2b, rule3a, rule3b, rule3c, rule4, rule5, rule6]


def register_all(registry: dict) -> None:
    for mod in ALL_RULES:
        registry[mod.RULE_ID] = mod.run
