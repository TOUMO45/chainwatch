"""Chainwatch detection rules. Each rule module exposes RULE_ID and
run(before_path, after_path, case_meta) -> bool (True = rule fires)."""

from . import rule3a, rule3b, rule3c

ALL_RULES = [rule3a, rule3b, rule3c]


def register_all(registry: dict) -> None:
    for mod in ALL_RULES:
        registry[mod.RULE_ID] = mod.run
