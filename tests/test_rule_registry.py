"""WALK-L7. Rule 10 was registered in RULES, fixture-tested at precision 1.00,
and silently absent from every product surface because `src/scan.py`'s
RULE_ORDER did not list it - every gate was green while the rule did nothing.

One assertion closes the class: RULE_ORDER and RULES must name exactly the
same rule ids, in both directions. A rule present in one and missing from the
other is either dead code (registered, never run) or a crash waiting to
happen (ordered, never registered).
"""

from __future__ import annotations

from src.scan import RULE_ORDER, RULES, RULE_TITLES


def test_every_registered_rule_is_scheduled():
    missing = set(RULES) - set(RULE_ORDER)
    assert not missing, "registered but never run: %s" % sorted(missing)


def test_every_scheduled_rule_is_registered():
    phantom = set(RULE_ORDER) - set(RULES)
    assert not phantom, "scheduled but not registered: %s" % sorted(phantom)


def test_every_rule_has_a_title():
    assert set(RULE_TITLES) == set(RULES), \
        "RULE_TITLES must cover exactly the registered rules, for the same reason"
