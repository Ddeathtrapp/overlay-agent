"""The §4 schema is a contract the policy engine will be written against.
These tests fail if a field is added, removed, or made mutable."""
from __future__ import annotations

import dataclasses

from _helpers import assert_raises  # noqa: F401  (path shim + helper)

from actions.schema import Action, Tier

# §4, verbatim. Adding a field widens what a handler can be handed without a
# matching change in the policy engine.
SPEC_FIELDS = {"id", "tier", "description", "params", "reversible", "handler"}


def test_action_has_exactly_the_spec_fields() -> None:
    assert {f.name for f in dataclasses.fields(Action)} == SPEC_FIELDS


def test_action_is_frozen() -> None:
    action = Action(
        id="x", tier=Tier.ZERO, description="X.", params=(),
        reversible=True, handler=lambda: None,
    )
    assert_raises(dataclasses.FrozenInstanceError,
                  setattr, action, "tier", Tier.TWO)


def test_tier_values_match_spec() -> None:
    # §5 names three tiers, 0/1/2. Ordering is relied on by policy code.
    assert [t.value for t in Tier] == [0, 1, 2]
    assert Tier.ZERO < Tier.ONE < Tier.TWO
