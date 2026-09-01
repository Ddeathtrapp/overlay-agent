"""Action schema — §4 of the action registry, verbatim. No extra fields.

Adding a field here widens what a handler can be handed without a matching
change in the policy engine, which is exactly the drift §4 warns against.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    # Type-only: avoids a runtime import cycle since params.py has no need
    # to know about Action/Tier.
    from actions.params import ParamSpec


class Tier(IntEnum):
    """§5. Ordering matters: policy code may compare tiers numerically."""
    ZERO = 0
    ONE = 1
    TWO = 2


@dataclass(frozen=True)
class Action:
    id: str                    # stable, snake_case, never reused after removal
    tier: Tier                 # see §5
    description: str           # human-readable; also fed to the classifier
    params: tuple["ParamSpec", ...]
    reversible: bool           # can the user trivially undo this?
    handler: Callable
