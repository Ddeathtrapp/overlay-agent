"""Vocabulary for the policy engine.

Shapes only. No permission logic lives here — this module exists so that
the engine, the exception store, the rate limiter, and the audit log all
describe the same objects in the same words.

Nothing in this file decides anything. If you find yourself adding an
`if` that grants or denies, it belongs in engine.py.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Mapping


# --------------------------------------------------------------------------
# Provenance
# --------------------------------------------------------------------------


class Source(str, Enum):
    """Where an ActionRequest came from.

        This is load-bearing. threat-model.md §4 T1 assumes screen content is
    hostile at all times: an attacker can place instruction-shaped text
    anywhere the OCR pipeline will read it.

    Two rules govern this field, and both are security-critical:

    1. It is stamped by the ENTRY POINT and by nothing else. The CLI
       hardcodes DESKTOP; the transport hardcodes PHONE. It never arrives
       in a request payload, is never a classifier output field, and is
       never derived from anything the model produced. A caller that could
       choose its own Source could stamp DESKTOP on a hostile request and
       the provenance rule would be worthless.

    2. It describes where the PARAMETERS came from, not where the utterance
       came from. "Open the app named on screen" is SCREEN_CONTEXT even
       though the human typed it, because OCR supplied the value.

    `trusted` does not mean auto-allowed. Tier rules apply regardless; it
    only means the request is not FORCED to confirm on provenance grounds.
    """

    DESKTOP = "desktop"
    PHONE = "phone"
    SCREEN_CONTEXT = "screen_context"

    @property
    def trusted(self) -> bool:
        """False for any origin an attacker can write to.

        DESKTOP and PHONE are authenticated human input. SCREEN_CONTEXT is
        whatever happened to be on the monitor.
        """
        return self is not Source.SCREEN_CONTEXT


# --------------------------------------------------------------------------
# Verdicts
# --------------------------------------------------------------------------


class Outcome(str, Enum):
    """How a request ended. Terminal — the engine resolves confirmation
    itself rather than handing the caller an "ask the user" state.
    """

    AUTO_ALLOWED = "auto_allowed"  # tier 0, or a standing exception matched
    CONFIRMED = "confirmed"  # a human said yes
    REJECTED = "rejected"


class RejectionCode(str, Enum):
    """Why a request was rejected.

    An enum rather than free text so the audit log is queryable and the
    CLI can map codes to exit codes without string matching.
    """

    UNKNOWN_ACTION = "unknown_action"
    BAD_ARITY = "bad_arity"
    PARAM_REJECTED = "param_rejected"
    RATE_LIMITED = "rate_limited"
    NOT_CONFIRMED = "not_confirmed"  # human declined, or confirmation timed out
    NO_CONFIRMER = "no_confirmer"  # nothing available to ask; fail closed


# --------------------------------------------------------------------------
# Requests
# --------------------------------------------------------------------------


def _new_request_id() -> str:
    return uuid.uuid4().hex[:12]


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class ActionRequest:
    """A proposal. Not a permission to do anything.

    Note what is absent: there is no `tier` field. Tier is read from the
    registry at evaluation time and can never be asserted by a caller.
    A compromised classifier cannot declare its own request to be tier 0.
    """

    action_id: str
    raw_params: Mapping[str, object]
    source: Source

    # What the human said, if anything. Audit context only — never parsed.
    utterance: str | None = None

    request_id: str = field(default_factory=_new_request_id)
    created_at: datetime = field(default_factory=_now)

    def __post_init__(self) -> None:
        # Freeze the mapping. A frozen dataclass does not stop `req.raw_params["x"] = ...`,
        # which is the same gap that made APPS mutable despite `Final`.
        object.__setattr__(self, "raw_params", MappingProxyType(dict(self.raw_params)))


# --------------------------------------------------------------------------
# Decisions
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Decision:
    """The engine's verdict on one request."""

    outcome: Outcome
    request: ActionRequest
    reason: str
    code: RejectionCode | None = None

    def __post_init__(self) -> None:
        # Fail closed at construction: a rejection without a code is
        # unloggable, and an allow carrying a rejection code is a bug
        # that would otherwise read as a legitimate approval.
        if self.outcome is Outcome.REJECTED and self.code is None:
            raise ValueError("REJECTED decision requires a RejectionCode")
        if self.outcome is not Outcome.REJECTED and self.code is not None:
            raise ValueError(f"{self.outcome.value} decision must not carry a code")

    @property
    def allowed(self) -> bool:
        return self.outcome is not Outcome.REJECTED

    # -- constructors, so engine.py reads as prose -------------------------

    @classmethod
    def auto_allow(cls, request: ActionRequest, reason: str) -> "Decision":
        return cls(Outcome.AUTO_ALLOWED, request, reason)

    @classmethod
    def confirmed(cls, request: ActionRequest, reason: str = "confirmed by human") -> "Decision":
        return cls(Outcome.CONFIRMED, request, reason)

    @classmethod
    def reject(cls, request: ActionRequest, code: RejectionCode, reason: str) -> "Decision":
        return cls(Outcome.REJECTED, request, reason, code)