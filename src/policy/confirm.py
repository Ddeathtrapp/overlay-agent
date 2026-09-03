"""Confirmation — asking a human before acting.

An interface, plus two implementations. Phase 4's desktop dialog and
Phase 5's phone UI implement `Confirmer`; the engine never knows which one
answered.

The Tier 2 typed-confirmation rule (action-registry.md §5) is enforced
HERE, not in the UI. The engine issues a challenge and verifies the reply
itself, so a UI cannot offer a one-tap approve for an irreversible action
even by accident. That matters because threat-model.md T6 treats
habituation as certain: the user WILL stop reading, and friction on the
irreversible path is the only control that resists it.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Mapping

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 120.0
TIER_TWO = 2


@dataclass(frozen=True, slots=True)
class ConfirmationPrompt:
    """What the human is being asked. Built by the engine, rendered by a UI."""

    action_id: str
    description: str
    params: Mapping[str, str]
    tier: int
    source_label: str  # "phone", "desktop", "screen context"

    # Tier 2 only. The literal string the human must type back.
    challenge: str | None = None

    # False for tier 2 — §5 forbids excepting an irreversible action, so
    # the UI must not render a "don't ask again" affordance at all.
    allow_remember: bool = True

    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS

    @property
    def requires_typed(self) -> bool:
        return self.challenge is not None

    def summary(self) -> str:
        """One line the UI should show prominently.

        Parameters are shown with their names because T6 depends on the
        human being able to tell `open_application notepad` from
        `open_application something_else` at a glance.
        """
        if not self.params:
            return self.action_id
        args = " ".join(f"{k}={v}" for k, v in sorted(self.params.items()))
        return f"{self.action_id} {args}"


@dataclass(frozen=True, slots=True)
class ConfirmationReply:
    """What came back. `approved` alone is never sufficient for tier 2 —
    see `Confirmer.verify`.

    Validated at construction, like Decision. Without this, `approved` is
    truthiness-tested: a JSON reply of {"approved": "false"} from a phone
    would approve the action, because the string "false" is truthy. A
    deserialised reply must not be able to mean the opposite of what it says.
    """

    approved: bool
    typed: str | None = None
    remember: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.approved, bool):
            raise TypeError(
                f"approved must be a bool, got {type(self.approved).__name__}"
            )
        if not isinstance(self.remember, bool):
            raise TypeError(
                f"remember must be a bool, got {type(self.remember).__name__}"
            )
        if self.typed is not None and not isinstance(self.typed, str):
            raise TypeError(
                f"typed must be a str or None, got {type(self.typed).__name__}"
            )


class Confirmer(ABC):
    """Ask a human. Implementations must never default to allow."""

    @abstractmethod
    def ask(self, prompt: ConfirmationPrompt) -> ConfirmationReply:
        """Block until the human answers, or the prompt times out.

        A timeout MUST return `ConfirmationReply(approved=False)`.
        architecture.md §7 records this as a Phase 4 constraint: a
        confirmation that defaults to allow on timeout is not a
        confirmation, it is a delay.
        """

    # -- verification, shared by every implementation ----------------------

    @staticmethod
    def verify(prompt: ConfirmationPrompt, reply: ConfirmationReply) -> bool:
        """Turn a reply into a yes or no. Called by the engine, not the UI.

        This is where the tier 2 rule actually lives. A UI that returns
        `approved=True` without the typed challenge gets a `False` here.
        It does not stop a deliberately malicious UI — the UI is trusted
        code — but it does stop a shortcut, a bug, or a well-meaning
        "just add a quick approve button" from silently removing the
        friction §5 requires.
        """
        if not reply.approved:
            return False
        if not prompt.requires_typed:
            return True
        if reply.typed is None:
            log.warning("tier %d confirmation approved with no typed reply", prompt.tier)
            return False
        return reply.typed.strip() == prompt.challenge

    @staticmethod
    def may_remember(prompt: ConfirmationPrompt, reply: ConfirmationReply) -> bool:
        """Whether this reply should become a standing exception.

        Refuses for tier 2 regardless of what the UI sent, so a UI bug
        cannot create a permission the exception store would have to
        refuse anyway.
        """
        return bool(reply.remember) and prompt.allow_remember and prompt.tier < TIER_TWO


# --------------------------------------------------------------------------
# Implementations
# --------------------------------------------------------------------------


class NullConfirmer(Confirmer):
    """No UI attached. Denies everything.

    This is the default, and it is the fail-closed direction: a headless
    service with nothing to ask must not run tier 1 or 2 actions. The
    engine turns this into RejectionCode.NO_CONFIRMER rather than
    pretending a human said no.
    """

    def ask(self, prompt: ConfirmationPrompt) -> ConfirmationReply:
        log.info("no confirmer attached; denying %s", prompt.summary())
        return ConfirmationReply(approved=False)


class AutoDenyConfirmer(NullConfirmer):
    """Alias used in tests, so a test that forgets to attach a confirmer
    fails loudly rather than accidentally exercising an allow path."""


class ConsoleConfirmer(Confirmer):
    """Terminal prompt. Phase 2 development only — not the Phase 4 UI.

    Deliberately not pretty. If this ever ships as the real interface, it
    should look temporary.
    """

    def ask(self, prompt: ConfirmationPrompt) -> ConfirmationReply:
        print()
        print("  ACTION REQUESTED")
        print(f"    {prompt.summary()}")
        print(f"    {prompt.description}")
        print(f"    tier {prompt.tier} · from {prompt.source_label}")

        if prompt.requires_typed:
            print(f"\n  This is irreversible. Type '{prompt.challenge}' to allow.")
            try:
                typed = input("  > ")
            except (EOFError, KeyboardInterrupt):
                return ConfirmationReply(approved=False)
            return ConfirmationReply(approved=True, typed=typed)

        suffix = " [y/N/a=always]" if prompt.allow_remember else " [y/N]"
        try:
            answer = input(f"\n  Allow?{suffix} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return ConfirmationReply(approved=False)

        if answer == "a" and prompt.allow_remember:
            return ConfirmationReply(approved=True, remember=True)
        return ConfirmationReply(approved=answer == "y")


# --------------------------------------------------------------------------
# Prompt construction
# --------------------------------------------------------------------------


def build_prompt(
    action_id: str,
    description: str,
    params: Mapping[str, str],
    tier: int,
    source_label: str,
    source_trusted: bool,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> ConfirmationPrompt:
    """Assemble a prompt with the tier rules already applied.

    The challenge is the action id itself rather than a random word. A
    random string proves the human is present; typing the action name
    proves they read WHAT they are approving, which is the failure mode
    T6 actually describes.

    `source_trusted` is required, not defaulted. An untrusted request may
    be confirmed, but it must never be able to create a standing exception:
    the engine stops screen context from USING an exception, and this stops
    it from MAKING one. With §12.3 removing expiry, one habituated "always"
    on a screen-driven prompt would be permanent.
    """
    is_tier_two = int(tier) >= TIER_TWO
    return ConfirmationPrompt(
        action_id=action_id,
        description=description,
        params=dict(params),
        tier=int(tier),
        source_label=source_label,
        challenge=action_id if is_tier_two else None,
        allow_remember=not is_tier_two and source_trusted,
        timeout_seconds=timeout_seconds,
    )