"""Engine-level policy behaviour: tiers, exceptions, provenance, and the
tier-2 typed-confirmation rule, exercised directly against `PolicyEngine`
rather than through the CLI.

Every engine here is built with `_helpers.build_engine`, which wires a
tmp_path-scoped `ExceptionStore`/`AuditLog` and a `StubConfirmer` that
never blocks on `input()`. Every handler that can actually run for real
(tier 0, or an auto-allowed tier 1) is patched at its module-level
dependency, the same pattern `test_handlers.py` uses — nothing here writes
a registry value, opens a Settings page, or synthesizes a keystroke on the
real machine.

`PolicyEngine._run` resolves every request through the process-global
`actions.lookup`, bound to the real `actions.REGISTRY`, regardless of what
registry the engine was constructed with (see `_helpers.build_engine`'s
docstring). That is why every test below dispatches a real action id
(`open_new_desktop`, `open_setting`, `shutdown_pc`) rather than a
fabricated stub action — there is no way to substitute one.
"""
from __future__ import annotations

from unittest.mock import patch

from _helpers import StubConfirmer, build_engine

from actions.handlers import desktops, settings
from actions.params import SettingPage
from policy.confirm import ConfirmationReply
from policy.types import Outcome, RejectionCode, Source

CHORD_LENGTH = 6  # Win+Ctrl+D: 3 key-down + 3 key-up, see test_handlers.py


# --- tier 0: auto-allowed, no prompt ---------------------------------------

def test_tier_zero_auto_allows_without_asking(tmp_path) -> None:
    confirmer = StubConfirmer()
    engine, _, _ = build_engine(tmp_path, confirmer)

    with patch.object(desktops, "_SendInput", return_value=CHORD_LENGTH):
        result = engine.execute("open_new_desktop", {}, source=Source.DESKTOP)

    assert result.decision.outcome is Outcome.AUTO_ALLOWED
    assert result.ok
    assert confirmer.call_count == 0, "tier 0 must never ask"


# --- tier 1: prompts; a decline is NOT_CONFIRMED ---------------------------

def test_tier_one_prompts_and_a_decline_is_not_confirmed(tmp_path) -> None:
    confirmer = StubConfirmer(ConfirmationReply(approved=False))
    engine, _, _ = build_engine(tmp_path, confirmer)

    result = engine.execute(
        "open_setting", {"page": "display"}, source=Source.DESKTOP
    )

    assert confirmer.call_count == 1
    assert result.decision.outcome is Outcome.REJECTED
    assert result.decision.code is RejectionCode.NOT_CONFIRMED
    assert not result.executed


# --- a granted exception auto-allows tier 1 without asking -----------------

def test_granted_exception_auto_allows_tier_one(tmp_path) -> None:
    confirmer = StubConfirmer(
        ConfirmationReply(approved=True, remember=True)
    )
    engine, store, _ = build_engine(tmp_path, confirmer)

    with patch.object(settings.os, "startfile"):
        first = engine.execute(
            "open_setting", {"page": "display"}, source=Source.DESKTOP
        )
    assert first.decision.outcome is Outcome.CONFIRMED
    assert confirmer.call_count == 1
    assert store.matches("open_setting", {"page": SettingPage.DISPLAY})

    with patch.object(settings.os, "startfile") as startfile:
        second = engine.execute(
            "open_setting", {"page": "display"}, source=Source.DESKTOP
        )

    assert second.decision.outcome is Outcome.AUTO_ALLOWED
    assert second.ok
    startfile.assert_called_once_with("ms-settings:display")
    assert confirmer.call_count == 1, "the second call must not ask again"


# --- provenance overrides a standing exception ------------------------------

def test_screen_context_still_prompts_despite_a_standing_exception(
    tmp_path,
) -> None:
    confirmer = StubConfirmer(ConfirmationReply(approved=False))
    engine, store, _ = build_engine(tmp_path, confirmer)
    engine.grant_exception("open_setting", {"page": SettingPage.DISPLAY})
    assert store.matches("open_setting", {"page": SettingPage.DISPLAY})

    result = engine.execute(
        "open_setting",
        {"page": "display"},
        source=Source.SCREEN_CONTEXT,
    )

    # engine.py:219-222 -- provenance forces a prompt even though the exact
    # (action, params) pair has a standing exception.
    assert confirmer.call_count == 1, "screen context must still be asked"
    assert result.decision.outcome is Outcome.REJECTED
    assert result.decision.code is RejectionCode.NOT_CONFIRMED


# --- tier 2 from screen context: rejected WITHOUT a prompt ------------------

def test_tier_two_from_screen_context_is_rejected_without_prompting(
    tmp_path,
) -> None:
    confirmer = StubConfirmer(ConfirmationReply(approved=True, typed="shutdown_pc"))
    engine, _, _ = build_engine(tmp_path, confirmer)

    result = engine.execute("shutdown_pc", {}, source=Source.SCREEN_CONTEXT)

    assert confirmer.call_count == 0, "tier 2 must never even be offered off-screen"
    assert result.decision.outcome is Outcome.REJECTED
    assert result.decision.code is RejectionCode.NOT_CONFIRMED
    assert not result.executed


# --- tier 2: approved=True with no typed challenge is still rejected -------

def test_tier_two_approved_without_typed_challenge_is_rejected(tmp_path) -> None:
    # Confirmer.verify requires the typed reply to equal the challenge for
    # any tier-2 prompt; `approved=True` alone is not sufficient, so a UI
    # bug or shortcut that forgets to collect the typed word cannot grant
    # an irreversible action.
    confirmer = StubConfirmer(ConfirmationReply(approved=True, typed=None))
    engine, _, _ = build_engine(tmp_path, confirmer)

    result = engine.execute("restart_pc", {}, source=Source.DESKTOP)

    assert confirmer.call_count == 1
    assert result.decision.outcome is Outcome.REJECTED
    assert result.decision.code is RejectionCode.NOT_CONFIRMED
    assert not result.executed
