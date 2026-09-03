"""policy.confirm: ConfirmationReply validation, Confirmer.verify's typed
tier-2 challenge, Confirmer.may_remember, and build_prompt's tier/trust
rules.

§5's whole irreversible-action guarantee lives in `Confirmer.verify` and
`build_prompt` -- the confirmer implementations themselves (console, phone,
desktop) are untrusted UI code, so these are the only checks standing
between "approved=True" and an actual shutdown. Before this file, the one
existing tier-2 test in test_policy_engine.py only ever passed `typed=None`,
so `verify` could have been implemented as `return reply.typed is not None`
and every test would still have passed. The tests below pin the ACTUAL
contract: the typed word must equal the action id, case-sensitively, with
surrounding whitespace tolerated and nothing else.
"""
from __future__ import annotations

from _helpers import assert_raises

from policy.confirm import (
    TIER_TWO,
    Confirmer,
    ConfirmationPrompt,
    ConfirmationReply,
    build_prompt,
)


def _prompt(tier: int, source_trusted: bool, action_id: str = "shutdown_pc") -> ConfirmationPrompt:
    return build_prompt(
        action_id=action_id,
        description="test action",
        params={},
        tier=tier,
        source_label="desktop",
        source_trusted=source_trusted,
    )


# --- ConfirmationReply: validated at construction, not truthiness-tested ---


def test_confirmation_reply_rejects_string_approved() -> None:
    # {"approved": "false"} deserialised naively -- the string "false" is
    # truthy, so this must raise rather than silently approve.
    assert_raises(TypeError, ConfirmationReply, "false")


def test_confirmation_reply_rejects_list_approved() -> None:
    assert_raises(TypeError, ConfirmationReply, [0])


def test_confirmation_reply_rejects_string_remember() -> None:
    assert_raises(TypeError, ConfirmationReply, True, None, "yes")


def test_confirmation_reply_rejects_non_string_typed() -> None:
    assert_raises(TypeError, ConfirmationReply, True, 5)


def test_confirmation_reply_valid_forms_construct() -> None:
    plain = ConfirmationReply(True)
    assert plain.approved is True
    assert plain.typed is None
    assert plain.remember is False

    declined = ConfirmationReply(False)
    assert declined.approved is False

    typed = ConfirmationReply(True, "shutdown_pc")
    assert typed.typed == "shutdown_pc"

    remembered = ConfirmationReply(True, None, True)
    assert remembered.remember is True


# --- build_prompt: challenge only for tier 2 --------------------------------


def test_build_prompt_challenge_is_action_id_for_tier_two() -> None:
    prompt = _prompt(tier=2, source_trusted=True, action_id="shutdown_pc")
    assert prompt.challenge == "shutdown_pc"
    assert prompt.requires_typed is True


def test_build_prompt_challenge_is_none_below_tier_two() -> None:
    for tier in (0, 1):
        prompt = _prompt(tier=tier, source_trusted=True)
        assert prompt.challenge is None
        assert prompt.requires_typed is False


# --- build_prompt: allow_remember follows source_trusted, except tier 2 ----


def test_build_prompt_allow_remember_false_when_source_untrusted() -> None:
    for tier in (0, 1):
        prompt = _prompt(tier=tier, source_trusted=False)
        assert prompt.allow_remember is False


def test_build_prompt_allow_remember_true_when_source_trusted_below_tier_two() -> None:
    for tier in (0, 1):
        prompt = _prompt(tier=tier, source_trusted=True)
        assert prompt.allow_remember is True


def test_build_prompt_allow_remember_always_false_for_tier_two() -> None:
    # §5 forbids excepting an irreversible action -- this must hold
    # regardless of how trusted the source is.
    assert _prompt(tier=TIER_TWO, source_trusted=True).allow_remember is False
    assert _prompt(tier=TIER_TWO, source_trusted=False).allow_remember is False


# --- Confirmer.verify: the tier-2 typed challenge ---------------------------


def test_verify_correct_word_allows() -> None:
    prompt = _prompt(tier=2, source_trusted=True, action_id="shutdown_pc")
    reply = ConfirmationReply(True, "shutdown_pc")
    assert Confirmer.verify(prompt, reply) is True


def test_verify_wrong_word_refuses() -> None:
    prompt = _prompt(tier=2, source_trusted=True, action_id="shutdown_pc")
    reply = ConfirmationReply(True, "not_the_word")
    assert Confirmer.verify(prompt, reply) is False


def test_verify_whitespace_around_correct_word_still_allows() -> None:
    prompt = _prompt(tier=2, source_trusted=True, action_id="shutdown_pc")
    reply = ConfirmationReply(True, "  shutdown_pc  ")
    assert Confirmer.verify(prompt, reply) is True


def test_verify_case_mismatch_refuses() -> None:
    # verify() strips whitespace but does not fold case -- typing the
    # action id proves the human read it, and a case-insensitive compare
    # would let "SHUTDOWN_PC" or "Shutdown_Pc" pass as "close enough".
    prompt = _prompt(tier=2, source_trusted=True, action_id="shutdown_pc")
    reply = ConfirmationReply(True, "SHUTDOWN_PC")
    assert Confirmer.verify(prompt, reply) is False


def test_verify_approved_false_with_correct_typed_word_still_refuses() -> None:
    prompt = _prompt(tier=2, source_trusted=True, action_id="shutdown_pc")
    reply = ConfirmationReply(False, "shutdown_pc")
    assert Confirmer.verify(prompt, reply) is False


def test_verify_typed_none_on_tier_two_refuses() -> None:
    prompt = _prompt(tier=2, source_trusted=True, action_id="shutdown_pc")
    reply = ConfirmationReply(True, None)
    assert Confirmer.verify(prompt, reply) is False


def test_verify_tier_one_approved_needs_no_typed_word() -> None:
    prompt = _prompt(tier=1, source_trusted=True)
    reply = ConfirmationReply(True)
    assert Confirmer.verify(prompt, reply) is True


# --- Confirmer.may_remember: tier 2 can never be excepted -------------------


def test_may_remember_false_for_tier_two_even_if_reply_asks() -> None:
    prompt = _prompt(tier=2, source_trusted=True, action_id="shutdown_pc")
    reply = ConfirmationReply(True, "shutdown_pc", True)
    assert Confirmer.may_remember(prompt, reply) is False


def test_may_remember_false_when_prompt_forbids_it() -> None:
    prompt = _prompt(tier=1, source_trusted=False)  # allow_remember is False
    reply = ConfirmationReply(True, None, True)
    assert Confirmer.may_remember(prompt, reply) is False


def test_may_remember_true_when_reply_asks_and_prompt_allows() -> None:
    prompt = _prompt(tier=1, source_trusted=True)
    reply = ConfirmationReply(True, None, True)
    assert Confirmer.may_remember(prompt, reply) is True
