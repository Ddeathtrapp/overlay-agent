"""KI-6: `PolicyEngine._pending_confirmation` had no test coverage.

architecture.md §7 / engine.py's `__init__` comment: this flag is the WHOLE
mitigation for the T7 composition finding. `open_new_desktop` is tier 0, so
it auto-allows with no prompt of its own, and Win+Ctrl+D switches the user
to a different virtual desktop -- away from a confirmation dialog they have
not yet answered. Windows offers no supported way to pin a window across
virtual desktops, so this block is not a supplement to a mitigation, it IS
the mitigation. If it silently stopped firing, every open confirmation
would become a window for a tier-0 (or exception-matched) action to run
underneath it, unseen.

`src/policy/engine.py` and `src/policy/confirm.py` are human-owned and are
read here, never modified. Everything below lives in `tests/`, which
architecture.md §6 lists as open to every agent.

Concurrency discipline (see the task brief this file was written against):
every blocking wait has an explicit timeout, the second `execute()` in the
"while a confirmation is open" tests is driven from a daemon thread and
joined with a timeout rather than called inline, and the handshake between
threads uses `threading.Event`, never a sleep. `_HandshakeConfirmer.ask()`
sets `prompt_open` on entry and then waits on `release` -- with its own
bounded timeout, so a bug here fails a test instead of hanging the suite.
"""
from __future__ import annotations

import json
import threading
import time
from unittest.mock import patch

from _helpers import build_engine, StubConfirmer

from actions.handlers import desktops, settings
from policy import confirm as confirm_module
from policy import engine as engine_module
from policy.confirm import Confirmer, ConfirmationReply
from policy.types import Outcome, RejectionCode, Source

_JOIN_TIMEOUT = 5.0  # generous ceiling for any cross-thread wait in this file


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _HandshakeConfirmer(Confirmer):
    """A confirmer whose `.ask()` blocks until the test releases it.

    `prompt_open` is set the instant `.ask()` is entered -- the test waits
    on this before firing a second `execute()`, which is what makes "while
    a confirmation is open" deterministic instead of timing-dependent.
    `.ask()` then waits on `release`, itself bounded, so a test that forgets
    to release it fails instead of hanging the run.
    """

    def __init__(self, reply: ConfirmationReply | None = None) -> None:
        self.prompt_open = threading.Event()
        self.release = threading.Event()
        self._reply = reply if reply is not None else ConfirmationReply(approved=True)
        self.asked = False

    def ask(self, prompt):  # noqa: D102 - see class docstring
        self.asked = True
        self.prompt_open.set()
        self.release.wait(timeout=_JOIN_TIMEOUT)
        return self._reply


class _HangingConfirmer(Confirmer):
    """`.ask()` outlasts the engine's own confirmation timeout.

    Used only for the timeout test. The wait is bounded so that if the
    `build_prompt` timeout override in the test ever fails to apply, the
    test fails on ITS OWN timeout rather than hanging the suite for the
    real 120s default.
    """

    def __init__(self) -> None:
        self.entered = threading.Event()

    def ask(self, prompt):  # noqa: D102 - see class docstring
        self.entered.set()
        threading.Event().wait(timeout=_JOIN_TIMEOUT)
        return ConfirmationReply(approved=True)


class _RaisingConfirmer(Confirmer):
    """`.ask()` blows up instead of answering -- a broken UI, not a no."""

    def ask(self, prompt):  # noqa: D102 - see class docstring
        raise RuntimeError("confirmer blew up")


class _MalformedConfirmer(Confirmer):
    """`.ask()` returns something that is not a `ConfirmationReply`.

    `ConfirmationReply` validates its own fields at construction, so the
    only way to produce a "malformed reply" is to have the confirmer
    return a different type outright -- e.g. a UI that hands back a raw
    dict instead of constructing the dataclass.
    """

    def ask(self, prompt):  # noqa: D102 - see class docstring
        return {"approved": True}


# ---------------------------------------------------------------------------
# Thread helpers
# ---------------------------------------------------------------------------


def _start_blocking_call(engine, confirmer, action_id, raw_params):
    """Start `action_id` on a daemon thread and wait until the confirmer's
    `.ask()` has actually been entered, so the caller can rely on
    `_pending_confirmation` being True before doing anything else.

    Returns `(thread, result)` where `result` is a one-element list the
    thread appends its `ExecutionResult` to once `execute()` returns -- or
    the raised exception instance, if `execute()` raised instead of
    returning. Captured explicitly rather than left for pytest's
    thread-exception hook, so a test that expects a raise can assert on it
    deterministically instead of just leaving a stray warning.
    """
    result: list = []

    def worker() -> None:
        try:
            result.append(engine.execute(action_id, raw_params, source=Source.DESKTOP))
        except BaseException as exc:  # noqa: BLE001 - captured for the test to inspect
            result.append(exc)

    thread = threading.Thread(target=worker, daemon=True, name=f"first-{action_id}")
    thread.start()
    opened = confirmer.prompt_open.wait(timeout=_JOIN_TIMEOUT)
    if not opened:
        raise AssertionError(
            f"confirmer.ask() for {action_id!r} was never entered within "
            f"{_JOIN_TIMEOUT}s -- the first call never reached phase B"
        )
    return thread, result


def _run_execute_in_thread(engine, action_id, raw_params):
    """Drive one `execute()` call from its own daemon thread and join with
    a timeout, per the brief: never call the "second" execute() inline
    while a first one may be holding phase B open, so a deadlock in the
    engine fails this test loudly instead of hanging the suite.
    """
    result: list = []

    def worker() -> None:
        result.append(engine.execute(action_id, raw_params, source=Source.DESKTOP))

    thread = threading.Thread(target=worker, daemon=True, name=f"second-{action_id}")
    thread.start()
    thread.join(_JOIN_TIMEOUT)
    if thread.is_alive():
        raise AssertionError(
            f"execute({action_id!r}) did not return within {_JOIN_TIMEOUT}s "
            f"-- the engine appears to have deadlocked"
        )
    if not result:
        raise AssertionError(f"execute({action_id!r}) thread produced no result")
    return result[0]


def _join(thread: threading.Thread) -> None:
    thread.join(_JOIN_TIMEOUT)
    if thread.is_alive():
        raise AssertionError("background thread did not finish within the join timeout")


# ---------------------------------------------------------------------------
# 1 + 3: a second execute() while a confirmation is open is rejected with
# CONFIRMATION_PENDING, its handler never runs, and the rejection is audited.
# ---------------------------------------------------------------------------


def test_second_execute_rejected_while_confirmation_pending_and_audited(tmp_path) -> None:
    confirmer = _HandshakeConfirmer(reply=ConfirmationReply(approved=True))
    engine, _, _ = build_engine(tmp_path, confirmer)

    first_thread, first_result = _start_blocking_call(
        engine, confirmer, "open_setting", {"page": "display"}
    )
    try:
        # A second, distinct request arrives while the first prompt is open.
        with patch.object(settings.os, "startfile") as startfile:
            second = _run_execute_in_thread(
                engine, "open_setting", {"page": "sound"}
            )

        assert second.decision.outcome is Outcome.REJECTED
        assert second.decision.code is RejectionCode.CONFIRMATION_PENDING
        assert not second.executed
        startfile.assert_not_called()
    finally:
        confirmer.release.set()
        _join(first_thread)

    assert first_result and first_result[0].decision.outcome is Outcome.CONFIRMED

    # The rejection must be audited -- an earlier version of this branch
    # raised AttributeError before `_reject` ran, which would have produced
    # the only rejection in the engine with no audit record at all.
    log_path = tmp_path / "audit.jsonl"
    records = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
    pending_records = [r for r in records if r.get("code") == "confirmation_pending"]
    assert pending_records, (
        "expected a decision record with code == 'confirmation_pending' in "
        f"{log_path}, got codes {[r.get('code') for r in records]}"
    )


# ---------------------------------------------------------------------------
# 2: the block applies to tier 0. open_new_desktop specifically -- it is
# the action the mitigation exists for.
# ---------------------------------------------------------------------------


def test_tier_zero_open_new_desktop_is_blocked_while_confirmation_pending(tmp_path) -> None:
    confirmer = _HandshakeConfirmer(reply=ConfirmationReply(approved=True))
    engine, _, _ = build_engine(tmp_path, confirmer)

    first_thread, first_result = _start_blocking_call(
        engine, confirmer, "open_setting", {"page": "display"}
    )
    try:
        with patch.object(desktops, "_SendInput") as send_input:
            second = _run_execute_in_thread(engine, "open_new_desktop", {})

        # Without the check, open_new_desktop -- tier 0 -- would auto-allow
        # and run the SendInput chord DURING the open prompt, switching the
        # user to a different virtual desktop and away from a dialog they
        # have not answered.
        assert second.decision.outcome is Outcome.REJECTED
        assert second.decision.code is RejectionCode.CONFIRMATION_PENDING
        assert not second.executed
        send_input.assert_not_called()
    finally:
        confirmer.release.set()
        _join(first_thread)

    assert first_result and first_result[0].decision.outcome is Outcome.CONFIRMED


# ---------------------------------------------------------------------------
# 4: the flag clears after the confirmation resolves, and a later action
# succeeds.
# ---------------------------------------------------------------------------


def test_pending_flag_clears_after_resolution_and_later_action_succeeds(tmp_path) -> None:
    confirmer = _HandshakeConfirmer(reply=ConfirmationReply(approved=True))
    engine, _, _ = build_engine(tmp_path, confirmer)

    first_thread, first_result = _start_blocking_call(
        engine, confirmer, "open_setting", {"page": "display"}
    )
    # Prove the flag is actually set while the prompt is open, using the
    # SAME tier-0 action the mitigation exists for.
    with patch.object(desktops, "_SendInput") as send_input:
        blocked = _run_execute_in_thread(engine, "open_new_desktop", {})
    assert blocked.decision.code is RejectionCode.CONFIRMATION_PENDING
    send_input.assert_not_called()

    confirmer.release.set()
    _join(first_thread)
    assert first_result[0].decision.outcome is Outcome.CONFIRMED

    # Now that the confirmation has resolved, a later action must succeed --
    # not be rejected by a flag that failed to clear.
    with patch.object(desktops, "_SendInput", return_value=6) as send_input:
        later = engine.execute("open_new_desktop", {}, source=Source.DESKTOP)

    assert later.decision.outcome is Outcome.AUTO_ALLOWED
    assert later.ok
    send_input.assert_called_once()


# ---------------------------------------------------------------------------
# 5: the flag clears when the confirmer raises, times out, or returns a
# malformed reply. Each case: a subsequent action must not be blocked.
# ---------------------------------------------------------------------------


def test_pending_flag_clears_when_confirmer_raises(tmp_path) -> None:
    confirmer = _RaisingConfirmer()
    engine, _, _ = build_engine(tmp_path, confirmer)

    first = engine.execute("open_setting", {"page": "display"}, source=Source.DESKTOP)
    assert first.decision.outcome is Outcome.REJECTED
    assert first.decision.code is RejectionCode.NOT_CONFIRMED

    with patch.object(desktops, "_SendInput", return_value=6) as send_input:
        later = engine.execute("open_new_desktop", {}, source=Source.DESKTOP)

    assert later.decision.outcome is Outcome.AUTO_ALLOWED
    assert later.ok
    send_input.assert_called_once()


def test_pending_flag_clears_when_any_exception_escapes_ask(tmp_path) -> None:
    """This test exists because the other test's escape route is not
    stable -- it depends on which exceptions `_ask` declines to catch, and
    that has already changed once this week (it used to be `AuditWriteFailed`
    from `audit.note`; `_ask` now catches that, so the test was retargeted
    to `OSError` from `store.grant`). If `grant` ever grows a broader
    `except` around it, that test goes vacuous and nothing notices.

    This test instead patches `_ask` itself (the instance, not the class,
    so nothing leaks into other tests) so the escape is forced at the
    `_run` level regardless of how `_ask` handles exceptions internally --
    it proves the `finally` in `_run` clears `_pending_confirmation` for
    ANY exception escaping `_ask`, not just the one the other test happens
    to exercise today.

    Fully synchronous: patching `_ask` makes it raise immediately, so no
    confirmer is ever invoked and there is nothing to hand-shake with.
    """
    engine, _, _ = build_engine(tmp_path, StubConfirmer())

    with patch.object(engine, "_ask", side_effect=RuntimeError("forced escape")):
        try:
            engine.execute("open_setting", {"page": "display"}, source=Source.DESKTOP)
            raised = False
        except RuntimeError:
            raised = True

    assert raised, "RuntimeError from _ask should propagate out of execute(), not be swallowed"
    assert engine._pending_confirmation is False

    with patch.object(desktops, "_SendInput", return_value=6) as send_input:
        later = engine.execute("open_new_desktop", {}, source=Source.DESKTOP)

    assert later.decision.outcome is Outcome.AUTO_ALLOWED
    assert later.ok
    send_input.assert_called_once()


def test_pending_flag_clears_when_confirmer_returns_malformed_reply(tmp_path) -> None:
    confirmer = _MalformedConfirmer()
    engine, _, _ = build_engine(tmp_path, confirmer)

    first = engine.execute("open_setting", {"page": "display"}, source=Source.DESKTOP)
    assert first.decision.outcome is Outcome.REJECTED
    assert first.decision.code is RejectionCode.NOT_CONFIRMED

    with patch.object(desktops, "_SendInput", return_value=6) as send_input:
        later = engine.execute("open_new_desktop", {}, source=Source.DESKTOP)

    assert later.decision.outcome is Outcome.AUTO_ALLOWED
    assert later.ok
    send_input.assert_called_once()


def test_pending_flag_clears_on_confirmation_timeout(tmp_path) -> None:
    # `build_prompt(..., timeout_seconds=DEFAULT_TIMEOUT_SECONDS)` binds
    # its default (120.0) at function-definition time -- monkeypatching
    # `policy.confirm.DEFAULT_TIMEOUT_SECONDS` after import would not
    # touch it. Instead, patch `policy.engine.build_prompt` (the name
    # engine.py actually calls) with a wrapper that forces a short
    # timeout, and verify by wall clock that it actually took effect
    # rather than trusting the patch silently.
    confirmer = _HangingConfirmer()
    engine, _, _ = build_engine(tmp_path, confirmer)

    real_build_prompt = confirm_module.build_prompt

    def short_timeout_build_prompt(*args, **kwargs):
        kwargs["timeout_seconds"] = 0.2
        return real_build_prompt(*args, **kwargs)

    started = time.monotonic()
    with patch.object(engine_module, "build_prompt", side_effect=short_timeout_build_prompt):
        first = engine.execute("open_setting", {"page": "display"}, source=Source.DESKTOP)
    elapsed = time.monotonic() - started

    # Confirms the override actually shortened the wait: if it silently
    # fell back to the 120s default this would fail here, fast, rather
    # than the test hanging for two minutes.
    assert elapsed < 5.0, (
        f"execute() took {elapsed:.1f}s -- build_prompt patch did not shorten "
        f"the confirmation timeout as expected"
    )
    assert confirmer.entered.is_set()
    assert first.decision.outcome is Outcome.REJECTED
    assert first.decision.code is RejectionCode.NOT_CONFIRMED

    with patch.object(desktops, "_SendInput", return_value=6) as send_input:
        later = engine.execute("open_new_desktop", {}, source=Source.DESKTOP)

    assert later.decision.outcome is Outcome.AUTO_ALLOWED
    assert later.ok
    send_input.assert_called_once()


# ---------------------------------------------------------------------------
# 5, continued: `_ask` does not only convert a raising/timing-out/malformed
# CONFIRMER into a Decision -- it can raise past the confirmer entirely.
# `AuditWriteFailed` from the "exception_granted" note is no longer that
# escape: `_ask` now catches `AuditWriteFailed` around that note explicitly
# (the grant is already on disk, so losing its note must not break the
# ExecutionResult contract on a path the human already approved). The
# surviving escape is `self._exceptions.grant(...)` itself -- it is wrapped
# only in `except ExceptionRefused`, so an `OSError` from it (realistic,
# since `ExceptionStore.grant` takes a `FileLock` and does file IO) is not
# caught and propagates out of `_ask`, through `_run`'s `try/finally`, and
# out of `execute()` to the caller instead of returning an `ExecutionResult`.
# `_run`'s `finally` is what still clears the flag on this path; the tests
# above never reach it, because `_ask` swallows every confirmer-level
# failure and returns normally.
# ---------------------------------------------------------------------------


def test_pending_flag_clears_when_ask_itself_raises_past_the_confirmer(tmp_path) -> None:
    confirmer = _HandshakeConfirmer(
        reply=ConfirmationReply(approved=True, remember=True)
    )
    engine, store, audit = build_engine(tmp_path, confirmer)

    first_thread, first_result = _start_blocking_call(
        engine, confirmer, "open_setting", {"page": "display"}
    )
    # Patch BEFORE releasing: the background thread reaches `store.grant`
    # asynchronously once released, and the patch must already be in place
    # or the race could let the real call through.
    with patch.object(store, "grant", side_effect=OSError("lock unavailable")):
        confirmer.release.set()
        _join(first_thread)

    assert first_result and isinstance(first_result[0], OSError), (
        "execute() should have raised OSError rather than "
        f"returning normally, got {first_result!r}"
    )

    with patch.object(desktops, "_SendInput", return_value=6) as send_input:
        later = engine.execute("open_new_desktop", {}, source=Source.DESKTOP)

    assert later.decision.outcome is Outcome.AUTO_ALLOWED
    assert later.ok
    send_input.assert_called_once()
