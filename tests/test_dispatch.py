"""Dispatch exit codes and fail-closed behaviour.

`dispatch/cli.py` makes no permission decisions of its own any more — every
action id, whether known or not, now reaches `PolicyEngine.execute`, and
the exit code is derived purely from the `ExecutionResult` it returns
(`dispatch/cli.py::_exit_code`). These tests exercise that mapping, not a
second copy of the policy logic.

Every test that dispatches an action uses the `cli_runtime` fixture, which
builds a `PolicyEngine` against a tmp_path-scoped `ExceptionStore`/
`AuditLog` and a `StubConfirmer`, then installs it as `cli.ENGINE` /
`cli.STORE` so `cli.main()` never touches the real
`%LOCALAPPDATA%\\overlay-agent` files or blocks on `input()`
(`dispatch/cli.py::_runtime`). Real handlers that could actually run
(tier 0, or a confirmed/auto-allowed tier 1) are patched at their
module-level dependency, same as `test_handlers.py` — nothing here writes
a registry value, opens a Settings page, launches a process, or shuts the
machine down.
"""
from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import pytest

from _helpers import StubConfirmer, assert_raises, build_engine  # noqa: F401  (path shim)

from actions.handlers import desktops, power, settings
from actions.params import SettingPage
from dispatch import cli
from policy.audit import AuditLog
from policy.confirm import ConfirmationReply

OK, HANDLER_ERROR, REJECTED, NOT_CONFIRMED, RATE_LIMITED = 0, 1, 2, 3, 4

CHORD_LENGTH = 6  # Win+Ctrl+D: 3 key-down + 3 key-up, see test_handlers.py


def run(*argv: str) -> tuple[int, str, str]:
    """Call cli.main with output captured, returning (exit, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def cli_runtime(tmp_path, monkeypatch):
    """Install a tmp_path-scoped engine (default: always-decline confirmer)
    as the CLI's module-level singletons for the duration of one test."""
    confirmer = StubConfirmer()
    engine, store, audit = build_engine(tmp_path, confirmer)
    monkeypatch.setattr(cli, "ENGINE", engine)
    monkeypatch.setattr(cli, "STORE", store)
    return engine, store, confirmer


# --- rejection paths, all exit 2 (before any handler could run) -----------

def test_no_arguments_is_rejected() -> None:
    code, _, err = run()
    assert code == REJECTED
    assert "usage" in err


def test_unknown_action_id_is_rejected(cli_runtime) -> None:
    code, _, err = run("bogus_action")
    assert code == REJECTED
    assert "bogus_action" in err


def test_retired_night_light_id_is_rejected(cli_runtime) -> None:
    code, _, err = run("toggle_night_light")
    assert code == REJECTED
    assert "toggle_night_light" in err


def test_too_few_parameters_is_rejected(cli_runtime) -> None:
    code, _, err = run("open_setting")
    assert code == REJECTED
    assert "open_setting" in err


def test_too_many_parameters_is_rejected(cli_runtime) -> None:
    code, _, err = run("open_setting", "display", "extra")
    assert code == REJECTED


def test_parameters_on_a_zero_param_action_are_rejected(cli_runtime) -> None:
    code, _, err = run("toggle_dark_mode", "true")
    assert code == REJECTED


def test_unknown_whitelist_key_is_rejected(cli_runtime) -> None:
    code, _, err = run("open_application", "vscode")
    assert code == REJECTED
    assert "vscode" in err


def test_excluded_setting_page_is_rejected(cli_runtime) -> None:
    code, _, err = run("open_setting", "windows_security")
    assert code == REJECTED


# --- tier 2: the engine gates it now, not the dispatcher --------------------
# The old "dispatch refuses tier 2 outright" behaviour is gone (§6 build
# order: Phase 2 is exactly the policy engine that now owns this). A tier 2
# request from the desktop reaches the engine and is offered a typed
# confirmation; a confirmer that declines (the `cli_runtime` default) still
# produces a rejection, just NOT_CONFIRMED rather than a dispatch-level
# block, and still exits nonzero.

def test_tier_two_actions_require_confirmation_and_a_decline_is_rejected(
    cli_runtime,
) -> None:
    engine, _, confirmer = cli_runtime
    for action_id in ("shutdown_pc", "restart_pc"):
        code, _, err = run(action_id)
        assert code == NOT_CONFIRMED, action_id
    assert confirmer.call_count == 2, "both actions must have been asked"


def test_tier_two_never_reaches_its_handler_on_a_decline(cli_runtime) -> None:
    with patch.object(power, "_InitiateSystemShutdownExW") as shutdown_call:
        code, _, _ = run("shutdown_pc")

    assert code == NOT_CONFIRMED
    shutdown_call.assert_not_called()


# --- handler invocation, via real tier-0 / confirmed tier-1 actions --------

def test_successful_dispatch_calls_the_handler_and_exits_zero(cli_runtime) -> None:
    with patch.object(desktops, "_SendInput", return_value=CHORD_LENGTH) as send_input:
        code, _, _ = run("open_new_desktop")

    assert code == OK
    send_input.assert_called_once()


def test_parsed_typed_value_is_bound_to_the_handler_keyword(tmp_path, monkeypatch) -> None:
    # Exercises cli.py's _shape_params -> engine.execute -> handler(**parsed)
    # path end to end: the handler must receive the TYPED enum value, not
    # the raw string "display", under the keyword the ParamSpec names.
    confirmer = StubConfirmer(ConfirmationReply(approved=True))
    engine, store, audit = build_engine(tmp_path, confirmer)
    monkeypatch.setattr(cli, "ENGINE", engine)
    monkeypatch.setattr(cli, "STORE", store)

    with patch.object(settings.os, "startfile") as startfile:
        code, _, _ = run("open_setting", "display")

    assert code == OK
    # open_setting(page) calls os.startfile(page.value); if the CLI had
    # handed the engine the raw string instead of letting it parse to
    # SettingPage.DISPLAY, this would never be reached at all (a str has no
    # .value the handler could use this way) or a different value entirely.
    startfile.assert_called_once_with("ms-settings:display")


def test_handler_exception_is_reported_not_retried(cli_runtime) -> None:
    # A partial SendInput makes the real handler raise OSError -- same
    # failure mode as test_handlers.py::test_open_new_desktop_fails_closed_on_partial_send,
    # exercised here through the full CLI/engine path instead.
    with patch.object(desktops, "_SendInput", return_value=3) as send_input:
        code, _, err = run("open_new_desktop")

    assert code == HANDLER_ERROR
    assert send_input.call_count == 1, "a failed handler must not be retried"
    assert "error:" in err


# --- listing --------------------------------------------------------------

def test_list_prints_every_action_and_exits_zero() -> None:
    from actions import REGISTRY

    code, out, _ = run("list")
    assert code == OK
    for action in REGISTRY:
        assert action.id in out
    assert len(out.strip().splitlines()) == len(REGISTRY)


# --- exceptions list --------------------------------------------------------

def test_exceptions_list_says_so_plainly_when_empty(cli_runtime) -> None:
    code, out, _ = run("exceptions", "list")
    assert code == OK
    assert "no standing exceptions" in out


def test_exceptions_list_shows_a_granted_exception(cli_runtime) -> None:
    engine, _, _ = cli_runtime
    engine.grant_exception("open_setting", {"page": SettingPage.DISPLAY})

    code, out, _ = run("exceptions", "list")

    assert code == OK
    assert "open_setting" in out
    assert "page=DISPLAY" in out


# --- exceptions revoke ------------------------------------------------------

def test_exceptions_revoke_round_trip_parses_the_value(cli_runtime) -> None:
    # Subtlety 2: grants are stored from PARSED values (engine._ask calls
    # grant(action.id, tier, parsed)), so revoking with the raw string
    # "display" must be parsed to SettingPage.DISPLAY before calling
    # revoke_exception, or the signature never matches
    # (str:display != enum:DISPLAY) and the grant survives.
    engine, store, _ = cli_runtime
    engine.grant_exception("open_setting", {"page": SettingPage.DISPLAY})
    assert store.matches("open_setting", {"page": SettingPage.DISPLAY})

    code, out, _ = run("exceptions", "revoke", "open_setting", "page=display")

    assert code == OK
    assert "revoked" in out
    assert not store.matches("open_setting", {"page": SettingPage.DISPLAY})


def test_exceptions_revoke_reports_no_match_without_erroring(cli_runtime) -> None:
    code, out, _ = run("exceptions", "revoke", "open_setting", "page=display")
    assert code == OK
    assert "no matching exception" in out


def test_exceptions_revoke_unknown_action_id_exits_two(cli_runtime) -> None:
    code, _, err = run("exceptions", "revoke", "bogus_action")
    assert code == REJECTED
    assert "bogus_action" in err


def test_exceptions_revoke_rejects_an_invalid_param_value(cli_runtime) -> None:
    code, _, err = run("exceptions", "revoke", "open_setting", "page=not_a_page")
    assert code == REJECTED
    assert "not_a_page" in err


def test_exceptions_revoke_rejects_malformed_pair(cli_runtime) -> None:
    code, _, err = run("exceptions", "revoke", "open_setting", "page-display")
    assert code == REJECTED


# --- exceptions revoke-all ---------------------------------------------------

def test_exceptions_revoke_all_reports_the_count_and_empties_the_store(
    cli_runtime,
) -> None:
    engine, store, _ = cli_runtime
    engine.grant_exception("open_setting", {"page": SettingPage.DISPLAY})
    engine.grant_exception("open_application", {"app": "notepad"})

    code, out, _ = run("exceptions", "revoke-all")

    assert code == OK
    assert "2" in out
    assert store.list() == []


def test_exceptions_revoke_all_audits_each_grant_before_the_summary(
    cli_runtime, tmp_path
) -> None:
    # `_exceptions_revoke_all` now goes through
    # `engine.revoke_all_exceptions()` (not `ExceptionStore.revoke_all()`
    # directly) so that a bulk revoke leaves the same per-action trail an
    # individual `exceptions revoke` does -- §12.1's inspect-and-revoke
    # contract, applied to the bulk path too.
    engine, store, _ = cli_runtime
    engine.grant_exception("open_setting", {"page": SettingPage.DISPLAY})
    engine.grant_exception("open_application", {"app": "notepad"})

    code, _, _ = run("exceptions", "revoke-all")
    assert code == OK

    # AuditLog has no public read method beyond verify_chain(), so the
    # jsonl file is read directly here. Records are flat on disk (`note()`
    # spreads its payload straight into the top-level JSON object rather
    # than nesting it), so filter by the `event` key.
    audit_path = tmp_path / "audit.jsonl"
    records = [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    revoked_indexes = [
        i for i, r in enumerate(records) if r.get("event") == "exception_revoked"
    ]
    summary_indexes = [
        i for i, r in enumerate(records) if r.get("event") == "exceptions_revoke_all"
    ]

    # grant_exception also writes an exception_granted note per call, so
    # the file holds more than just the revoke records above -- filtering
    # by event, rather than assuming an exact line count, is what makes
    # this robust to that.
    assert len(revoked_indexes) == 2
    assert len(summary_indexes) == 1
    assert records[summary_indexes[0]]["count"] == 2

    revoked_action_ids = {records[i]["action_id"] for i in revoked_indexes}
    assert revoked_action_ids == {"open_setting", "open_application"}

    # the summary note must be written after BOTH per-grant notes, so the
    # log reads "these were revoked, then the bulk op completed", in that
    # order, on disk.
    assert max(revoked_indexes) < summary_indexes[0]

    assert AuditLog(audit_path).verify_chain()

    assert store.list() == []
