"""Dispatch exit codes and fail-closed behaviour.

Nothing here invokes a real handler. Rejection paths never reach one by
construction; the two tests that do reach a handler substitute a recording
stub, so running this suite never launches a process or shuts the machine down.
"""
from __future__ import annotations

import io
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from _helpers import assert_raises  # noqa: F401  (path shim)

from actions.params import EnumParam, SettingPage
from actions.schema import Action, Tier
from dispatch import cli

OK, HANDLER_ERROR, REJECTED, TIER_TWO_BLOCKED = 0, 1, 2, 3


def run(*argv: str) -> tuple[int, str, str]:
    """Call cli.main with output captured, returning (exit, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def stub_action(**overrides: object) -> Action:
    defaults = dict(id="stub", tier=Tier.ZERO, description="Stub.",
                    params=(), reversible=True, handler=lambda: None)
    defaults.update(overrides)
    return Action(**defaults)  # type: ignore[arg-type]


# --- rejection paths, all exit 2 ------------------------------------------

def test_no_arguments_is_rejected() -> None:
    code, _, err = run()
    assert code == REJECTED
    assert "usage" in err


def test_unknown_action_id_is_rejected() -> None:
    code, _, err = run("bogus_action")
    assert code == REJECTED
    assert "unknown action id" in err


def test_retired_night_light_id_is_rejected() -> None:
    code, _, err = run("toggle_night_light")
    assert code == REJECTED
    assert "unknown action id" in err


def test_too_few_parameters_is_rejected() -> None:
    code, _, err = run("open_setting")
    assert code == REJECTED
    assert "parameter" in err


def test_too_many_parameters_is_rejected() -> None:
    code, _, err = run("open_setting", "display", "extra")
    assert code == REJECTED
    assert "parameter" in err


def test_parameters_on_a_zero_param_action_are_rejected() -> None:
    code, _, err = run("toggle_dark_mode", "true")
    assert code == REJECTED


def test_unknown_whitelist_key_is_rejected() -> None:
    code, _, err = run("open_application", "vscode")
    assert code == REJECTED
    assert "vscode" in err


def test_excluded_setting_page_is_rejected() -> None:
    code, _, err = run("open_setting", "windows_security")
    assert code == REJECTED


# --- tier 2 is unreachable until the policy engine exists (§6) -------------

def test_tier_two_actions_are_blocked() -> None:
    for action_id in ("shutdown_pc", "restart_pc"):
        code, _, err = run(action_id)
        assert code == TIER_TWO_BLOCKED, action_id
        assert "policy engine" in err, action_id


def test_tier_two_never_reaches_its_handler() -> None:
    called = False

    def handler() -> None:
        nonlocal called
        called = True

    with patch.object(cli, "lookup",
                      return_value=stub_action(tier=Tier.TWO, reversible=False,
                                               handler=handler)):
        code, _, _ = run("stub")

    assert code == TIER_TWO_BLOCKED
    assert not called, "tier 2 handler was invoked — the gate leaked"


# --- handler invocation ---------------------------------------------------

def test_successful_dispatch_calls_the_handler_and_exits_zero() -> None:
    called = False

    def handler() -> None:
        nonlocal called
        called = True

    with patch.object(cli, "lookup",
                      return_value=stub_action(handler=handler)):
        code, _, _ = run("stub")

    assert code == OK
    # Asserted on a flag, not on absence of output: exit 0 alone cannot
    # distinguish "handler ran" from "handler was never reached", which would
    # make the tier-2 block test prove nothing by contrast.
    assert called, "handler was not invoked"


def test_parsed_typed_value_is_bound_to_the_handler_keyword() -> None:
    # Exercises cli.py's parsed[spec.name] -> handler(**parsed) path: the
    # handler must receive the TYPED value, not the raw string, under the
    # keyword named by the ParamSpec.
    received: dict[str, object] = {}

    def handler(page: object) -> None:
        received["page"] = page

    stub = stub_action(params=(EnumParam("page", SettingPage),),
                       handler=handler)
    with patch.object(cli, "lookup", return_value=stub):
        code, _, _ = run("stub", "display")

    assert code == OK
    assert received["page"] is SettingPage.DISPLAY
    assert not isinstance(received["page"], str)


def test_handler_exception_is_reported_not_retried() -> None:
    calls = 0

    def handler() -> None:
        nonlocal calls
        calls += 1
        raise RuntimeError("handler blew up")

    with patch.object(cli, "lookup",
                      return_value=stub_action(handler=handler)):
        code, _, err = run("stub")

    assert code == HANDLER_ERROR
    assert calls == 1, "a failed handler must not be retried"
    assert "handler blew up" in err


# --- listing --------------------------------------------------------------

def test_list_prints_every_action_and_exits_zero() -> None:
    from actions import REGISTRY

    code, out, _ = run("list")
    assert code == OK
    for action in REGISTRY:
        assert action.id in out
    assert len(out.strip().splitlines()) == len(REGISTRY)
