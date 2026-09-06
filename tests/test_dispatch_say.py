"""`cli.py say` — the classifier-mediated dispatch path.

`classifier.classify.Classifier` is ALWAYS stubbed here (`patch(
"classifier.classify.Classifier", ...)`) -- nothing in this file may reach
Ollama. The stub matches the constructor shape `dispatch.cli._say` actually
calls it with (`Classifier(REGISTRY)`, i.e. one positional arg, no
`client=`) and returns a scripted `Classification` regardless of what
utterance it is given.

Because `dispatch.cli._say` imports `Classifier` lazily (inside the
function, so the direct-dispatch subcommands never pay Ollama's import
cost), the patch target is `classifier.classify.Classifier` -- the name as
it exists at *its* module -- not `dispatch.cli.Classifier`, which does not
exist until `_say` runs (see `docs/action-registry.md` discussion in
`cli.py`'s own module docstring for the same lazy-import reasoning).

Every test that builds a real `PolicyEngine` goes through
`_helpers.build_engine` (tmp_path-scoped store/audit) and installs it as
`cli.ENGINE` / `cli.STORE`, same convention as `test_dispatch.py`.
"""
from __future__ import annotations

import io
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import MagicMock, patch

import pytest

from _helpers import StubConfirmer, build_engine  # noqa: F401  (path shim)

from actions.handlers import apps, desktops
from classifier.classify import NO_MATCH, Classification, Reason
from dispatch import cli
from policy.confirm import ConfirmationReply
from policy.types import Source

OK, HANDLER_ERROR, REJECTED, NOT_CONFIRMED, RATE_LIMITED = 0, 1, 2, 3, 4
COMPREHENSION, INFRASTRUCTURE = 5, 6

CHORD_LENGTH = 6  # Win+Ctrl+D: 3 key-down + 3 key-up, see test_handlers.py


def run(*argv: str) -> tuple[int, str, str]:
    """Call cli.main with output captured, returning (exit, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def _stub_classifier(classification: Classification):
    """A stand-in for `classifier.classify.Classifier`: same constructor
    shape (`Classifier(registry, client=None)`), but `.classify()` returns
    a scripted `Classification` instead of ever talking to Ollama."""

    class _Stub:
        def __init__(self, registry, client=None) -> None:
            pass

        def classify(self, utterance: str, screen_context: str | None = None) -> Classification:
            return classification

    return _Stub


@pytest.fixture
def cli_runtime(tmp_path, monkeypatch):
    """Install a tmp_path-scoped engine (default: always-decline confirmer)
    as the CLI's module-level singletons for the duration of one test."""
    confirmer = StubConfirmer()
    engine, store, audit = build_engine(tmp_path, confirmer)
    monkeypatch.setattr(cli, "ENGINE", engine)
    monkeypatch.setattr(cli, "STORE", store)
    return engine, store, confirmer


# --- a matched classification reaches the engine, correctly stamped -------

def test_matched_classification_reaches_engine_with_desktop_source_and_utterance(
    tmp_path, monkeypatch
) -> None:
    utterance = "open notepad please"
    classification = Classification(
        action_id="open_application",
        raw_params={"app": "notepad"},
        reason=Reason.MATCHED,
    )
    confirmer = StubConfirmer(ConfirmationReply(approved=True))
    engine, store, audit = build_engine(tmp_path, confirmer)
    monkeypatch.setattr(cli, "ENGINE", engine)
    monkeypatch.setattr(cli, "STORE", store)

    spy = MagicMock(side_effect=engine.execute)
    monkeypatch.setattr(engine, "execute", spy)

    with patch("classifier.classify.Classifier", _stub_classifier(classification)), \
            patch.object(apps.subprocess, "Popen") as popen:
        code, out, _ = run("say", utterance)

    assert code == OK
    popen.assert_called_once()

    # Assert the actual kwarg VALUES, not merely that execute was called:
    # a source or utterance smuggled in under the wrong keyword, or a
    # provenance derived from the classification instead of a literal,
    # would still satisfy "was called" but not this.
    spy.assert_called_once_with(
        "open_application",
        {"app": "notepad"},
        source=Source.DESKTOP,
        utterance=utterance,
    )
    args, kwargs = spy.call_args
    assert kwargs["source"] is Source.DESKTOP
    assert kwargs["utterance"] == utterance


# --- describe() is printed before dispatch, even for a silent auto-allow --

def test_describe_line_is_printed_before_the_handler_runs_on_a_tier0_auto_allow(
    cli_runtime,
) -> None:
    # tier 0 auto-allows with no confirmation prompt at all -- if the
    # describe() line were only printed alongside a confirmation, a tier 0
    # dispatch like this one would leave no visible record of what the
    # model thought it heard.
    classification = Classification(
        action_id="open_new_desktop", raw_params={}, reason=Reason.MATCHED
    )
    buf = io.StringIO()
    seen: dict[str, str] = {}

    def fake_send_input(*args, **kwargs):
        # Captured at the moment the handler fires -- proves the describe()
        # line was already on stdout BEFORE dispatch, not merely that it
        # appears somewhere in the final output.
        seen["stdout_at_dispatch_time"] = buf.getvalue()
        return CHORD_LENGTH

    with patch("classifier.classify.Classifier", _stub_classifier(classification)), \
            patch.object(desktops, "_SendInput", side_effect=fake_send_input) as send_input:
        with redirect_stdout(buf):
            code = cli.main(["say", "make a new desktop"])

    assert code == OK
    send_input.assert_called_once()
    assert "open_new_desktop" in seen["stdout_at_dispatch_time"]


# --- NO_MATCH never dispatches ---------------------------------------------

def test_no_match_never_reaches_the_engine(cli_runtime, monkeypatch) -> None:
    engine, _, _ = cli_runtime
    spy = MagicMock(side_effect=engine.execute)
    monkeypatch.setattr(engine, "execute", spy)

    classification = Classification(
        action_id=NO_MATCH, reason=Reason.NO_ACTION_MATCHED, detail="mystery input"
    )
    with patch("classifier.classify.Classifier", _stub_classifier(classification)):
        code, out, err = run("say", "asdkjhasdkjh")

    assert code == COMPREHENSION
    spy.assert_not_called()
    assert "no action matched" in out
    assert "mystery input" in out


# --- exit 5 vs exit 6, across all four NO_MATCH reasons --------------------

@pytest.mark.parametrize(
    "reason, expected_code",
    [
        (Reason.NO_ACTION_MATCHED, COMPREHENSION),
        (Reason.PARAM_UNDETERMINED, COMPREHENSION),
        (Reason.CLASSIFIER_UNAVAILABLE, INFRASTRUCTURE),
        (Reason.REGISTRY_ERROR, INFRASTRUCTURE),
    ],
)
def test_no_match_reasons_map_to_distinct_exit_codes(
    cli_runtime, monkeypatch, reason, expected_code
) -> None:
    engine, _, _ = cli_runtime
    spy = MagicMock(side_effect=engine.execute)
    monkeypatch.setattr(engine, "execute", spy)

    classification = Classification(action_id=NO_MATCH, reason=reason, detail="x")
    with patch("classifier.classify.Classifier", _stub_classifier(classification)):
        code, _, _ = run("say", "whatever")

    assert code == expected_code
    spy.assert_not_called()


# --- --dry-run ---------------------------------------------------------------

def test_dry_run_never_touches_the_engine_and_exits_zero(monkeypatch) -> None:
    def boom(*args, **kwargs):
        raise AssertionError("--dry-run must never construct or call the engine")

    monkeypatch.setattr(cli, "_runtime", boom)

    classification = Classification(
        action_id="open_new_desktop", raw_params={}, reason=Reason.MATCHED
    )
    with patch("classifier.classify.Classifier", _stub_classifier(classification)):
        code, out, _ = run("say", "make a new desktop", "--dry-run")

    assert code == OK
    assert "open_new_desktop" in out
    assert "nothing" in out.lower() and "dispatch" in out.lower()


def test_dry_run_on_a_no_match_still_neither_touches_the_engine_nor_errors(
    monkeypatch,
) -> None:
    def boom(*args, **kwargs):
        raise AssertionError("--dry-run must never construct or call the engine")

    monkeypatch.setattr(cli, "_runtime", boom)

    classification = Classification(
        action_id=NO_MATCH, reason=Reason.CLASSIFIER_UNAVAILABLE, detail="connection refused"
    )
    with patch("classifier.classify.Classifier", _stub_classifier(classification)):
        code, out, _ = run("say", "anything", "--dry-run")

    assert code == OK
    assert "classifier unavailable" in out


# --- an id the classifier invented is the ENGINE's problem, not the CLI's --

def test_action_id_absent_from_the_registry_is_rejected_by_the_engine(
    cli_runtime,
) -> None:
    classification = Classification(
        action_id="not_a_real_action", raw_params={}, reason=Reason.MATCHED
    )
    with patch("classifier.classify.Classifier", _stub_classifier(classification)):
        code, _, err = run("say", "do the thing")

    # UNKNOWN_ACTION, from `PolicyEngine._resolve` -- the CLI performs no id
    # lookup of its own before calling `engine.execute` in `_say`.
    assert code == REJECTED
    assert "not_a_real_action" in err
