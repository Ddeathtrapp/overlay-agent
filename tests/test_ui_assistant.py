"""ui.assistant: hotkey + input box, wired through PolicyEngine.execute.

No test here opens a real window, registers a real hotkey, or talks to a
live model:

  * `InputBox` tests replace the module-level `tkinter` name inside
    `ui.assistant` with a small scriptable fake -- the same technique
    `tests/test_ui_confirm_dialog.py` uses for `ui.confirm_dialog` -- so
    `InputBox.run()` never creates a real Tk root or blocks in a real
    `mainloop()`.
  * `classify` is always a plain injected callable. `_handle_hotkey`/`run`
    accept one, so nothing here needs to patch `classifier.classify.Classifier`
    or reach Ollama.
  * `run()`'s `register_hotkey`, `message_loop`, and `unregister_hotkey`
    parameters are always stubbed -- nothing here calls the real
    `RegisterHotKey`/`GetMessageW`/`UnregisterHotKey`.

Every real `PolicyEngine` goes through `_helpers.build_engine`
(tmp_path-scoped store/audit), same convention as
`tests/test_dispatch_say.py`. Tests that only need to assert
`engine.execute` was or was not called use a bare `unittest.mock.MagicMock`
standing in for the engine instead -- that is not one of the names
`tests/test_test_hygiene.py` watches for.
"""
from __future__ import annotations

import types
from unittest.mock import MagicMock, patch

from _helpers import build_engine  # noqa: F401  (path shim: puts src/ on sys.path)

from actions.handlers import desktops
from classifier.classify import NO_MATCH, Classification, Reason
from policy.audit import AuditWriteFailed
from policy.engine import ExecutionResult
from policy.types import ActionRequest, Decision, RejectionCode, Source

import ui.assistant as assistant
from ui.assistant import InputBox, _handle_hotkey, run

CHORD_LENGTH = 6  # Win+Ctrl+D: 3 key-down + 3 key-up, see test_handlers.py


# --------------------------------------------------------------------------
# Fake tkinter -- just enough surface for InputBox._build_and_run
# --------------------------------------------------------------------------


class _FakeStringVar:
    def __init__(self, value: str = "") -> None:
        self._value = value

    def get(self) -> str:
        return self._value

    def set(self, value: str) -> None:
        self._value = value


class _FakeWidget:
    def __init__(self, master=None, **kwargs) -> None:
        self.master = master
        self.kwargs = dict(kwargs)

    def pack(self, **kwargs) -> None:
        pass

    def config(self, **kwargs) -> None:
        self.kwargs.update(kwargs)

    configure = config

    def focus_set(self) -> None:
        pass


class _FakeFrame(_FakeWidget):
    pass


class _FakeLabel(_FakeWidget):
    pass


class _FakeEntry(_FakeWidget):
    instances: list = []  # reset per test, see _make_fake_tkinter

    def __init__(self, master=None, **kwargs) -> None:
        super().__init__(master, **kwargs)
        _FakeEntry.instances.append(self)

    def get(self) -> str:
        var = self.kwargs.get("textvariable")
        return var.get() if var is not None else ""


class _FakeRoot:
    mainloop_hook = None  # set per test; called once from mainloop()

    def __init__(self, *args, **kwargs) -> None:
        self.protocols: dict = {}
        self.bindings: dict = {}
        self.destroyed = False

    # -- window chrome, all no-ops -----------------------------------------
    def title(self, *a, **k) -> None: pass
    def resizable(self, *a, **k) -> None: pass
    def attributes(self, *a, **k) -> None: pass
    def geometry(self, *a, **k) -> None: pass
    def deiconify(self) -> None: pass
    def lift(self) -> None: pass
    def focus_force(self) -> None: pass
    def update_idletasks(self) -> None: pass
    def update(self) -> None: pass
    def winfo_reqwidth(self) -> int: return 300
    def winfo_reqheight(self) -> int: return 80
    def winfo_screenwidth(self) -> int: return 1920
    def winfo_screenheight(self) -> int: return 1080

    def protocol(self, name, callback) -> None:
        self.protocols[name] = callback

    def bind(self, sequence, callback) -> None:
        self.bindings[sequence] = callback

    def mainloop(self) -> None:
        if _FakeRoot.mainloop_hook is not None:
            _FakeRoot.mainloop_hook(self)

    def destroy(self) -> None:
        self.destroyed = True


def _make_fake_tkinter() -> types.SimpleNamespace:
    """A fresh fake `tkinter` module, resetting per-test widget state the
    same way `test_ui_confirm_dialog.py`'s `_make_fake_tkinter` does."""
    _FakeEntry.instances = []
    _FakeRoot.mainloop_hook = None
    return types.SimpleNamespace(
        Tk=_FakeRoot,
        Frame=_FakeFrame,
        Label=_FakeLabel,
        Entry=_FakeEntry,
        StringVar=_FakeStringVar,
        DISABLED="disabled",
        NORMAL="normal",
    )


def _install_fake_tkinter(monkeypatch) -> types.SimpleNamespace:
    fake = _make_fake_tkinter()
    monkeypatch.setattr(assistant, "tkinter", fake)
    return fake


def _submit(text: str) -> None:
    """Script the fake root's one mainloop pass: type `text`, press Enter."""

    def hook(root: _FakeRoot) -> None:
        entry = _FakeEntry.instances[0]
        entry_var = entry.kwargs["textvariable"]
        entry_var.set(text)
        root.bindings["<Return>"]()

    _FakeRoot.mainloop_hook = hook


def _press_escape() -> None:
    _FakeRoot.mainloop_hook = lambda root: root.bindings["<Escape>"]()


def _stub_input_box(text: str):
    """A `run()`-compatible input box double that skips tkinter entirely:
    it hands `text` straight to whatever `classify` callable it is given,
    exactly like a real `InputBox` would after a real Enter press. Used to
    test `_handle_hotkey`/`run` wiring without re-driving the fake-tkinter
    machinery for every dispatch test."""

    class _Stub:
        def run(self, classify):
            classification = classify(text)
            return assistant._InputOutcome(utterance=text, classification=classification)

    return _Stub


# --------------------------------------------------------------------------
# InputBox: Escape / empty submission never call classify
# --------------------------------------------------------------------------


def test_escape_cancels_without_calling_classify(monkeypatch) -> None:
    _install_fake_tkinter(monkeypatch)
    _press_escape()
    classify_calls: list[str] = []

    outcome = InputBox().run(lambda text: classify_calls.append(text))

    assert outcome.utterance is None
    assert classify_calls == []


def test_window_close_cancels_without_calling_classify(monkeypatch) -> None:
    _install_fake_tkinter(monkeypatch)
    _FakeRoot.mainloop_hook = lambda root: root.protocols["WM_DELETE_WINDOW"]()
    classify_calls: list[str] = []

    outcome = InputBox().run(lambda text: classify_calls.append(text))

    assert outcome.utterance is None
    assert classify_calls == []


def test_empty_submission_does_nothing(monkeypatch) -> None:
    _install_fake_tkinter(monkeypatch)
    destroyed_immediately_after_return: list[bool] = []

    def hook(root: _FakeRoot) -> None:
        # entry_var defaults to "" -- nothing was typed.
        root.bindings["<Return>"]()
        # If the empty submission had dispatched, the root would already
        # be destroyed by the time this line runs.
        destroyed_immediately_after_return.append(root.destroyed)

    _FakeRoot.mainloop_hook = hook
    classify_calls: list[str] = []

    outcome = InputBox().run(lambda text: classify_calls.append(text))

    assert outcome.utterance is None
    assert classify_calls == []
    assert destroyed_immediately_after_return == [False]


def test_submit_calls_classify_with_typed_text_and_returns_its_result(monkeypatch) -> None:
    _install_fake_tkinter(monkeypatch)
    _submit("open notepad")
    classification = Classification(
        action_id="open_application", raw_params={"app": "notepad"}, reason=Reason.MATCHED
    )

    outcome = InputBox().run(lambda text: classification if text == "open notepad" else None)

    assert outcome.utterance == "open notepad"
    assert outcome.classification is classification


# --------------------------------------------------------------------------
# _handle_hotkey: a matched classification reaches the engine, correctly
# stamped (source=Source.DESKTOP, utterance=the typed text) -- assert the
# kwarg VALUES, not merely that execute was called.
# --------------------------------------------------------------------------


def test_submitted_utterance_reaches_engine_with_desktop_source_and_utterance(
    tmp_path,
) -> None:
    utterance = "make a new desktop"
    classification = Classification(
        action_id="open_new_desktop", raw_params={}, reason=Reason.MATCHED
    )
    engine, _, _ = build_engine(tmp_path)
    spy = MagicMock(side_effect=engine.execute)
    engine.execute = spy

    def classify(text: str) -> Classification:
        assert text == utterance
        return classification

    with patch.object(desktops, "_SendInput", side_effect=lambda *a, **k: CHORD_LENGTH):
        _handle_hotkey(
            engine,
            classify,
            input_box_factory=_stub_input_box(utterance),
            report=lambda *_: None,
        )

    spy.assert_called_once_with(
        "open_new_desktop",
        {},
        source=Source.DESKTOP,
        utterance=utterance,
    )
    args, kwargs = spy.call_args
    assert kwargs["source"] is Source.DESKTOP
    assert kwargs["utterance"] == utterance


def test_escape_never_reaches_the_engine() -> None:
    engine = MagicMock()

    class _CancelledBox:
        def run(self, classify):
            return assistant._InputOutcome(utterance=None, classification=None)

    _handle_hotkey(
        engine,
        classify=lambda text: (_ for _ in ()).throw(AssertionError("classify must not run")),
        input_box_factory=_CancelledBox,
        report=lambda *_: None,
    )

    engine.execute.assert_not_called()


# --------------------------------------------------------------------------
# NO_MATCH never reaches the engine, and the message shown differs between
# a comprehension failure and an infrastructure failure.
# --------------------------------------------------------------------------


def test_no_match_never_reaches_the_engine() -> None:
    engine = MagicMock()
    classification = Classification(
        action_id=NO_MATCH, reason=Reason.NO_ACTION_MATCHED, detail="mystery input"
    )
    messages: list[str] = []

    _handle_hotkey(
        engine,
        classify=lambda text: classification,
        input_box_factory=_stub_input_box("asdkjhasdkjh"),
        report=messages.append,
    )

    engine.execute.assert_not_called()
    assert any("didn't understand" in m for m in messages)


def test_comprehension_and_infrastructure_failures_are_surfaced_differently() -> None:
    def messages_for(reason: Reason) -> list[str]:
        engine = MagicMock()
        classification = Classification(action_id=NO_MATCH, reason=reason, detail="x")
        seen: list[str] = []
        _handle_hotkey(
            engine,
            classify=lambda text: classification,
            input_box_factory=_stub_input_box("whatever"),
            report=seen.append,
        )
        engine.execute.assert_not_called()
        return seen

    comprehension = messages_for(Reason.NO_ACTION_MATCHED)
    infrastructure = messages_for(Reason.CLASSIFIER_UNAVAILABLE)

    assert any("didn't understand" in m for m in comprehension)
    assert not any("didn't understand" in m for m in infrastructure)
    assert any("isn't running" in m for m in infrastructure)
    assert not any("isn't running" in m for m in comprehension)


def test_all_four_no_match_reasons_split_the_same_way_as_cli_exit_codes() -> None:
    # Mirrors dispatch/cli.py:191's _CLASSIFICATION_EXIT_CODES split
    # (NO_ACTION_MATCHED/PARAM_UNDETERMINED -> comprehension;
    # CLASSIFIER_UNAVAILABLE/REGISTRY_ERROR -> infrastructure).
    comprehension_reasons = (Reason.NO_ACTION_MATCHED, Reason.PARAM_UNDETERMINED)
    infrastructure_reasons = (Reason.CLASSIFIER_UNAVAILABLE, Reason.REGISTRY_ERROR)

    for reason in comprehension_reasons:
        message = assistant._classification_message(
            Classification(action_id=NO_MATCH, reason=reason)
        )
        assert "didn't understand" in message
        assert "isn't running" not in message

    for reason in infrastructure_reasons:
        message = assistant._classification_message(
            Classification(action_id=NO_MATCH, reason=reason)
        )
        assert "isn't running" in message
        assert "didn't understand" not in message


# --------------------------------------------------------------------------
# Hotkey registration failure: exit non-zero, no fallback, no engine built.
# --------------------------------------------------------------------------


def test_hotkey_registration_failure_exits_nonzero_and_builds_nothing(capsys) -> None:
    engine_factory = MagicMock()
    message_loop = MagicMock()
    unregister_hotkey = MagicMock()

    code = run(
        engine_factory=engine_factory,
        message_loop=message_loop,
        register_hotkey=lambda: False,
        unregister_hotkey=unregister_hotkey,
        classify=lambda text: Classification(action_id=NO_MATCH),
    )

    assert code != 0
    engine_factory.assert_not_called()
    message_loop.assert_not_called()
    unregister_hotkey.assert_not_called()
    captured = capsys.readouterr()
    assert assistant.HOTKEY_LABEL in captured.err


# --------------------------------------------------------------------------
# The engine is constructed ONCE, not per hotkey press.
# --------------------------------------------------------------------------


def test_engine_constructed_once_across_two_hotkey_presses(tmp_path) -> None:
    built: list[object] = []

    def engine_factory():
        engine, _, _ = build_engine(tmp_path)
        built.append(engine)
        return engine

    def fake_message_loop(on_hotkey) -> None:
        on_hotkey()
        on_hotkey()

    classification = Classification(action_id=NO_MATCH, reason=Reason.NO_ACTION_MATCHED)

    code = run(
        engine_factory=engine_factory,
        message_loop=fake_message_loop,
        register_hotkey=lambda: True,
        unregister_hotkey=lambda: None,
        classify=lambda text: classification,
        input_box_factory=_stub_input_box("hi"),
        report=lambda *_: None,
    )

    assert code == 0
    assert len(built) == 1


# --------------------------------------------------------------------------
# _default_classify lazily imports Classifier, same discipline as
# dispatch.cli._say (patch target is classifier.classify.Classifier, not
# ui.assistant.Classifier, which does not exist until the function runs).
# --------------------------------------------------------------------------


def test_default_classify_uses_the_real_registry_and_never_imports_eagerly() -> None:
    # `Classifier` is imported inside `_default_classify`, not at module
    # scope -- so importing `ui.assistant` never binds the name at all.
    assert not hasattr(assistant, "Classifier")

    class _Stub:
        def __init__(self, registry, client=None) -> None:
            self.registry = registry

        def classify(self, utterance, screen_context=None) -> Classification:
            return Classification(action_id=NO_MATCH, reason=Reason.NO_ACTION_MATCHED, detail=utterance)

    with patch("classifier.classify.Classifier", _Stub):
        result = assistant._default_classify("open notepad")

    assert result.detail == "open notepad"


# --------------------------------------------------------------------------
# KI-3: `engine.execute`'s `ExecutionResult` is no longer discarded --
# every distinct outcome shape must produce a distinguishable, non-empty
# message through `report`. The engine is always a stub here (a bare
# `MagicMock` whose `.execute` returns a canned `ExecutionResult`) -- no
# real `PolicyEngine`, no live model, no window. Record everything into a
# list OUTSIDE the callback and assert after `_handle_hotkey` returns --
# no `assert` inside `report` itself, matching the `DesktopConfirmer.ask`
# lesson noted in the module docstring above.
# --------------------------------------------------------------------------

_MATCHED = Classification(action_id="shutdown", raw_params={}, reason=Reason.MATCHED)


def _messages_for_result(result: ExecutionResult) -> list[str]:
    engine = MagicMock()
    engine.execute = MagicMock(return_value=result)
    seen: list[str] = []

    _handle_hotkey(
        engine,
        classify=lambda text: _MATCHED,
        input_box_factory=_stub_input_box("shut down"),
        report=seen.append,
    )

    engine.execute.assert_called_once()
    return seen


def _last_message_for_result(result: ExecutionResult) -> str:
    messages = _messages_for_result(result)
    # `report(classification.describe())` fires first, then the execution
    # message -- the one this section is about is always the last one.
    return messages[-1]


def _rejected_result(code: RejectionCode, reason: str) -> ExecutionResult:
    request = ActionRequest(action_id="shutdown", raw_params={}, source=Source.DESKTOP)
    return ExecutionResult(Decision.reject(request, code, reason))


def test_successful_execution_is_reported() -> None:
    request = ActionRequest(action_id="shutdown", raw_params={}, source=Source.DESKTOP)
    result = ExecutionResult(Decision.auto_allow(request, "tier 0"), executed=True)

    message = _last_message_for_result(result)

    assert result.ok
    assert "shutdown" in message


def test_allowed_but_handler_raised_is_reported_and_distinct_from_success() -> None:
    request = ActionRequest(action_id="shutdown", raw_params={}, source=Source.DESKTOP)
    success = ExecutionResult(Decision.auto_allow(request, "tier 0"), executed=True)
    handler_error = ExecutionResult(
        Decision.auto_allow(request, "tier 0"),
        executed=True,
        error="RuntimeError('handler exploded')",
    )

    success_message = _last_message_for_result(success)
    error_message = _last_message_for_result(handler_error)

    assert not handler_error.ok
    assert error_message != success_message
    assert "handler exploded" in error_message


def test_not_confirmed_rate_limited_and_confirmation_pending_are_distinguishable() -> None:
    """The four rejection situations named in the task (declined, blocked
    by an open confirmation, rate limited with a retry duration, and
    malformed) must not collapse into one generic "rejected" string."""
    not_confirmed = _rejected_result(
        RejectionCode.NOT_CONFIRMED, "declined or not confirmed"
    )
    rate_limited = _rejected_result(
        RejectionCode.RATE_LIMITED,
        "shutdown is rate limited at 1 per 600s; retry in 42s",
    )
    confirmation_pending = _rejected_result(
        RejectionCode.CONFIRMATION_PENDING,
        "a confirmation is already awaiting an answer",
    )
    bad_arity = _rejected_result(
        RejectionCode.BAD_ARITY, "shutdown takes [], got ['bogus']"
    )

    messages = {
        "not_confirmed": _last_message_for_result(not_confirmed),
        "rate_limited": _last_message_for_result(rate_limited),
        "confirmation_pending": _last_message_for_result(confirmation_pending),
        "bad_arity": _last_message_for_result(bad_arity),
    }

    # Distinguishable: every message differs from every other one --
    # not merely "each is non-empty", which a single shared "rejected"
    # string would also satisfy.
    assert len(set(messages.values())) == len(messages)

    # RATE_LIMITED must surface the actionable retry-after duration
    # (LimitStatus.reason(), policy/limits.py:63-67), not just the label.
    assert "42s" in messages["rate_limited"]

    # NOT_CONFIRMED reads as a decline, not as any of the others.
    assert "declined" in messages["not_confirmed"].lower()
    assert "42s" not in messages["not_confirmed"]

    # CONFIRMATION_PENDING reads as "you weren't asked", not a decline.
    assert "confirmation" in messages["confirmation_pending"].lower()
    assert messages["confirmation_pending"] != messages["not_confirmed"]


def test_every_rejection_code_is_handled_with_an_explicit_message() -> None:
    """The drift guard: iterate the live `RejectionCode` enum, not a
    hardcoded list, so adding an eighth member without updating
    `assistant._REJECTION_MESSAGES` fails this test immediately instead of
    silently rendering as the generic fallback (or, worse, as success)."""
    request = ActionRequest(action_id="shutdown", raw_params={}, source=Source.DESKTOP)

    for code in RejectionCode:
        assert code in assistant._REJECTION_MESSAGES, (
            f"{code!r} has no entry in ui.assistant._REJECTION_MESSAGES -- "
            "KI-3 drift guard tripped"
        )
        decision = Decision.reject(request, code, f"reason text for {code.value}")
        message = assistant._rejection_message(decision)

        assert message, f"{code!r} produced an empty message"
        assert not message.startswith(f"{assistant._UNMAPPED_REJECTION_MESSAGE}:"), (
            f"{code!r} fell through to the closed fallback"
        )
        assert f"reason text for {code.value}" in message


def test_unmapped_rejection_code_falls_back_closed_not_to_success() -> None:
    """A `RejectionCode` absent from `_REJECTION_MESSAGES` (simulated here
    with a real code temporarily deleted from the dict) must still render
    a non-empty, clearly-rejected message -- never blank, never a message
    indistinguishable from success."""
    request = ActionRequest(action_id="shutdown", raw_params={}, source=Source.DESKTOP)
    decision = Decision.reject(request, RejectionCode.NOT_CONFIRMED, "declined")

    original = dict(assistant._REJECTION_MESSAGES)
    del assistant._REJECTION_MESSAGES[RejectionCode.NOT_CONFIRMED]
    try:
        message = assistant._rejection_message(decision)
    finally:
        assistant._REJECTION_MESSAGES.clear()
        assistant._REJECTION_MESSAGES.update(original)

    assert message
    assert message.startswith(f"{assistant._UNMAPPED_REJECTION_MESSAGE}:")
    assert "declined" in message


# --------------------------------------------------------------------------
# KI-8: `AuditWriteFailed` -- raised by the real `PolicyEngine._finalize`
# when the audit write itself fails, deliberately, rather than executing
# unlogged (see `policy.audit.AuditWriteFailed`'s docstring) -- must be
# reported distinctly, not swallowed by the blanket `except Exception` in
# `_handle_hotkey`, and must not stop the hotkey from being serviced again.
# `engine` is a bare `MagicMock` whose `.execute` RAISES rather than
# returns, unlike `_messages_for_result`'s stub above. Same record-outside-
# the-hook discipline as the rest of this file: `seen` is a list defined
# outside `report`, and every assertion happens after `_handle_hotkey`
# returns.
# --------------------------------------------------------------------------


def _audit_write_failed_engine(reason: str) -> MagicMock:
    engine = MagicMock()
    engine.execute = MagicMock(side_effect=AuditWriteFailed(reason))
    return engine


def test_audit_write_failed_names_the_audit_log_and_the_reason() -> None:
    reason = "could not write audit record: [Errno 28] No space left on device"
    engine = _audit_write_failed_engine(reason)
    seen: list[str] = []

    _handle_hotkey(
        engine,
        classify=lambda text: _MATCHED,
        input_box_factory=_stub_input_box("shut down"),
        report=seen.append,
    )

    engine.execute.assert_called_once()
    message = seen[-1]

    # Names the audit log specifically -- not a generic error string.
    assert "audit log" in message.lower()
    # The underlying reason (disk-full vs. permission-denied) must survive
    # -- a message that says "audit log failed" while dropping the cause
    # would pass a weaker check but fails this one.
    assert "[Errno 28] No space left on device" in message


def test_audit_write_failed_is_distinguishable_from_handler_error_and_rejections() -> None:
    reason = "could not write audit record: [Errno 28] No space left on device"
    engine = _audit_write_failed_engine(reason)
    seen: list[str] = []

    _handle_hotkey(
        engine,
        classify=lambda text: _MATCHED,
        input_box_factory=_stub_input_box("shut down"),
        report=seen.append,
    )
    audit_message = seen[-1]

    # Compare against actual messages produced through the same
    # `_handle_hotkey`/`report` path, not against hardcoded strings.
    request = ActionRequest(action_id="shutdown", raw_params={}, source=Source.DESKTOP)
    success_message = _last_message_for_result(
        ExecutionResult(Decision.auto_allow(request, "tier 0"), executed=True)
    )
    handler_error_message = _last_message_for_result(
        ExecutionResult(
            Decision.auto_allow(request, "tier 0"),
            executed=True,
            error="RuntimeError('handler exploded')",
        )
    )
    rejection_message = _last_message_for_result(
        _rejected_result(RejectionCode.NOT_CONFIRMED, "declined or not confirmed")
    )

    assert audit_message != success_message
    assert audit_message != handler_error_message
    assert audit_message != rejection_message
    # Never reads as success.
    assert "done:" not in audit_message
    assert "ran but failed" not in audit_message  # not the handler-error shape

    # Conveys that this blocks every action, not one bad request. `and`,
    # not `or`: the message already begins "blocked:", so an `or` is
    # satisfied by that prefix alone and would still pass if the "every
    # action" framing were dropped -- which is the half that tells the user
    # the assistant is non-functional until they fix the underlying cause.
    assert (
        "every action" in audit_message.lower()
        and "blocked" in audit_message.lower()
    )


def test_audit_write_failed_does_not_stop_the_hotkey_from_being_serviced_again() -> None:
    """The listener must survive: a second press with the same failing
    engine is still serviced (not merely "did not raise once") and still
    reports the same kind of message."""
    reason = "could not write audit record: [Errno 13] Permission denied"
    engine = _audit_write_failed_engine(reason)
    seen: list[str] = []

    for _ in range(2):
        _handle_hotkey(
            engine,
            classify=lambda text: _MATCHED,
            input_box_factory=_stub_input_box("shut down"),
            report=seen.append,
        )

    assert engine.execute.call_count == 2
    audit_messages = [m for m in seen if "audit log" in m.lower()]
    assert len(audit_messages) == 2
    assert "[Errno 13] Permission denied" in audit_messages[0]
    assert "[Errno 13] Permission denied" in audit_messages[1]
