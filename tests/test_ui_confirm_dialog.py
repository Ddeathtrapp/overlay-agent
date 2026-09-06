"""ui.confirm_dialog: DesktopConfirmer never opens a real window here.

Every test below replaces the module-level `tkinter` name inside
`ui.confirm_dialog` with a small scriptable fake (see `_make_fake_tkinter`)
so the suite never creates a real Tk root and never blocks in a real
`mainloop()`. `FakeRoot.mainloop_hook` stands in for "the user did something
while the dialog was open" -- each test sets it to simulate exactly one
interaction (close the window, press Escape, type a value, click a button)
and DesktopConfirmer.ask() runs to completion synchronously.

Contract under test, from src/policy/confirm.py and the Phase 4 spec:
  * timeout, window close, and Escape are all `approved=False`
  * a Tk initialisation failure is `approved=False` with nothing raised
  * the tier-2 Allow button is disabled until the typed entry exactly
    (case-sensitively) equals `prompt.challenge`
  * no "always allow" checkbox is constructed when `prompt.allow_remember`
    is False
  * the returned `ConfirmationReply` carries real `bool`s, never truthy
    stand-ins
"""
from __future__ import annotations

import types

from policy.confirm import ConfirmationReply, build_prompt

import ui.confirm_dialog as confirm_dialog
from ui.confirm_dialog import DesktopConfirmer


# --------------------------------------------------------------------------
# Fake tkinter -- just enough surface for confirm_dialog._build_and_run
# --------------------------------------------------------------------------


class _FakeVar:
    def __init__(self, value=None) -> None:
        self._value = value
        self._traces: list = []

    def get(self):
        return self._value

    def set(self, value) -> None:
        self._value = value
        for callback in list(self._traces):
            callback("name", "index", "write")

    def trace_add(self, mode, callback) -> None:
        self._traces.append(callback)


class _FakeStringVar(_FakeVar):
    def __init__(self, value: str = "") -> None:
        super().__init__(value)


class _FakeBooleanVar(_FakeVar):
    def __init__(self, value: bool = False) -> None:
        super().__init__(bool(value))


class _FakeWidget:
    instances: list = []  # overridden per-subclass, reset per test

    def __init__(self, master=None, **kwargs) -> None:
        self.master = master
        self.kwargs = dict(kwargs)
        type(self).instances.append(self)

    def pack(self, **kwargs) -> None:
        pass

    def grid(self, **kwargs) -> None:
        pass

    def config(self, **kwargs) -> None:
        self.kwargs.update(kwargs)

    configure = config

    @property
    def state(self):
        return self.kwargs.get("state")

    def focus_set(self) -> None:
        _FakeRoot.active._focused = self

    def invoke(self) -> None:
        command = self.kwargs.get("command")
        if command is not None:
            command()


class _FakeFrame(_FakeWidget):
    instances: list = []


class _FakeLabel(_FakeWidget):
    instances: list = []


class _FakeButton(_FakeWidget):
    instances: list = []


class _FakeCheckbutton(_FakeWidget):
    instances: list = []


class _FakeEntry(_FakeWidget):
    instances: list = []

    def get(self) -> str:
        var = self.kwargs.get("textvariable")
        return var.get() if var is not None else ""


class _FakeRoot:
    active: "_FakeRoot | None" = None
    mainloop_hook = None  # set per test; called once from mainloop()

    def __init__(self, *args, **kwargs) -> None:
        self.protocols: dict = {}
        self.bindings: dict = {}
        self.after_calls: list = []
        self._after_seq = 0
        self.destroyed = False
        self._focused = None
        _FakeRoot.active = self

    # -- window chrome, all no-ops -----------------------------------------
    def title(self, *a, **k) -> None: pass
    def resizable(self, *a, **k) -> None: pass
    def attributes(self, *a, **k) -> None: pass
    def geometry(self, *a, **k) -> None: pass
    def deiconify(self) -> None: pass
    def lift(self) -> None: pass
    def focus_force(self) -> None: pass
    def update_idletasks(self) -> None: pass
    def winfo_reqwidth(self) -> int: return 400
    def winfo_reqheight(self) -> int: return 300
    def winfo_screenwidth(self) -> int: return 1920
    def winfo_screenheight(self) -> int: return 1080

    def protocol(self, name, callback) -> None:
        self.protocols[name] = callback

    def bind(self, sequence, callback) -> None:
        self.bindings[sequence] = callback

    def after(self, ms, callback):
        self._after_seq += 1
        cid = self._after_seq
        self.after_calls.append((ms, callback, cid))
        return cid

    def after_cancel(self, cid) -> None:
        self.after_calls = [c for c in self.after_calls if c[2] != cid]

    def focus_get(self):
        return self._focused

    def mainloop(self) -> None:
        if _FakeRoot.mainloop_hook is not None:
            _FakeRoot.mainloop_hook(self)

    def destroy(self) -> None:
        self.destroyed = True


def _make_fake_tkinter() -> types.SimpleNamespace:
    """A fresh fake `tkinter` module. Resets every fake widget's instance
    registry so tests never see widgets left over from a previous test."""
    for cls in (_FakeFrame, _FakeLabel, _FakeButton, _FakeCheckbutton, _FakeEntry):
        cls.instances = []
    _FakeRoot.active = None
    _FakeRoot.mainloop_hook = None
    return types.SimpleNamespace(
        Tk=_FakeRoot,
        Frame=_FakeFrame,
        Label=_FakeLabel,
        Button=_FakeButton,
        Checkbutton=_FakeCheckbutton,
        Entry=_FakeEntry,
        StringVar=_FakeStringVar,
        BooleanVar=_FakeBooleanVar,
        DISABLED="disabled",
        NORMAL="normal",
    )


def _install_fake_tkinter(monkeypatch) -> types.SimpleNamespace:
    fake = _make_fake_tkinter()
    monkeypatch.setattr(confirm_dialog, "tkinter", fake)
    return fake


def _button(fake, text: str):
    matches = [b for b in fake.Button.instances if b.kwargs.get("text") == text]
    assert len(matches) == 1, f"expected exactly one {text!r} button, found {len(matches)}"
    return matches[0]


def _tier0_prompt(timeout_seconds: float = 30.0, source_trusted: bool = True):
    return build_prompt(
        action_id="open_application",
        description="Opens an application window.",
        params={"name": "notepad"},
        tier=0,
        source_label="desktop",
        source_trusted=source_trusted,
        timeout_seconds=timeout_seconds,
    )


def _tier2_prompt(timeout_seconds: float = 30.0):
    return build_prompt(
        action_id="shutdown_pc",
        description="Shuts the computer down. Cannot be undone.",
        params={},
        tier=2,
        source_label="desktop",
        source_trusted=True,
        timeout_seconds=timeout_seconds,
    )


# --------------------------------------------------------------------------
# Timeout, close, Escape -- all denials
# --------------------------------------------------------------------------


def test_timeout_denies(monkeypatch) -> None:
    _install_fake_tkinter(monkeypatch)
    # `_dialog_deadline_seconds` floors at zero once timeout_seconds is
    # below the 1s close margin, so the deadline is effectively "now" --
    # by the time the synchronous first `tick()` call re-reads the
    # monotonic clock, real time has moved forward and `remaining <= 0`
    # fires without needing to fake the clock or sleep.
    prompt = _tier0_prompt(timeout_seconds=0.01)

    reply = DesktopConfirmer().ask(prompt)

    assert reply.approved is False


def test_window_close_denies(monkeypatch) -> None:
    _install_fake_tkinter(monkeypatch)
    _FakeRoot.mainloop_hook = lambda root: root.protocols["WM_DELETE_WINDOW"]()
    prompt = _tier0_prompt()

    reply = DesktopConfirmer().ask(prompt)

    assert reply.approved is False


def test_escape_denies(monkeypatch) -> None:
    _install_fake_tkinter(monkeypatch)
    _FakeRoot.mainloop_hook = lambda root: root.bindings["<Escape>"]()
    prompt = _tier0_prompt()

    reply = DesktopConfirmer().ask(prompt)

    assert reply.approved is False


# --------------------------------------------------------------------------
# Tk cannot initialise at all
# --------------------------------------------------------------------------


def test_tkinter_init_failure_denies_without_raising(monkeypatch) -> None:
    def _raise_no_display(self):
        raise RuntimeError("no display")

    monkeypatch.setattr(DesktopConfirmer, "_create_root", _raise_no_display)
    prompt = _tier0_prompt()

    # The test itself is the "no exception escapes" assertion: if `ask()`
    # let this propagate, the test would error rather than reach the
    # assertions below.
    reply = DesktopConfirmer().ask(prompt)

    assert reply.approved is False


# --------------------------------------------------------------------------
# Tier 2: Allow disabled until the typed text exactly matches the challenge
# --------------------------------------------------------------------------


def test_tier_two_allow_disabled_until_exact_match(monkeypatch) -> None:
    fake = _install_fake_tkinter(monkeypatch)
    prompt = _tier2_prompt()
    assert prompt.challenge == "shutdown_pc"

    seen_states: list = []

    def hook(root) -> None:
        entry = fake.Entry.instances[0]
        entry_var = entry.kwargs["textvariable"]
        allow = _button(fake, "Allow")

        # Never typed anything: disabled by construction.
        seen_states.append(allow.state)

        entry_var.set("shutdown_pc")
        seen_states.append(allow.state)

        # Deny to end the dialog cleanly.
        _button(fake, "Deny").invoke()

    _FakeRoot.mainloop_hook = hook

    reply = DesktopConfirmer().ask(prompt)

    assert seen_states[0] == fake.DISABLED
    assert seen_states[1] == fake.NORMAL
    assert reply.approved is False


def test_tier_two_allow_disabled_on_case_mismatch(monkeypatch) -> None:
    fake = _install_fake_tkinter(monkeypatch)
    prompt = _tier2_prompt()

    def hook(root) -> None:
        entry = fake.Entry.instances[0]
        entry_var = entry.kwargs["textvariable"]
        allow = _button(fake, "Allow")

        # Case mismatch: verify() folds nothing, so the button must stay
        # disabled even though the text is otherwise correct.
        entry_var.set("SHUTDOWN_PC")
        assert allow.state == fake.DISABLED

        entry_var.set("Shutdown_Pc")
        assert allow.state == fake.DISABLED

        # Exact match now enables it...
        entry_var.set("shutdown_pc")
        assert allow.state == fake.NORMAL

        # ...and drifting back off the exact match disables it again.
        entry_var.set("shutdown_pc ")
        assert allow.state == fake.DISABLED

        _button(fake, "Deny").invoke()

    _FakeRoot.mainloop_hook = hook

    reply = DesktopConfirmer().ask(prompt)
    assert reply.approved is False


def test_tier_two_allow_click_reports_typed_value(monkeypatch) -> None:
    fake = _install_fake_tkinter(monkeypatch)
    prompt = _tier2_prompt()

    def hook(root) -> None:
        entry = fake.Entry.instances[0]
        entry_var = entry.kwargs["textvariable"]
        entry_var.set("shutdown_pc")
        _button(fake, "Allow").invoke()

    _FakeRoot.mainloop_hook = hook

    reply = DesktopConfirmer().ask(prompt)

    assert reply.approved is True
    assert reply.typed == "shutdown_pc"
    # Tier 2 never offers "always allow" -- build_prompt forces
    # allow_remember False, so the dialog never even builds the checkbox.
    assert reply.remember is False


# --------------------------------------------------------------------------
# "Always allow" checkbox: only when allow_remember is True
# --------------------------------------------------------------------------


def test_no_remember_checkbox_when_allow_remember_false(monkeypatch) -> None:
    fake = _install_fake_tkinter(monkeypatch)
    prompt = _tier2_prompt()
    assert prompt.allow_remember is False
    _FakeRoot.mainloop_hook = lambda root: root.protocols["WM_DELETE_WINDOW"]()

    DesktopConfirmer().ask(prompt)

    assert fake.Checkbutton.instances == []


def test_remember_checkbox_present_when_allow_remember_true(monkeypatch) -> None:
    fake = _install_fake_tkinter(monkeypatch)
    prompt = _tier0_prompt(source_trusted=True)
    assert prompt.allow_remember is True
    _FakeRoot.mainloop_hook = lambda root: root.protocols["WM_DELETE_WINDOW"]()

    DesktopConfirmer().ask(prompt)

    assert len(fake.Checkbutton.instances) == 1


# --------------------------------------------------------------------------
# Returned reply carries real bools
# --------------------------------------------------------------------------


def test_allow_reply_has_real_bools(monkeypatch) -> None:
    fake = _install_fake_tkinter(monkeypatch)
    prompt = _tier0_prompt(source_trusted=True)

    def hook(root) -> None:
        checkbox = fake.Checkbutton.instances[0]
        remember_var = checkbox.kwargs["variable"]
        remember_var.set(True)
        _button(fake, "Allow").invoke()

    _FakeRoot.mainloop_hook = hook

    reply = DesktopConfirmer().ask(prompt)

    assert reply.approved is True
    assert reply.remember is True
    assert isinstance(reply.approved, bool)
    assert isinstance(reply.remember, bool)
    # Constructing a ConfirmationReply raises TypeError on non-bool
    # approved/remember -- ask() already built one, but pin it explicitly
    # so this test fails loudly if DesktopConfirmer ever starts handing
    # back a truthy BooleanVar.get() int instead of a real bool.
    ConfirmationReply(approved=reply.approved, typed=reply.typed, remember=reply.remember)


def test_deny_reply_has_real_bools(monkeypatch) -> None:
    fake = _install_fake_tkinter(monkeypatch)
    prompt = _tier0_prompt()
    _FakeRoot.mainloop_hook = lambda root: _button(fake, "Deny").invoke()

    reply = DesktopConfirmer().ask(prompt)

    assert reply.approved is False
    assert isinstance(reply.approved, bool)
    assert isinstance(reply.remember, bool)
    ConfirmationReply(approved=reply.approved, typed=reply.typed, remember=reply.remember)
