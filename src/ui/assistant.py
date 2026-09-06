"""Hotkey + input box — the desktop entry point for Phase 4.

Run as ``python -m ui.assistant`` from ``src/``. Press the hotkey (default
Ctrl+Alt+Space), type an utterance, press Enter. The utterance is classified
and, if matched, run through the same `policy.engine.PolicyEngine.execute`
call `dispatch.cli._say` uses — see that function's docstring
(`src/dispatch/cli.py`) for the provenance rule this module also follows
(threat-model.md T12): `source=Source.DESKTOP` is always a literal keyword
here, never derived from argv, an environment variable, or the
classification.

Threading — READ BEFORE TOUCHING ANYTHING TK-RELATED
------------------------------------------------------
Exactly one thread ever pumps Win32 messages, and that same thread is the
only one that ever calls `engine.execute`:

  * **The hotkey thread** (whichever thread calls `run()` — the main thread
    for a normal `python -m ui.assistant` invocation) owns the Win32
    message loop (`_win32_message_loop`, `GetMessageW`/`WM_HOTKEY`). It is
    also where `InputBox.run()` creates, uses, and destroys ITS Tk root
    (see `InputBox` docstring), and it is where `engine.execute(...)` is
    called — synchronously, directly inside the `WM_HOTKEY` handler.

  * **`InputBox`'s Tk root** lives entirely within one `InputBox.run()`
    call, on the hotkey thread, and is destroyed (`_safe_destroy`) before
    that call returns — i.e. strictly before `_handle_hotkey` goes on to
    call `engine.execute`. The input box is therefore ALWAYS gone before
    any confirmation dialog could appear, structurally (nothing here can
    call `engine.execute` while the box's root is still alive), not just
    by timing.

  * **The confirmation dialog's Tk root** is `ui.confirm_dialog`'s
    business, not this module's. `PolicyEngine._ask_with_timeout` spawns
    its own daemon thread per confirmation and calls
    `DesktopConfirmer.ask()` there; `ask()` creates/uses/destroys its Tk
    root inside itself, entirely on that daemon thread (see
    `confirm_dialog.py`'s module docstring). This module does not create a
    second thread for that and does not touch Tk from inside
    `engine.execute` — it reuses the mechanism `confirm_dialog.py` already
    built, exactly as instructed. The hotkey thread is simply blocked (in
    `PolicyEngine._ask_with_timeout`'s `thread.join(...)`) for the
    duration, so at no point do two Tk roots exist at once anywhere in the
    process.

  * **Dispatch is synchronous, on purpose.** `_handle_hotkey` calls
    `engine.execute` directly and waits for it (including waiting out any
    confirmation). While that call is in flight the hotkey thread is not
    back at `GetMessageW`, so a second hotkey press arriving during
    classification or a confirmation is not acted on until the loop
    returns to pump messages again — it is not queued and replayed as a
    fresh request. This is deliberate: it mirrors `policy/engine.py` §12.4
    ("no two handlers run at once" — the gate), so the UI layer never lets
    two dispatches race even though the engine's own gate is released
    during phase B (see `engine.py`'s module docstring). It is a
    consequence of the design, not an oversight.

Hotkey
------
`RegisterHotKey(hWnd=NULL, ...)` binds the hotkey to the CALLING THREAD's
message queue, not to a window — there is deliberately no window here (the
overlay, `src/overlay/`, is a separate Phase 7 component; this process has
no HWND of its own). `WM_HOTKEY` messages for it are only delivered while
that thread is pumping messages via `GetMessageW`, which is exactly what
`_win32_message_loop` does for the rest of the process's life.

A global hotkey registered by a non-elevated process will NOT fire while an
elevated (Run as Administrator) window has focus — Windows' UIPI blocks
low-to-high input in that direction. That is a Windows integrity-level
restriction, not a bug in this module, and there is no supported
workaround; do not attempt one here. Run this process elevated if it must
work while an elevated window is focused.

If `RegisterHotKey` fails (almost always: another process already owns the
combination), this prints exactly which combination failed and exits
non-zero. It never silently falls back to a different combination — a
hotkey that quietly becomes a different hotkey is worse than one that
fails loudly (see module-level TRAP note in the task this module was built
against).
"""

from __future__ import annotations

import ctypes
import logging
import sys
import tkinter
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

# Resolve src/ onto sys.path, same shim as dispatch/cli.py, so this module
# works both as `python -m ui.assistant` (run from src/, where this is a
# no-op) and if ever invoked some other way.
_SRC = Path(__file__).resolve().parents[1]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from actions import REGISTRY  # noqa: E402
from policy.audit import AuditLog  # noqa: E402
from policy.engine import PolicyEngine  # noqa: E402
from policy.exceptions import ExceptionStore  # noqa: E402
from policy.types import Source  # noqa: E402

from ui.confirm_dialog import DesktopConfirmer  # noqa: E402

log = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# Hotkey — Ctrl+Alt+Space, a module constant (not user-configurable here)
# ----------------------------------------------------------------------
# ctypes constants, stdlib only — no pip installs (CLAUDE.md).
MOD_ALT = 0x0001
MOD_CONTROL = 0x0002
MOD_NOREPEAT = 0x4000  # one WM_HOTKEY per physical press, not one per repeat
VK_SPACE = 0x20

WM_HOTKEY = 0x0312

HOTKEY_ID = 1  # arbitrary nonzero id, scoped to this thread's queue only
HOTKEY_MODIFIERS = MOD_CONTROL | MOD_ALT | MOD_NOREPEAT
HOTKEY_VK = VK_SPACE
HOTKEY_LABEL = "Ctrl+Alt+Space"  # kept in sync with the two constants above
                                  # by hand -- both are module constants and
                                  # neither is expected to change casually.

# ----------------------------------------------------------------------
# ctypes bindings — argtypes/restype set on every function, as
# actions/handlers/power.py does.
# ----------------------------------------------------------------------
_user32 = ctypes.WinDLL("user32", use_last_error=True)

_RegisterHotKey = _user32.RegisterHotKey
_RegisterHotKey.argtypes = [wintypes.HWND, ctypes.c_int, wintypes.UINT, wintypes.UINT]
_RegisterHotKey.restype = wintypes.BOOL

_UnregisterHotKey = _user32.UnregisterHotKey
_UnregisterHotKey.argtypes = [wintypes.HWND, ctypes.c_int]
_UnregisterHotKey.restype = wintypes.BOOL

_GetMessageW = _user32.GetMessageW
_GetMessageW.argtypes = [
    ctypes.POINTER(wintypes.MSG),
    wintypes.HWND,
    wintypes.UINT,
    wintypes.UINT,
]
_GetMessageW.restype = wintypes.BOOL


def _register_hotkey() -> bool:
    """Register `HOTKEY_ID` on THIS thread's message queue. True on success.

    Never falls back to a different combination on failure — the caller
    (`run`) reports exactly which combination failed and exits non-zero.
    """
    return bool(_RegisterHotKey(None, HOTKEY_ID, HOTKEY_MODIFIERS, HOTKEY_VK))


def _unregister_hotkey() -> None:
    _UnregisterHotKey(None, HOTKEY_ID)


def _win32_message_loop(on_hotkey: Callable[[], None]) -> None:
    """Block, pumping this thread's message queue, until `WM_QUIT`.

    Calls `on_hotkey()` synchronously, ON THIS THREAD, for every
    `WM_HOTKEY` carrying `HOTKEY_ID` — see the module docstring's
    "Threading" section for why that matters. There is no window to
    `TranslateMessage`/`DispatchMessage` to; `WM_HOTKEY` is handled
    directly here instead.
    """
    msg = wintypes.MSG()
    while True:
        ret = _GetMessageW(ctypes.byref(msg), None, 0, 0)
        if ret == 0:  # WM_QUIT
            return
        if ret == -1:
            raise ctypes.WinError(ctypes.get_last_error())
        if msg.message == WM_HOTKEY and msg.wParam == HOTKEY_ID:
            on_hotkey()


# ----------------------------------------------------------------------
# The engine — constructed exactly once, for the process lifetime
# ----------------------------------------------------------------------


def build_default_engine() -> PolicyEngine:
    """The one real `PolicyEngine`, built once and shared for as long as
    this process runs.

    Uses `DesktopConfirmer` (this Phase's tkinter confirmation dialog),
    never `ConsoleConfirmer` — `dispatch.cli._runtime()` builds a
    `ConsoleConfirmer`, which blocks on `input()`; in a GUI process with no
    console attached that hangs forever holding the engine's `_gate`
    (policy/engine.py). See the TRAP note this module was built against.

    Default `ExceptionStore()` / `AuditLog()` paths are correct here, same
    as `dispatch.cli._runtime()`'s bare construction is correct for the
    real CLI: this is a real, long-lived process, not a test. (It is
    exempt from `tests/test_test_hygiene.py`'s AST check because that
    check only scans `tests/`.)

    `run()` calls this exactly once, before entering the message loop, and
    every hotkey press for the rest of the process's life reuses that one
    engine — this is the first long-lived engine in the project, per the
    task this module was built against: the rate limiter's sliding window
    and the §12.4 serial gate only mean something across multiple
    invocations of ONE engine, and `dispatch.cli`'s one-process-per-action
    model could never exercise either (T8).
    """
    return PolicyEngine(
        REGISTRY,
        confirmer=DesktopConfirmer(),
        exceptions=ExceptionStore(),
        audit=AuditLog(),
    )


# ----------------------------------------------------------------------
# Classification — comprehension vs. infrastructure failure
# ----------------------------------------------------------------------
# Mirrors dispatch/cli.py:191's `_CLASSIFICATION_EXIT_CODES` split (5 vs 6)
# as user-facing text instead of an exit code. Duplicated deliberately,
# not imported from `dispatch.cli` -- that dict is a private, CLI-specific
# exit-code table, and this module has no business reaching into another
# module's underscore-prefixed internals for a string. Keep both splits in
# sync with `classifier.classify.Reason` if a new Reason is ever added.

_COMPREHENSION_REASONS = frozenset({"NO_ACTION_MATCHED", "PARAM_UNDETERMINED"})
_INFRASTRUCTURE_REASONS = frozenset({"CLASSIFIER_UNAVAILABLE", "REGISTRY_ERROR"})


def _classification_message(classification: Any) -> str:
    """User-facing text for a NO_MATCH classification.

    Distinguishes "I didn't understand that" (a comprehension failure --
    the model ran and had nothing) from "the classifier isn't running" (an
    infrastructure failure -- the model never got to try), the same split
    `dispatch/cli.py`'s `_CLASSIFICATION_EXIT_CODES` makes for exit codes 5
    vs 6. An unmapped reason name falls to the comprehension message
    rather than raising -- fail toward the more common, less alarming
    case, never toward a crash inside a NO_MATCH handler.
    """
    name = classification.reason.name
    detail = f" ({classification.detail})" if classification.detail else ""
    if name in _INFRASTRUCTURE_REASONS:
        return f"the classifier isn't running{detail}"
    return f"I didn't understand that{detail}"


def _default_classify(utterance: str) -> Any:
    """Classify `utterance` against the real registry via the real Ollama
    classifier.

    `Classifier` is imported HERE, lazily, not at module scope -- same
    reasoning as `dispatch.cli._say`'s lazy import: importing
    `ui.assistant` (which every test in this suite does) must not pay
    Ollama-client import cost, and must keep working with Ollama stopped.
    """
    from classifier.classify import Classifier  # lazy -- see docstring above

    return Classifier(REGISTRY).classify(utterance)


# ----------------------------------------------------------------------
# The input box
# ----------------------------------------------------------------------


def _safe_destroy(root: object) -> None:
    """Best-effort teardown, mirroring `ui.confirm_dialog._safe_destroy`:
    a second `.destroy()` on an already-destroyed real Tk root raises
    `TclError`; swallow it, this always runs in a `finally`."""
    try:
        root.destroy()  # type: ignore[attr-defined]
    except Exception:
        pass


_WINDOW_TITLE = "Say something"
_STATUS_FONT = ("Segoe UI", 10)
_ENTRY_FONT = ("Segoe UI", 13)


@dataclass
class _InputOutcome:
    """What the box produced. `utterance` is None for Escape, a window
    close, or a submission `InputBox` never reached (i.e. every
    cancellation path) -- callers must treat `None` as "never touch the
    engine", not merely "nothing typed"."""

    utterance: str | None = None
    classification: Any = None  # set only when utterance is not None


class InputBox:
    """Small, centred, always-on-top tkinter box for one typed utterance.

    Threading contract: identical in shape to
    `ui.confirm_dialog.DesktopConfirmer` -- the Tk root is created, used,
    and destroyed inside a single `run()` call, on whichever thread calls
    it (the hotkey thread; see the module docstring). No Tk object
    survives past one `run()` call.

    Unlike the overlay (`src/overlay/`, Phase 7, click-through and
    non-focusable by design), this window IS an input surface: it takes
    focus and has a normal, closable window (no `WDA_EXCLUDEFROMCAPTURE`
    concern here -- it is not meant to be invisible, only unobtrusive:
    no taskbar entry, via `-toolwindow`, same technique
    `confirm_dialog.py` uses).

    `run(classify)`:
      * Escape or the window's close button -> returns immediately with
        `utterance=None`. `classify` is never called.
      * Enter on an empty entry -> a no-op: the box stays open, nothing
        happens, `classify` is never called ("empty submission does
        nothing").
      * Enter on non-empty text -> disables the entry, shows a "Thinking…"
        status line, forces a repaint (`update_idletasks()` + `update()`)
        so that label is actually on screen -- classification is not
        instant (roughly 365ms with no parameters, up to ~700ms with one,
        per the two-pass classifier in `classifier/classify.py`), and an
        unpainted window over that gap reads as hung, not busy -- THEN
        calls `classify(text)` synchronously (this blocks the Tk event
        loop; that is the point, since dispatch downstream is
        synchronous too, see the module docstring), then destroys the
        root and returns the typed text plus whatever `classify` returned.
    """

    def run(self, classify: Callable[[str], Any]) -> _InputOutcome:
        root = self._create_root()
        try:
            return self._build_and_run(root, classify)
        finally:
            _safe_destroy(root)

    # -- seam, mirroring confirm_dialog.DesktopConfirmer._create_root ------

    def _create_root(self) -> tkinter.Tk:
        return tkinter.Tk()

    # -- rendering -----------------------------------------------------------

    def _build_and_run(self, root: tkinter.Tk, classify: Callable[[str], Any]) -> _InputOutcome:
        outcome = _InputOutcome()

        root.title(_WINDOW_TITLE)
        root.resizable(False, False)
        try:
            root.attributes("-topmost", True)
        except Exception:
            pass
        try:
            root.attributes("-toolwindow", True)  # no taskbar entry
        except Exception:
            pass

        def cancel(_event: object = None) -> None:
            outcome.utterance = None
            _safe_destroy(root)

        root.protocol("WM_DELETE_WINDOW", cancel)
        root.bind("<Escape>", cancel)

        container = tkinter.Frame(root, padx=16, pady=12)
        container.pack()

        status_label = tkinter.Label(container, text="Type a command", font=_STATUS_FONT)
        status_label.pack(anchor="w")

        entry_var = tkinter.StringVar(value="")
        entry = tkinter.Entry(container, textvariable=entry_var, width=48, font=_ENTRY_FONT)
        entry.pack(anchor="w", pady=(4, 0))

        def submit(_event: object = None) -> None:
            text = entry_var.get().strip()
            if not text:
                return  # empty submission does nothing -- box stays open
            entry.config(state=tkinter.DISABLED)
            status_label.config(text="Thinking…")
            # Force the "Thinking…" label onto screen before the blocking
            # classify() call below -- see the class docstring for why
            # this matters (classify() takes long enough that an unpainted
            # window reads as broken, not busy).
            root.update_idletasks()
            root.update()
            outcome.utterance = text
            outcome.classification = classify(text)
            _safe_destroy(root)

        root.bind("<Return>", submit)

        try:
            root.geometry("")
            root.update_idletasks()
            width = root.winfo_reqwidth()
            height = root.winfo_reqheight()
            screen_w = root.winfo_screenwidth()
            screen_h = root.winfo_screenheight()
            x = max(0, (screen_w - width) // 2)
            y = max(0, (screen_h - height) // 3)
            root.geometry(f"{width}x{height}+{x}+{y}")
        except Exception:
            # Centring is cosmetic -- must not prevent the box from working.
            pass

        try:
            root.deiconify()
        except Exception:
            pass
        try:
            root.lift()
            root.focus_force()
            entry.focus_set()
        except Exception:
            pass

        root.mainloop()
        return outcome


# ----------------------------------------------------------------------
# Orchestration
# ----------------------------------------------------------------------


def _handle_hotkey(
    engine: PolicyEngine,
    classify: Callable[[str], Any],
    *,
    input_box_factory: Callable[[], InputBox] = InputBox,
    report: Callable[[str], None] = print,
) -> None:
    """One hotkey press, start to finish. Runs on the hotkey thread; see
    the module docstring's "Threading" section.

    Never raises out to the message loop -- a rendering or classification
    failure here must not take down the hotkey for the rest of the
    process, the same "never let a UI failure escalate" rule
    `confirm_dialog.DesktopConfirmer.ask()` follows for the confirmation
    dialog.
    """
    try:
        box = input_box_factory()
        outcome = box.run(classify)

        if outcome.utterance is None:
            return  # Escape / window close -- never touches the engine

        classification = outcome.classification
        report(classification.describe())

        if not classification.matched:
            # NO_MATCH must never reach the engine.
            report(_classification_message(classification))
            return

        # `source=Source.DESKTOP` is a literal here, exactly as in
        # `dispatch.cli._say` (threat-model.md T12): never derived from
        # `classification`, argv, or an environment variable.
        # `utterance=` is the ORIGINAL typed text, not anything the model
        # produced, so that is what reaches the audit record via
        # `policy.audit._safe_utterance` (DESKTOP is trusted, so it is
        # logged).
        engine.execute(
            classification.action_id,
            classification.raw_params,
            source=Source.DESKTOP,
            utterance=outcome.utterance,
        )
    except Exception:
        log.exception("unhandled error while handling a hotkey press")


def run(
    *,
    engine_factory: Callable[[], PolicyEngine] = build_default_engine,
    message_loop: Callable[[Callable[[], None]], None] = _win32_message_loop,
    register_hotkey: Callable[[], bool] = _register_hotkey,
    unregister_hotkey: Callable[[], None] = _unregister_hotkey,
    classify: Callable[[str], Any] | None = None,
    input_box_factory: Callable[[], InputBox] = InputBox,
    report: Callable[[str], None] = print,
) -> int:
    """Register the hotkey, build the one engine, pump messages forever.

    Every dependency is injectable so tests never touch a real window, a
    real hotkey, or a live model (see `tests/test_ui_assistant.py`); the
    defaults are the real Win32 calls and the real classifier.

    Registration failure prints exactly which combination failed and
    returns non-zero WITHOUT constructing an engine or entering the
    message loop -- there is no fallback combination.

    `engine_factory` is called exactly once, here, before the message
    loop starts. Every hotkey press for the life of the process reuses
    that one `PolicyEngine` (see `build_default_engine`'s docstring for
    why that matters) -- `on_hotkey` below closes over the single
    `engine` value; it does not call `engine_factory` again.
    """
    if not register_hotkey():
        print(
            f"could not register hotkey {HOTKEY_LABEL} -- "
            "another process likely already owns this combination; "
            "not falling back to a different one",
            file=sys.stderr,
        )
        return 1

    engine = engine_factory()
    classify_fn = classify or _default_classify

    def on_hotkey() -> None:
        _handle_hotkey(
            engine,
            classify_fn,
            input_box_factory=input_box_factory,
            report=report,
        )

    try:
        message_loop(on_hotkey)
    finally:
        unregister_hotkey()

    return 0


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
