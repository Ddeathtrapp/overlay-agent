"""Desktop confirmation dialog — the Phase 4 `Confirmer` implementation.

Implements `policy.confirm.Confirmer`. Renders a modal tkinter window that
asks the human to allow or deny an `ActionRequest`, and returns whatever they
answered as a `ConfirmationReply`. It does not decide anything: the tier-2
typed-challenge rule lives in `policy.confirm.Confirmer.verify`, not here
(architecture.md §3.7, policy/confirm.py's module docstring). This file only
renders `prompt` and reports what the human did with it.

Threading model
----------------
`engine.py:_ask_with_timeout` spawns a **daemon** thread per confirmation
(`confirm-{action_id}`) whose target calls `Confirmer.ask(prompt)` directly,
then does `thread.join(prompt.timeout_seconds)` on the *calling* thread. So:

* `ask()` genuinely runs off the main thread — whichever thread the engine
  happens to be running on when it needs a confirmation. Tk requires its
  root to be created, used, and destroyed on the same thread ("Tcl_Interp
  is not thread safe"), so the `tkinter.Tk()` root is created *inside*
  `ask()`, all widget/event work happens inside that same call, and the
  root is destroyed before `ask()` returns. No Tk object survives past a
  single `ask()` call, and nothing here is shared across calls.
* The engine's `thread.join(prompt.timeout_seconds)` is a **backstop**, not
  the mechanism: if this dialog took the full `timeout_seconds` to close,
  the engine could time out and return its own denial to the caller a
  moment before this thread finishes, and because the worker is a daemon
  thread nothing is left to join it or kill the window — a dead dialog
  would sit on screen with no one listening to its answer. So this dialog
  self-closes (as a denial) on a deadline set slightly *before*
  `prompt.timeout_seconds`, guaranteeing it is gone before the engine gives
  up. See `_CLOSE_MARGIN_SECONDS` below for the exact margin and why it is
  a flat value rather than a percentage.
* If `_run_dialog` raises for any reason, `ask()` catches it and returns a
  denial rather than letting the exception surface — `engine.py` re-raises
  a confirmer's exception on the *calling* thread, and re-raising out of a
  UI failure is exactly the "something went wrong -> approved=True" path
  this module must never have.

Test seam
---------
Tests must never open a real window or block. Two seams exist for that:

* `DesktopConfirmer._create_root` — the single point that calls
  `tkinter.Tk()`. Monkeypatching this on the class simulates Tk failing to
  initialise at all (headless session, no display) without needing a fake
  `tkinter` module.
* The module-level `tkinter` name itself. `_build_and_run` only ever
  references widgets as `tkinter.Frame`, `tkinter.Button`, etc. (never via
  a `from tkinter import ...`), so a test can do
  `monkeypatch.setattr(confirm_dialog, "tkinter", fake_module)` and every
  widget class, `Tk`, `StringVar`, and `BooleanVar` resolved inside this
  module resolves to the fake instead, with `mainloop()` a controllable
  no-op instead of a real blocking event loop.
"""

from __future__ import annotations

import logging
import math
import time
import tkinter
from dataclasses import dataclass

from policy.confirm import Confirmer, ConfirmationPrompt, ConfirmationReply

log = logging.getLogger(__name__)

# Margin subtracted from `prompt.timeout_seconds` to get this dialog's own
# self-close deadline (see module docstring, "Threading model").
#
# A flat margin, not a percentage. At the platform default of 120s a 2%
# margin (2.4s) would be plenty, but at a short custom timeout (a handful
# of seconds) a percentage shrinks to a fraction of a second -- not enough
# headroom once you account for Tk's `after()` polling interval and
# ordinary OS scheduling jitter. A flat 1s margin gives the same real
# headroom regardless of how the timeout is configured.
_CLOSE_MARGIN_SECONDS = 1.0

# How often the countdown re-checks the deadline and repaints the label.
# Sub-second so the self-close deadline (which must land strictly before
# the engine's) is not missed by up to a whole second.
_TICK_MS = 200

_WINDOW_TITLE = "Confirm action"
_SUMMARY_FONT = ("Segoe UI", 15, "bold")
_DESCRIPTION_FONT = ("Segoe UI", 10)
_META_FONT = ("Segoe UI", 9)
_WARNING_FONT = ("Segoe UI", 10, "bold")
_CHALLENGE_FONT = ("Consolas", 11, "bold")
_COUNTDOWN_FONT = ("Segoe UI", 9)


def _dialog_deadline_seconds(timeout_seconds: float) -> float:
    """How long *this dialog* waits before self-closing as a denial.

    Always strictly less than `timeout_seconds` (floored at zero for a
    pathologically short configured timeout) so the window is gone before
    `engine.py`'s `thread.join(prompt.timeout_seconds)` gives up.
    """
    return max(0.0, timeout_seconds - _CLOSE_MARGIN_SECONDS)


def _safe_destroy(root: object) -> None:
    """Best-effort teardown. A second `.destroy()` on an already-destroyed
    real Tk root raises `TclError`; swallow it, this runs in a `finally`."""
    try:
        root.destroy()  # type: ignore[attr-defined]
    except Exception:
        pass


@dataclass
class _Outcome:
    """Mutable box the dialog's callbacks write into. `ask()` never reads
    tkinter widget state directly -- only this, after the window is gone."""

    approved: bool = False
    typed: str | None = None
    remember: bool = False


class DesktopConfirmer(Confirmer):
    """Modal tkinter confirmation dialog. See module docstring for the
    threading contract this class must uphold."""

    def ask(self, prompt: ConfirmationPrompt) -> ConfirmationReply:
        """Block until answered, denied, closed, or self-timed-out.

        Never raises. `_run_dialog` is where rendering happens; anything
        it throws (Tk failing to initialise, a widget error, anything)
        is caught here and turned into a denial -- there is no path from
        a rendering failure to `approved=True`.
        """
        try:
            outcome = self._run_dialog(prompt)
        except Exception:
            log.exception(
                "desktop confirmation dialog failed for %s; denying", prompt.action_id
            )
            return ConfirmationReply(approved=False)

        # Explicit bool(...): callbacks build this from real bool literals,
        # but a BooleanVar.get() can hand back an int, and
        # ConfirmationReply.__post_init__ rejects anything that is not
        # literally a bool. Coerce here rather than trust upstream.
        return ConfirmationReply(
            approved=bool(outcome.approved),
            typed=outcome.typed,
            remember=bool(outcome.remember),
        )

    # -- seams -------------------------------------------------------------

    def _create_root(self) -> tkinter.Tk:
        """The one call to `tkinter.Tk()`. Kept as its own method so a test
        can monkeypatch just this to simulate Tk failing outright (no
        display, headless session) without building a fake `tkinter`
        module."""
        return tkinter.Tk()

    def _run_dialog(self, prompt: ConfirmationPrompt) -> _Outcome:
        root = self._create_root()
        try:
            return self._build_and_run(root, prompt)
        finally:
            _safe_destroy(root)

    # -- rendering -----------------------------------------------------------

    def _build_and_run(self, root: tkinter.Tk, prompt: ConfirmationPrompt) -> _Outcome:
        outcome = _Outcome()

        root.title(_WINDOW_TITLE)
        root.resizable(False, False)
        try:
            root.attributes("-topmost", True)
        except Exception:
            pass
        try:
            # Windows-only attribute: keeps this off the taskbar without
            # giving up the normal title bar/close button the confirmation
            # (unlike the overlay) is allowed to have.
            root.attributes("-toolwindow", True)
        except Exception:
            pass

        def finish(approved: bool, typed: str | None = None, remember: bool = False) -> None:
            outcome.approved = approved
            outcome.typed = typed
            outcome.remember = remember
            _safe_destroy(root)

        root.protocol("WM_DELETE_WINDOW", lambda: finish(False))
        root.bind("<Escape>", lambda _event=None: finish(False))

        container = tkinter.Frame(root, padx=20, pady=16)
        container.pack()

        summary_label = tkinter.Label(
            container, text=prompt.summary(), font=_SUMMARY_FONT, wraplength=440, justify="left"
        )
        summary_label.pack(anchor="w")

        description_label = tkinter.Label(
            container, text=prompt.description, font=_DESCRIPTION_FONT, wraplength=440, justify="left"
        )
        description_label.pack(anchor="w", pady=(4, 0))

        meta_label = tkinter.Label(
            container,
            text=f"tier {prompt.tier} · from {prompt.source_label}",
            font=_META_FONT,
            fg="#555555",
        )
        meta_label.pack(anchor="w", pady=(2, 8))

        entry_var = None
        if prompt.requires_typed:
            warning_label = tkinter.Label(
                container,
                text="This action is irreversible. Type the phrase below exactly to allow it.",
                font=_WARNING_FONT,
                fg="#b00020",
                wraplength=440,
                justify="left",
            )
            warning_label.pack(anchor="w", pady=(0, 4))

            challenge_label = tkinter.Label(
                container, text=prompt.challenge, font=_CHALLENGE_FONT, fg="#b00020"
            )
            challenge_label.pack(anchor="w", pady=(0, 4))

            entry_var = tkinter.StringVar(value="")
            entry = tkinter.Entry(container, textvariable=entry_var, width=40)
            entry.pack(anchor="w", pady=(0, 8))

        remember_var = None
        if prompt.allow_remember:
            remember_var = tkinter.BooleanVar(value=False)
            remember_check = tkinter.Checkbutton(
                container, text="Always allow this exact action", variable=remember_var
            )
            remember_check.pack(anchor="w", pady=(0, 8))

        countdown_label = tkinter.Label(container, text="", font=_COUNTDOWN_FONT, fg="#555555")
        countdown_label.pack(anchor="w", pady=(0, 8))

        button_row = tkinter.Frame(container)
        button_row.pack(anchor="e", fill="x")

        def on_allow() -> None:
            typed_value = entry_var.get() if entry_var is not None else None
            remember_value = bool(remember_var.get()) if remember_var is not None else False
            finish(True, typed=typed_value, remember=remember_value)

        def on_deny() -> None:
            finish(False)

        allow_state = tkinter.DISABLED if prompt.requires_typed else tkinter.NORMAL
        allow_button = tkinter.Button(
            button_row, text="Allow", command=on_allow, state=allow_state
        )
        deny_button = tkinter.Button(button_row, text="Deny", command=on_deny)
        deny_button.pack(side="right", padx=(8, 0))
        allow_button.pack(side="right")

        if prompt.requires_typed:

            def on_challenge_changed(*_args: object) -> None:
                # Exact, case-sensitive match against the same comparison
                # `Confirmer.verify` performs (`reply.typed.strip() ==
                # prompt.challenge`) -- the button must not enable on
                # anything `verify` would go on to refuse anyway.
                matches = entry_var.get().strip() == prompt.challenge
                allow_button.config(state=tkinter.NORMAL if matches else tkinter.DISABLED)

            entry_var.trace_add("write", on_challenge_changed)

        # Deny holds default focus so a stray Enter denies. The contract
        # only calls this out for tier 0/1, but defaulting focus to Deny
        # on tier 2 as well is strictly safer (Enter cannot approve there
        # anyway -- Allow starts disabled) and keeps the behaviour uniform.
        deny_button.focus_set()

        def on_return(_event: object = None) -> None:
            widget = root.focus_get()
            invoke = getattr(widget, "invoke", None)
            if callable(invoke):
                invoke()

        root.bind("<Return>", on_return)

        deadline = time.monotonic() + _dialog_deadline_seconds(prompt.timeout_seconds)

        def tick() -> None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                finish(False)
                return
            countdown_label.config(text=f"{math.ceil(remaining)}s remaining")
            root.after(_TICK_MS, tick)

        tick()

        try:
            root.geometry("")
            root.update_idletasks()
            width = root.winfo_reqwidth()
            height = root.winfo_reqheight()
            screen_w = root.winfo_screenwidth()
            screen_h = root.winfo_screenheight()
            x = max(0, (screen_w - width) // 2)
            y = max(0, (screen_h - height) // 2)
            root.geometry(f"{width}x{height}+{x}+{y}")
        except Exception:
            # Centring is cosmetic. A failure here must not prevent the
            # dialog (or its fail-closed defaults) from working.
            pass

        try:
            root.deiconify()
        except Exception:
            pass
        try:
            root.lift()
            root.focus_force()
        except Exception:
            pass

        root.mainloop()
        return outcome


# --------------------------------------------------------------------------
# Manual demo -- not exercised by the test suite.
# --------------------------------------------------------------------------


def _demo_prompt(tier: int, timeout_seconds: float) -> ConfirmationPrompt:
    from policy.confirm import build_prompt

    if tier >= 2:
        return build_prompt(
            action_id="shutdown_pc",
            description="Shuts the computer down immediately. Cannot be undone.",
            params={},
            tier=2,
            source_label="desktop",
            source_trusted=True,
            timeout_seconds=timeout_seconds,
        )
    return build_prompt(
        action_id="open_application",
        description="Opens an application window.",
        params={"name": "notepad"},
        tier=tier,
        source_label="desktop",
        source_trusted=True,
        timeout_seconds=timeout_seconds,
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Show a real DesktopConfirmer dialog.")
    parser.add_argument("--tier", type=int, choices=(0, 1, 2), default=0)
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()

    demo_prompt = _demo_prompt(args.tier, args.timeout)
    print(f"showing: {demo_prompt.summary()!r} (tier {demo_prompt.tier})")
    demo_reply = DesktopConfirmer().ask(demo_prompt)
    print(f"reply: approved={demo_reply.approved!r} typed={demo_reply.typed!r} remember={demo_reply.remember!r}")
