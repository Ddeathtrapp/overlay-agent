"""Shared test helpers.

The `assert_raises` helper is deliberately free of any `pytest` import: it
predates pytest being available in `.venv` (see the repo's pytest-in-venv
memory note) and is kept dependency-free so it also works under a plain
runner. `PolicyEngine`/`ExceptionStore`/`AuditLog` test-doubles below DO use
pytest fixtures (`tmp_path`) by parameter name, same as the rest of the
suite already does — that needs no import, only pytest itself running the
collection.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Callable

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from actions import REGISTRY  # noqa: E402
from policy.audit import AuditLog  # noqa: E402
from policy.confirm import Confirmer, ConfirmationPrompt, ConfirmationReply  # noqa: E402
from policy.engine import PolicyEngine  # noqa: E402
from policy.exceptions import ExceptionStore  # noqa: E402


def assert_raises(exc: type[BaseException], fn: Callable[..., Any], *args: Any,
                  match: str | None = None) -> BaseException:
    """Stand-in for `pytest.raises`, usable without pytest installed."""
    try:
        fn(*args)
    except exc as caught:
        if match is not None and match not in str(caught):
            raise AssertionError(
                f"expected {match!r} in error message, got {str(caught)!r}"
            ) from None
        return caught
    raise AssertionError(f"expected {exc.__name__}, but nothing was raised")


class StubConfirmer(Confirmer):
    """A `Confirmer` a test can script, that never blocks on `input()`.

    Subclasses `Confirmer` directly, NOT `NullConfirmer` — `engine._ask`
    special-cases `isinstance(self._confirmer, NullConfirmer)` to
    short-circuit to `NO_CONFIRMER` *without ever calling `.ask()`*, so a
    `NullConfirmer` subclass would never actually exercise the ask/verify
    path this stub exists to test.

    Replies are consumed in order, one per call to `.ask()`. Once
    exhausted, further calls default to a plain decline — the fail-closed
    direction — rather than raising `IndexError` or repeating the last
    reply, so a test that mis-counts its scripted replies gets a rejection
    it can see instead of an exception mid-run.
    """

    def __init__(self, *replies: ConfirmationReply) -> None:
        self._replies = list(replies)
        self.prompts: list[ConfirmationPrompt] = []

    def ask(self, prompt: ConfirmationPrompt) -> ConfirmationReply:
        self.prompts.append(prompt)
        if self._replies:
            return self._replies.pop(0)
        return ConfirmationReply(approved=False)

    @property
    def call_count(self) -> int:
        return len(self.prompts)


def build_engine(
    tmp_path: Path, confirmer: Confirmer | None = None,
) -> tuple[PolicyEngine, ExceptionStore, AuditLog]:
    """A `PolicyEngine` wired to tmp_path-scoped store/audit, built against
    the REAL `actions.REGISTRY`.

    Always the real registry, on purpose: `PolicyEngine._run` resolves
    every request through the process-global `actions.lookup`, which is
    bound to `actions.REGISTRY` regardless of what `registry` argument the
    engine was constructed with (that argument only feeds the rate-limit
    table and exception pruning). A fabricated registry here would build a
    rate-limit table with no entry for the action actually being executed
    and every dispatch would spuriously fail with RATE_LIMITED.

    Every test that needs a `PolicyEngine` should go through this rather
    than constructing one directly, so tmp_path scoping can't be
    forgotten and `ExceptionStore()`/`AuditLog()` are never called bare.
    """
    store = ExceptionStore(tmp_path / "exceptions.json")
    audit = AuditLog(tmp_path / "audit.jsonl")
    engine = PolicyEngine(
        REGISTRY,
        confirmer=confirmer if confirmer is not None else StubConfirmer(),
        exceptions=store,
        audit=audit,
    )
    return engine, store, audit
