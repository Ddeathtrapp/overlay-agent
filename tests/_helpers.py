"""Shared test helpers.

Deliberately free of any `pytest` import. pytest is not installed on this
machine and `CLAUDE.md` forbids installing it, so the suite is written so its
assertions can also be exercised by a plain runner in the meantime. Every test
here is a bare `test_*` function using `assert`, which pytest collects natively
once it is available.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Callable

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


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
