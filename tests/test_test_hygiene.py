"""Guards on the test suite itself, not on application code.

`ExceptionStore()`, `AuditLog()`, and `PolicyEngine()` (when built with the
exceptions/audit store defaults) all resolve, with no arguments, to paths
under the user's REAL `%LOCALAPPDATA%\\overlay-agent`. A test that
constructs any of these bare would read or write the real store or the
real audit log. Every test in this suite is required to pass an explicit
tmp_path-derived `ExceptionStore`/`AuditLog` (see `_helpers.build_engine`,
which every PolicyEngine-needing test should go through instead of
constructing one directly) -- this test is the tripwire for a future test
that forgets.

`src/dispatch/cli.py::_runtime` is the one legitimate bare construction in
the whole codebase (the real CLI's real default), and it is deliberately
outside `tests/`, so it is not scanned here.

Uses `ast`, not a text/regex search: several files in this suite discuss
`ExceptionStore()` in prose (this docstring is one of them) precisely to
warn against writing it as code, and a text search would flag its own
warning.
"""
from __future__ import annotations

import ast
from pathlib import Path

_TESTS_DIR = Path(__file__).resolve().parent

_WATCHED_NAMES = {"PolicyEngine", "ExceptionStore", "AuditLog"}


def _bare_calls(source: str) -> list[int]:
    """Line numbers of `Name()` calls, with zero args and zero keywords,
    to one of the watched constructors. Only a direct `Foo()` call is
    checked (not `mod.Foo()`) -- every watched name is imported directly
    by name in this codebase, never accessed through a module attribute."""
    tree = ast.parse(source)
    hits: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in _WATCHED_NAMES:
            if not node.args and not node.keywords:
                hits.append(node.lineno)
    return hits


def test_no_test_file_constructs_policy_objects_with_empty_parens() -> None:
    offenders = []
    for path in _TESTS_DIR.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for line_no in _bare_calls(text):
            offenders.append(f"{path.relative_to(_TESTS_DIR)}:{line_no}")

    assert not offenders, (
        "bare (real %LOCALAPPDATA%-path) construction found in tests/ -- "
        "use _helpers.build_engine or pass an explicit tmp_path instead:\n"
        + "\n".join(offenders)
    )
