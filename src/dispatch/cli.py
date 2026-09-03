"""CLI dispatch — the entry point for desktop-originated requests.

Phase 2 (§7 build order: "policy engine + audit log; adversarial tests
pass; everything fails closed"). This module makes NO permission
decisions. It shapes argv into the shape the policy engine wants, calls
`PolicyEngine.execute`, and maps the `ExecutionResult` it gets back onto a
process exit code. Every decision — arity, parameter validity, tier,
exceptions, rate limits, confirmation — lives in `policy/engine.py`
(architecture.md §3.4: "the only component that may invoke a handler").
A second copy of any of that logic here would drift from the first.

Usage:
    python src/dispatch/cli.py <action_id> [param ...]
    python src/dispatch/cli.py list
    python src/dispatch/cli.py exceptions list
    python src/dispatch/cli.py exceptions revoke <action_id> [key=value ...]
    python src/dispatch/cli.py exceptions revoke-all
"""
from __future__ import annotations

import sys
from pathlib import Path

# Resolve src/ onto sys.path from this file's location so `from actions...`
# works regardless of invocation cwd, with no packaging changes.
_SRC = Path(__file__).resolve().parents[1]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from actions import REGISTRY, lookup  # noqa: E402
from actions.params import ParamRejected  # noqa: E402
from policy.audit import AuditLog  # noqa: E402
from policy.confirm import ConsoleConfirmer  # noqa: E402
from policy.engine import ExecutionResult, PolicyEngine  # noqa: E402
from policy.exceptions import ExceptionStore  # noqa: E402
from policy.types import RejectionCode, Source  # noqa: E402

# ----------------------------------------------------------------------
# Runtime — the engine and the store it was built with. `STORE` is not
# read directly by any subcommand any more — `exceptions revoke-all`
# goes through `engine.revoke_all_exceptions()`, same as every other
# exceptions subcommand — but it stays a module global because
# `_runtime()` constructs `PolicyEngine(exceptions=STORE, ...)` from it,
# and because tests substitute it alongside `cli.ENGINE` (see below).
#
# Built LAZILY, on first real use, and never at import time: importing
# this module — which every test does — must not construct
# `ExceptionStore()` / `AuditLog()` with their real default paths under
# `%LOCALAPPDATA%`. Tests substitute their own engine and store by
# assigning `cli.ENGINE` and `cli.STORE` (the SAME instance passed to the
# engine's `exceptions=`) before calling `main()`; `_runtime()` then never
# rebuilds the real defaults.
# ----------------------------------------------------------------------

ENGINE: PolicyEngine | None = None
STORE: ExceptionStore | None = None


def _runtime() -> tuple[PolicyEngine, ExceptionStore]:
    global ENGINE, STORE
    if ENGINE is None:
        STORE = ExceptionStore()  # default path is correct for real CLI use
        audit = AuditLog()
        ENGINE = PolicyEngine(
            REGISTRY, confirmer=ConsoleConfirmer(), exceptions=STORE, audit=audit
        )
    assert STORE is not None  # set alongside ENGINE, above or by a test
    return ENGINE, STORE


# ----------------------------------------------------------------------
# Exit codes
# ----------------------------------------------------------------------
#   0  result.ok
#   1  result.executed and result.error is not None   (handler raised)
#   2  UNKNOWN_ACTION, BAD_ARITY, PARAM_REJECTED
#   3  NOT_CONFIRMED, NO_CONFIRMER
#   4  RATE_LIMITED
#
# A dict, not an if-chain, so an unmapped RejectionCode cannot silently
# read as one of these by falling through an `else`.

_REJECTION_EXIT_CODES: dict[RejectionCode, int] = {
    RejectionCode.UNKNOWN_ACTION: 2,
    RejectionCode.BAD_ARITY: 2,
    RejectionCode.PARAM_REJECTED: 2,
    RejectionCode.NOT_CONFIRMED: 3,
    RejectionCode.NO_CONFIRMER: 3,
    RejectionCode.RATE_LIMITED: 4,
}


def _exit_code(result: ExecutionResult) -> int:
    if result.ok:
        return 0
    if result.executed and result.error is not None:
        return 1
    # Not executed => the decision was REJECTED, and `Decision.__post_init__`
    # guarantees a REJECTED decision always carries a code. The lookups
    # below still fail closed instead of defaulting to 0 if that ever stops
    # being true.
    code = result.decision.code
    if code is None:
        return 2
    try:
        return _REJECTION_EXIT_CODES[code]
    except KeyError:
        return 2


# ----------------------------------------------------------------------
# argv shaping — NOT a permission decision
# ----------------------------------------------------------------------


def _shape_params(action_id: str, raw_params: list[str]) -> dict[str, str]:
    """Turn positional CLI values into the name->value mapping the engine's
    arity check wants (`policy/engine.py`: `{spec.name for spec in
    action.params} == set(raw_params)`).

    The action is looked up here ONLY to learn what to call each
    positional value — that is argv shaping, not a decision. Every failure
    mode is left for the engine to reject:

    - unknown action id: lookup fails, so an empty mapping is returned;
      the engine's own lookup then produces UNKNOWN_ACTION.
    - wrong count: surplus values are keyed under `_extra0`, `_extra1`,
      ... so the mapping's key set does not equal the expected set, and
      the engine produces BAD_ARITY. (Too few values simply leaves some
      expected names absent from the mapping, which has the same effect.)
    """
    try:
        action = lookup(action_id)
    except KeyError:
        return {}

    names = [spec.name for spec in action.params]
    mapping: dict[str, str] = {}
    for i, raw in enumerate(raw_params):
        key = names[i] if i < len(names) else f"_extra{i}"
        mapping[key] = raw
    return mapping


def _dispatch(action_id: str, raw_params: list[str]) -> int:
    shaped = _shape_params(action_id, raw_params)
    engine, _ = _runtime()
    result = engine.execute(action_id, shaped, source=Source.DESKTOP)

    if not result.decision.allowed:
        print(f"reject: {result.decision.reason}", file=sys.stderr)
    elif result.error is not None:
        print(f"error: {result.error}", file=sys.stderr)

    return _exit_code(result)


# ----------------------------------------------------------------------
# `list`
# ----------------------------------------------------------------------


def _print_list() -> None:
    for action in REGISTRY:
        names = ", ".join(spec.name for spec in action.params) or "none"
        print(
            f"{action.id}\ttier={action.tier.value}\tparams=[{names}]"
            f"\treversible={action.reversible}\t{action.description}"
        )


# ----------------------------------------------------------------------
# `exceptions ...`
# ----------------------------------------------------------------------


def _exceptions_list(engine: PolicyEngine) -> int:
    grants = engine.list_exceptions()
    if not grants:
        print("no standing exceptions")
        return 0
    for grant in grants:
        print(f"{grant.granted_at.isoformat()}\t{grant.describe()}")
    return 0


def _exceptions_revoke(engine: PolicyEngine, args: list[str]) -> int:
    if not args:
        print(
            "usage: cli.py exceptions revoke <action_id> [key=value ...]",
            file=sys.stderr,
        )
        return 2

    action_id, pairs = args[0], args[1:]
    try:
        action = lookup(action_id)
    except KeyError as exc:
        print(f"reject: {exc}", file=sys.stderr)
        return 2

    # Grants are stored from PARSED values (`engine._ask` calls
    # `grant(action.id, tier, parsed)`), so revoking by the raw string a
    # user typed would build the wrong signature — e.g. `str:display`
    # instead of `enum:DISPLAY` — and never match. Parse each value with
    # the action's own ParamSpec before calling revoke_exception, exactly
    # as the engine parses on the way in.
    specs = {spec.name: spec for spec in action.params}
    parsed: dict[str, object] = {}
    for pair in pairs:
        if "=" not in pair:
            print(f"reject: expected key=value, got {pair!r}", file=sys.stderr)
            return 2
        key, _, raw_value = pair.partition("=")
        spec = specs.get(key)
        if spec is None:
            print(f"reject: {action_id} has no parameter {key!r}", file=sys.stderr)
            return 2
        try:
            parsed[key] = spec.parse(raw_value)
        except ParamRejected as exc:
            print(f"reject: {exc}", file=sys.stderr)
            return 2

    removed = engine.revoke_exception(action_id, parsed)
    label = " ".join(pairs)
    if removed:
        print(f"revoked: {action_id} {label}".rstrip())
    else:
        print(f"no matching exception for {action_id} {label}".rstrip())
    return 0


def _exceptions_revoke_all(engine: PolicyEngine) -> int:
    # Goes through the engine, not the store directly, because
    # `revoke_all_exceptions()` audits an `exception_revoked` note per
    # grant plus a summary note — `ExceptionStore.revoke_all()` alone
    # writes nothing, which would leave a bulk revoke untraceable.
    count = engine.revoke_all_exceptions()
    print(f"revoked {count} exception(s)")
    return 0


def _exceptions_command(args: list[str]) -> int:
    if not args:
        print(
            "usage: cli.py exceptions <list|revoke|revoke-all> ...",
            file=sys.stderr,
        )
        return 2

    sub, rest = args[0], args[1:]
    engine, _ = _runtime()

    if sub == "list":
        return _exceptions_list(engine)
    if sub == "revoke-all":
        return _exceptions_revoke_all(engine)
    if sub == "revoke":
        return _exceptions_revoke(engine, rest)

    print(f"usage: unknown exceptions subcommand {sub!r}", file=sys.stderr)
    return 2


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------


def main(argv: list[str]) -> int:
    if not argv:
        print(
            "usage: cli.py <action_id> [param ...] | cli.py list | "
            "cli.py exceptions <list|revoke|revoke-all> ...",
            file=sys.stderr,
        )
        return 2

    if argv[0] == "list":
        _print_list()
        return 0

    if argv[0] == "exceptions":
        return _exceptions_command(argv[1:])

    return _dispatch(argv[0], argv[1:])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
