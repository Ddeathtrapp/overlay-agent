"""CLI dispatch — Phase 1's only entry point (§7 build order: "Working CLI
tool, no LLM anywhere"). This stands in for the classifier and the policy
engine, neither of which exist yet. Every step fails closed (§2.4, §6).

Usage:
    python src/dispatch/cli.py <action_id> [param ...]
    python src/dispatch/cli.py list
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
from actions.schema import Tier  # noqa: E402


def _print_list() -> None:
    for action in REGISTRY:
        names = ", ".join(spec.name for spec in action.params) or "none"
        print(
            f"{action.id}\ttier={action.tier.value}\tparams=[{names}]"
            f"\treversible={action.reversible}\t{action.description}"
        )


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: cli.py <action_id> [param ...] | cli.py list", file=sys.stderr)
        return 2

    if argv[0] == "list":
        _print_list()
        return 0

    action_id, raw_params = argv[0], argv[1:]

    try:
        action = lookup(action_id)
    except KeyError as exc:
        print(f"reject: {exc}", file=sys.stderr)
        return 2

    if len(raw_params) != len(action.params):
        print(
            f"reject: {action_id} takes {len(action.params)} parameter(s), "
            f"got {len(raw_params)}",
            file=sys.stderr,
        )
        return 2

    parsed: dict[str, object] = {}
    for spec, raw in zip(action.params, raw_params):
        try:
            parsed[spec.name] = spec.parse(raw)
        except ParamRejected as exc:
            print(f"reject: {exc}", file=sys.stderr)
            return 2

    # §6: only the policy engine may invoke a handler for a tier 2 action.
    # Phase 2 doesn't exist yet, so dispatch refuses rather than calling the
    # handler unchecked. Reads action.tier off the registry directly — no
    # separate "tier 2 ids" list to drift out of sync with it. Allowlist the
    # tiers dispatch is permitted to run (§2.4 fail closed): anything other
    # than ZERO/ONE is blocked, rather than singling out TWO by identity —
    # a denylist on the one tier we know about today silently falls open for
    # any tier this check wasn't written to anticipate.
    if action.tier not in (Tier.ZERO, Tier.ONE):
        print(
            f"reject: {action_id} is tier 2 and requires the policy engine "
            "(Phase 2)",
            file=sys.stderr,
        )
        return 3

    try:
        action.handler(**parsed)
    except Exception as exc:  # handler failure is reported, never retried
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
