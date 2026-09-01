"""Registry integrity. These are the invariants from §2 and §5 expressed as
assertions, so a future action that violates one cannot be merged quietly."""
from __future__ import annotations

from _helpers import assert_raises

from actions import REGISTRY, lookup
from actions.params import BoundedIntParam, EnumParam, WhitelistKeyParam
from actions.schema import Action, Tier

PARAM_KINDS = (EnumParam, BoundedIntParam, WhitelistKeyParam)

# §8. Names that must never appear as action IDs, in whole or in part.
EXCLUDED_SUBSTRINGS = (
    "run_command", "execute", "shell", "write_file", "delete_file",
    "download", "install", "update", "send_network_request",
    "read_credential", "modify_security", "open_url",
)


def test_registry_is_a_tuple_of_actions() -> None:
    # §2.1: closed at build time. A tuple cannot be appended to at runtime.
    assert isinstance(REGISTRY, tuple)
    assert all(isinstance(a, Action) for a in REGISTRY)
    assert REGISTRY, "registry must not be empty"


def test_ids_are_unique() -> None:
    ids = [a.id for a in REGISTRY]
    assert len(ids) == len(set(ids))


def test_ids_are_snake_case() -> None:
    for action in REGISTRY:
        assert action.id, "empty id"
        assert all(c.islower() or c.isdigit() or c == "_" for c in action.id), action.id
        assert not action.id.startswith("_") and not action.id.endswith("_"), action.id


def test_no_id_resembles_the_exclusion_list() -> None:
    for action in REGISTRY:
        for banned in EXCLUDED_SUBSTRINGS:
            assert banned not in action.id, f"{action.id} is §8-adjacent"


def test_retired_ids_are_not_registered() -> None:
    # §0.1 / §4: toggle_night_light was retired, never reassigned.
    assert "toggle_night_light" not in {a.id for a in REGISTRY}


def test_every_param_is_one_of_the_three_kinds() -> None:
    # §3: there is no fourth kind.
    for action in REGISTRY:
        assert isinstance(action.params, tuple), action.id
        for spec in action.params:
            assert isinstance(spec, PARAM_KINDS), f"{action.id}: {type(spec)}"


def test_param_names_are_unique_within_an_action() -> None:
    # cli.py passes params as **kwargs keyed on spec.name; duplicates would
    # silently drop one.
    for action in REGISTRY:
        names = [spec.name for spec in action.params]
        assert len(names) == len(set(names)), action.id


def test_tiers_are_valid_and_consistent() -> None:
    for action in REGISTRY:
        assert isinstance(action.tier, Tier), action.id
        if action.tier is Tier.ZERO:
            # §5: tier 0 is "zero parameters, reversible".
            assert action.params == (), action.id
            assert action.reversible, action.id
        if not action.reversible:
            # §5: irreversible means tier 2, always.
            assert action.tier is Tier.TWO, action.id


def test_descriptions_are_classifier_ready_sentences() -> None:
    # §4: written as a plain sentence a person would say, because that is what
    # the classifier matches against.
    for action in REGISTRY:
        assert action.description, action.id
        assert action.description[0].isupper(), action.id
        assert action.description.endswith("."), action.id


def test_handlers_are_callable_and_distinct() -> None:
    handlers = [a.handler for a in REGISTRY]
    assert all(callable(h) for h in handlers)
    assert len(set(handlers)) == len(handlers), "two actions share a handler"


def test_lookup_returns_the_matching_action() -> None:
    for action in REGISTRY:
        assert lookup(action.id) is action


def test_registry_size_forces_a_composition_recheck() -> None:
    # §7 mandates re-running the composition check across the WHOLE registry
    # every ten additions, but nothing otherwise notices the tenth one — and
    # §6's second erosion path is exactly registry growth, where ten
    # individually safe actions compose into an unsafe capability no single
    # review catches. This converts that process into a build-time stop.
    assert len(REGISTRY) <= 10, (
        "§7: run the whole-registry composition check across all actions, "
        "record the pairwise reasoning, then raise this bound."
    )


def test_lookup_fails_closed_on_unknown_id() -> None:
    # §2.4: never guess, never coerce, never fall through to a default.
    for unknown in ("", "toggle_night_light", "shutdown", "SHUTDOWN_PC",
                    "open_application ", "bogus"):
        assert_raises(KeyError, lookup, unknown)
