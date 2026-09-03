"""policy.exceptions: the standing-exception store.

Every store constructed here takes an explicit tmp_path. ExceptionStore()
with no path argument resolves to the user's REAL
%LOCALAPPDATA%\\overlay-agent\\exceptions.json -- never construct one bare,
here or anywhere else.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from _helpers import assert_raises

from policy.exceptions import (
    TIER_TWO,
    ExceptionRefused,
    ExceptionStore,
    Grant,
    _canonical,
    signature,
)


class _Color(Enum):
    RED = "red"


# --- grant(): tier 2 is never storable -----------------------------------

def test_grant_tier_two_raises_and_persists_nothing(tmp_path) -> None:
    path = tmp_path / "exceptions.json"
    store = ExceptionStore(path)
    assert_raises(ExceptionRefused, store.grant, "shutdown", TIER_TWO, {})
    assert store.list() == []
    assert not path.exists()  # _save() is only reached on the success path


# --- grant()/matches(): exact parameter-value scoping -----------------------

def test_grant_for_one_value_does_not_match_a_different_value(tmp_path) -> None:
    path = tmp_path / "exceptions.json"
    store = ExceptionStore(path)
    store.grant("open_app", 1, {"app": "notepad"})
    assert store.matches("open_app", {"app": "notepad"}) is True
    assert store.matches("open_app", {"app": "calc"}) is False


def test_signature_is_order_independent() -> None:
    # No store needed -- signature() is a pure function.
    assert signature({"a": 1, "b": 2}) == signature({"b": 2, "a": 1})


def test_matches_ignores_original_param_key_order(tmp_path) -> None:
    path = tmp_path / "exceptions.json"
    store = ExceptionStore(path)
    store.grant("set_volume", 1, {"a": 1, "b": 2})
    assert store.matches("set_volume", {"b": 2, "a": 1}) is True


def test_parameterless_action_signature_matches_only_itself(tmp_path) -> None:
    path = tmp_path / "exceptions.json"
    store = ExceptionStore(path)
    store.grant("action_a", 1, {})
    # direction 1: a different action id with the same (empty) signature
    # does not match the grant that was made.
    assert store.matches("action_b", {}) is False
    store.grant("action_b", 1, {})
    # direction 2: granting the second id does not retroactively make the
    # first grant answer for it, or vice versa -- each id's empty signature
    # matches only its own grant.
    assert store.matches("action_a", {}) is True
    assert store.matches("action_b", {}) is True
    assert store.matches("action_c", {}) is False


# --- _canonical(): unsupported types fail closed, not str()-fallback -------

def test_canonical_rejects_list_dict_and_arbitrary_object() -> None:
    assert_raises(ExceptionRefused, _canonical, [1, 2])
    assert_raises(ExceptionRefused, _canonical, {"a": 1})
    assert_raises(ExceptionRefused, _canonical, object())


def test_canonical_rejects_bool_checked_before_int() -> None:
    # bool is a subclass of int, so the isinstance(value, bool) check MUST
    # run before isinstance(value, int) or True/False would silently become
    # "int:1" / "int:0" -- a signature indistinguishable from a real int
    # parameter. That ordering is load-bearing.
    assert_raises(ExceptionRefused, _canonical, True)
    assert_raises(ExceptionRefused, _canonical, False)


def test_canonical_accepts_the_three_supported_kinds() -> None:
    assert _canonical(_Color.RED) == "enum:RED"
    assert _canonical(5) == "int:5"
    assert _canonical("x") == "str:x"


def test_matches_returns_false_for_uncanonicalisable_params(tmp_path) -> None:
    path = tmp_path / "exceptions.json"
    store = ExceptionStore(path)
    # No matching grant exists (and could never exist), but matches() must
    # fail closed (return False) rather than raise.
    assert store.matches("open_app", {"app": [1, 2]}) is False


def test_grant_with_uncanonicalisable_param_raises(tmp_path) -> None:
    path = tmp_path / "exceptions.json"
    store = ExceptionStore(path)
    assert_raises(ExceptionRefused, store.grant, "open_app", 1, {"app": [1, 2]})
    assert store.list() == []


# --- corrupt store: fail closed to empty, never to "allow everything" ------

def test_corrupt_json_store_loads_empty(tmp_path) -> None:
    path = tmp_path / "exceptions.json"
    path.write_text("{not json", encoding="utf-8")
    store = ExceptionStore(path)
    assert store.list() == []
    assert store.matches("open_app", {"app": "notepad"}) is False
    assert store.matches("anything", {}) is False


def test_truncated_json_store_loads_empty(tmp_path) -> None:
    path = tmp_path / "exceptions.json"
    path.write_text('[{"action_id":', encoding="utf-8")
    store = ExceptionStore(path)
    assert store.list() == []
    assert store.matches("open_app", {}) is False


# --- revoke() ----------------------------------------------------------------

def test_revoke_never_granted_returns_false(tmp_path) -> None:
    path = tmp_path / "exceptions.json"
    store = ExceptionStore(path)
    assert store.revoke("open_app", {"app": "notepad"}) is False


def test_revoke_all_returns_count_and_empties_store(tmp_path) -> None:
    path = tmp_path / "exceptions.json"
    store = ExceptionStore(path)
    store.grant("open_app", 1, {"app": "notepad"})
    store.grant("lock_screen", 0, {})
    assert store.revoke_all() == 2
    assert store.list() == []


# --- persistence: a fresh store against the same path sees the grant -------

def test_round_trip_through_a_fresh_store_instance(tmp_path) -> None:
    path = tmp_path / "exceptions.json"
    store1 = ExceptionStore(path)
    store1.grant("open_app", 1, {"app": "notepad"})

    store2 = ExceptionStore(path)  # fresh instance, same file
    assert store2.matches("open_app", {"app": "notepad"}) is True


# --- prune_unknown() ----------------------------------------------------------

def test_prune_unknown_removes_stale_and_keeps_known(tmp_path) -> None:
    path = tmp_path / "exceptions.json"
    store = ExceptionStore(path)
    store.grant("open_app", 1, {"app": "notepad"})
    store.grant("lock_screen", 0, {})
    removed = store.prune_unknown({"open_app"})
    assert removed == 1
    assert {g.action_id for g in store.list()} == {"open_app"}


# --- Grant.describe() / to_json / from_json ------------------------------------

def test_grant_describe_parameterless() -> None:
    grant = Grant("lock_screen", (), datetime.now(timezone.utc))
    assert grant.describe() == "lock_screen"


def test_grant_describe_with_params() -> None:
    # describe() now includes the parameter NAME, not just its value, so a
    # human reading the exception list can tell which parameter a value
    # belongs to at a glance (see confirm.py's ConfirmationPrompt.summary()
    # docstring for the same reasoning applied to confirmation prompts).
    grant = Grant("open_app", (("app", "str:notepad"),), datetime.now(timezone.utc))
    assert grant.describe() == "open_app app=notepad"


def test_grant_to_json_from_json_round_trip() -> None:
    original = Grant("open_app", (("app", "str:notepad"),), datetime.now(timezone.utc))
    restored = Grant.from_json(original.to_json())
    assert restored == original
