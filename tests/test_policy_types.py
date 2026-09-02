"""policy.types is documented as "shapes only, nothing decides anything" —
but the two `__post_init__` invariants (Decision's code/outcome pairing and
ActionRequest's frozen raw_params) ARE the security surface of this module,
so those are exercised directly rather than only through engine.py."""
from __future__ import annotations

import dataclasses

from _helpers import assert_raises

from policy.types import ActionRequest, Decision, Outcome, RejectionCode, Source


def _req(**overrides) -> ActionRequest:
    params = overrides.pop("raw_params", {"a": 1})
    kwargs = dict(action_id="some_action", raw_params=params, source=Source.DESKTOP)
    kwargs.update(overrides)
    return ActionRequest(**kwargs)


# --- Decision: REJECTED requires a code -------------------------------------

def test_rejected_decision_without_code_raises() -> None:
    req = _req()
    assert_raises(ValueError, Decision, Outcome.REJECTED, req, "reason")


def test_reject_classmethod_with_none_code_raises() -> None:
    # `code` is positional-required on Decision.reject's signature, but
    # nothing in the type hint stops a caller passing None explicitly.
    # __post_init__ is the actual backstop, not the annotation, so exercise
    # the classmethod route too, not just the raw constructor.
    req = _req()
    assert_raises(ValueError, Decision.reject, req, None, "reason")


# --- Decision: non-rejection outcomes must not carry a code -----------------

def test_auto_allowed_decision_with_code_raises() -> None:
    # Decision.auto_allow() takes no `code` parameter at all, so this bad
    # state is unreachable through the classmethod -- only the raw
    # constructor can produce it. That the classmethods make it
    # unrepresentable is exactly the point; this test is what confirms the
    # constructor itself still refuses it, in case a classmethod is ever
    # changed to forward a code by mistake.
    req = _req()
    assert_raises(
        ValueError, Decision, Outcome.AUTO_ALLOWED, req, "r", RejectionCode.RATE_LIMITED
    )


def test_confirmed_decision_with_code_raises() -> None:
    req = _req()
    assert_raises(
        ValueError, Decision, Outcome.CONFIRMED, req, "r", RejectionCode.RATE_LIMITED
    )


# --- Decision.allowed ---------------------------------------------------------

def test_allowed_is_false_only_for_rejected() -> None:
    req = _req()
    assert Decision.auto_allow(req, "r").allowed is True
    assert Decision.confirmed(req).allowed is True
    assert Decision.reject(req, RejectionCode.BAD_ARITY, "r").allowed is False


# --- ActionRequest.raw_params is immutable -----------------------------------

def test_raw_params_setitem_raises_typeerror() -> None:
    # MappingProxyType has no __setitem__ attribute at all, so calling
    # assert_raises(TypeError, req.raw_params.__setitem__, ...) would blow up
    # with AttributeError while evaluating the arguments, before
    # assert_raises even runs. Route through a closure instead.
    req = _req(raw_params={"k": "v"})

    def mutate() -> None:
        req.raw_params["k"] = "v2"

    assert_raises(TypeError, mutate)


def test_raw_params_exposes_no_mutators() -> None:
    req = _req(raw_params={"k": "v"})
    for mutator in ("__setitem__", "update", "pop", "clear", "setdefault", "popitem"):
        assert not hasattr(req.raw_params, mutator), f"raw_params exposes {mutator}"


def test_raw_params_is_a_copy_of_the_original_dict() -> None:
    # __post_init__ wraps `dict(self.raw_params)`, i.e. a copy, before
    # freezing it -- so mutating the dict the caller originally passed in
    # must not reach back into the request.
    original = {"k": "v"}
    req = _req(raw_params=original)
    original["k"] = "changed"
    original["new"] = "added"
    assert req.raw_params["k"] == "v"
    assert "new" not in req.raw_params


# --- Source.trusted ------------------------------------------------------------

def test_source_trusted_flags() -> None:
    # Asserted per-member (and that the member set is exactly this), rather
    # than just "screen_context is False", so a future Source added to the
    # enum forces a decision here instead of silently defaulting to trusted.
    expected = {
        Source.DESKTOP: True,
        Source.PHONE: True,
        Source.SCREEN_CONTEXT: False,
    }
    assert set(Source) == set(expected)
    for member, trusted in expected.items():
        assert member.trusted is trusted, member


# --- ActionRequest has no tier field ------------------------------------------

def test_action_request_has_no_tier_field() -> None:
    field_names = {f.name for f in dataclasses.fields(ActionRequest)}
    assert "tier" not in field_names


def test_action_request_has_no_tier_attribute() -> None:
    req = _req()
    assert not hasattr(req, "tier")
