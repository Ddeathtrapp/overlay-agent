"""policy.limits: the sliding-window rate limiter. Zero tests existed for
this module before this file, despite it being the only thing standing
between a spammed action and threat-model.md T8.

Two traps documented up front because they are easy to get backwards:

1. `check()` is "non-mutating" only in the quota sense -- it does not
   consume a slot. It DOES prune expired timestamps internally (it has to,
   to compute `remaining` correctly). Tests here assert the security
   property (`remaining` is stable across repeated `check()` calls, and
   never drops without an intervening `record()`), not that the internal
   deque is byte-for-byte untouched.

2. Time is patched narrowly. `limits.py` does `import time` at module
   scope and calls `time.monotonic()`, so tests replace the `time`
   NAME inside the `limits` module namespace with a fake object, never
   `time.monotonic` globally -- pytest's own timing depends on the real
   clock.
"""
from __future__ import annotations

from _helpers import assert_raises

from policy import limits
from policy.limits import (
    TIER_DEFAULTS,
    NoLimitConfigured,
    RateLimit,
    RateLimiter,
    default_for_tier,
)


class _FakeTime:
    """Stands in for the `time` module inside `limits`'s namespace. Only
    `monotonic()` is needed -- that is the only function `limits.py` calls
    on it."""

    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now


# --- RateLimit: fails closed on nonsensical configuration -------------------


def test_rate_limit_rejects_zero_max_calls() -> None:
    assert_raises(ValueError, RateLimit, 0, 60)


def test_rate_limit_rejects_negative_max_calls() -> None:
    assert_raises(ValueError, RateLimit, -1, 60)


def test_rate_limit_rejects_zero_window_seconds() -> None:
    assert_raises(ValueError, RateLimit, 5, 0)


def test_rate_limit_rejects_negative_window_seconds() -> None:
    assert_raises(ValueError, RateLimit, 5, -1)


# --- default_for_tier: §12.2 values, fails closed for unknown tiers --------


def test_default_for_tier_matches_declared_values() -> None:
    assert default_for_tier(0) == RateLimit(max_calls=10, window_seconds=60)
    assert default_for_tier(1) == RateLimit(max_calls=5, window_seconds=60)
    assert default_for_tier(2) == RateLimit(max_calls=1, window_seconds=600)
    # TIER_DEFAULTS itself must agree -- default_for_tier is not allowed to
    # drift from the table it is supposed to be reading.
    assert TIER_DEFAULTS[0] == default_for_tier(0)
    assert TIER_DEFAULTS[1] == default_for_tier(1)
    assert TIER_DEFAULTS[2] == default_for_tier(2)


def test_default_for_tier_unknown_tier_raises_no_limit_configured() -> None:
    assert_raises(NoLimitConfigured, default_for_tier, 3)
    assert_raises(NoLimitConfigured, default_for_tier, -1)


# --- limit_for() / check(): unknown action fails closed, not KeyError ------


def test_limit_for_unknown_action_raises_no_limit_configured() -> None:
    limiter = RateLimiter({})
    assert_raises(NoLimitConfigured, limiter.limit_for, "no_such_action")


def test_check_unknown_action_raises_no_limit_configured() -> None:
    limiter = RateLimiter({})
    assert_raises(NoLimitConfigured, limiter.check, "no_such_action")


# --- check(): non-mutating in the quota sense (trap 1) ----------------------


def test_repeated_check_returns_the_same_remaining_without_a_record() -> None:
    limiter = RateLimiter({"a": RateLimit(max_calls=5, window_seconds=60)})
    first = limiter.check("a")
    second = limiter.check("a")
    third = limiter.check("a")
    assert first.remaining == second.remaining == third.remaining == 5
    assert first.allowed is True


def test_check_never_decreases_remaining_without_an_intervening_record(monkeypatch) -> None:
    fake = _FakeTime()
    monkeypatch.setattr(limits, "time", fake)
    limiter = RateLimiter({"a": RateLimit(max_calls=5, window_seconds=60)})
    limiter.record("a")
    seen = []
    for _ in range(3):
        seen.append(limiter.check("a").remaining)
        fake.now += 1  # still well inside the window
    assert len(set(seen)) == 1, "remaining changed with no intervening record()"


# --- record(): reflected by the next check() --------------------------------


def test_record_then_check_reflects_the_new_count() -> None:
    limiter = RateLimiter({"a": RateLimit(max_calls=3, window_seconds=60)})
    assert limiter.check("a").remaining == 3
    limiter.record("a")
    assert limiter.check("a").remaining == 2
    limiter.record("a")
    assert limiter.check("a").remaining == 1
    limiter.record("a")
    status = limiter.check("a")
    assert status.remaining == 0
    assert status.allowed is False


# --- exceeding the limit -----------------------------------------------------


def test_exceeding_the_limit_is_not_allowed_with_positive_retry_after() -> None:
    limiter = RateLimiter({"a": RateLimit(max_calls=1, window_seconds=60)})
    limiter.record("a")
    status = limiter.check("a")
    assert status.allowed is False
    assert status.remaining == 0
    assert status.retry_after > 0


# --- only ALLOWED executions are recorded -----------------------------------


def test_check_on_an_already_exhausted_action_does_not_extend_the_window(monkeypatch) -> None:
    """If `check()` recorded anything, spamming a rejected action would keep
    resetting its own window and the user would never regain a slot -- the
    denial-of-service `record()`'s docstring warns about. Pin the negative:
    repeated `check()` calls on an exhausted action must not push
    `retry_after` back out.
    """
    fake = _FakeTime()
    monkeypatch.setattr(limits, "time", fake)
    limiter = RateLimiter({"a": RateLimit(max_calls=1, window_seconds=10)})
    limiter.record("a")

    first = limiter.check("a")
    assert first.allowed is False

    fake.now += 5
    second = limiter.check("a")
    assert second.allowed is False
    assert second.retry_after < first.retry_after, (
        "retry_after must count down from the original record(), not reset "
        "on every rejected check()"
    )


# --- the window slides --------------------------------------------------------


def test_window_slides_past_expiry_and_allows_again(monkeypatch) -> None:
    fake = _FakeTime()
    monkeypatch.setattr(limits, "time", fake)
    limiter = RateLimiter({"a": RateLimit(max_calls=1, window_seconds=10)})

    limiter.record("a")
    assert limiter.check("a").allowed is False

    fake.now += 10.001  # strictly past the window
    status = limiter.check("a")
    assert status.allowed is True
    assert status.remaining == 1
