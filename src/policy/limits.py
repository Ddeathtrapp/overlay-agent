"""Per-action rate limiting.

Implements action-registry.md §12.2. Each action carries its own limit, so
one spammed Tier 0 action cannot starve everything else — that is the
failure mode threat-model.md T8 describes.

This module counts. It does not decide: engine.py asks whether an action is
over its limit and turns the answer into a Decision. The limit VALUES live
on the registry entry, not here; this module is handed them.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Mapping

# Hard ceiling on retained timestamps per action. A limit of N only ever
# needs N of them; the slack absorbs a mid-window config change without
# letting a spammed action grow memory without bound.
_MAX_RETAINED = 64


class NoLimitConfigured(Exception):
    """Raised when an action has no rate limit declared.

    Fails closed by refusing to answer rather than assuming "unlimited".
    Every registered action must declare a limit; a missing one is a
    registry defect, not a permission to run freely.
    """


@dataclass(frozen=True, slots=True)
class RateLimit:
    """How often an action may run. §12.2 defaults: tier 0 -> 10/60s,
    tier 1 -> 5/60s, tier 2 -> 1/600s."""

    max_calls: int
    window_seconds: float

    def __post_init__(self) -> None:
        if self.max_calls < 1:
            raise ValueError("max_calls must be at least 1")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

    def describe(self) -> str:
        if self.window_seconds == 60:
            return f"{self.max_calls}/min"
        return f"{self.max_calls} per {self.window_seconds:g}s"


@dataclass(frozen=True, slots=True)
class LimitStatus:
    """Answer to 'may this run right now?'"""

    allowed: bool
    remaining: int
    retry_after: float  # seconds until the next slot frees; 0.0 when allowed

    def reason(self, action_id: str, limit: RateLimit) -> str:
        return (
            f"{action_id} is rate limited at {limit.describe()}; "
            f"retry in {self.retry_after:.0f}s"
        )


class RateLimiter:
    """Sliding window of recent executions, per action.

    Two properties worth stating outright, because both are security
    behaviour rather than implementation detail:

    1. Time comes from `time.monotonic()`, never the wall clock. A wall
       clock can be moved backwards — by NTP, by DST, or by a user — and
       a backwards jump would hand out free slots. Tier 2's one-per-ten-
       minutes is exactly the limit worth attacking that way.

    2. Only ALLOWED executions are recorded. Counting rejected attempts
       would let anything that can spam requests lock the user out of
       their own machine: each rejection would extend the window, so the
       limiter would amplify a nuisance into a denial of service instead
       of containing it.

    Known limitation, accepted: the window is in memory, so restarting the
    process clears it. An attacker able to restart the process already has
    code execution and does not need this bypass, and persisting it would
    mean a reboot could leave a legitimate shutdown blocked for ten minutes.
    See threat-model.md T8 — this becomes in-scope at Phase 5.
    """

    def __init__(self, limits: Mapping[str, RateLimit]) -> None:
        self._limits = dict(limits)
        self._lock = threading.Lock()
        self._calls: dict[str, deque[float]] = {}

    # -- queries -----------------------------------------------------------

    def limit_for(self, action_id: str) -> RateLimit:
        try:
            return self._limits[action_id]
        except KeyError:
            raise NoLimitConfigured(
                f"{action_id} has no rate limit declared in the registry"
            ) from None

    def check(self, action_id: str) -> LimitStatus:
        """Non-mutating. Ask before confirming, so the user is never
        prompted for something that would be refused anyway.
        """
        limit = self.limit_for(action_id)
        now = time.monotonic()
        with self._lock:
            window = self._prune(action_id, now, limit)
            used = len(window)
            if used < limit.max_calls:
                return LimitStatus(True, limit.max_calls - used, 0.0)
            oldest = window[0]
            retry_after = max(0.0, (oldest + limit.window_seconds) - now)
            return LimitStatus(False, 0, retry_after)

    # -- mutation ----------------------------------------------------------

    def record(self, action_id: str) -> None:
        """Log one execution. Call AFTER the decision is allow, never before.

        Ordering matters: recording before confirmation would let a
        declined prompt consume quota, so repeatedly saying "no" would
        eventually lock out saying "yes".
        """
        limit = self.limit_for(action_id)
        now = time.monotonic()
        with self._lock:
            window = self._prune(action_id, now, limit)
            window.append(now)
            while len(window) > _MAX_RETAINED:
                window.popleft()

    def reset(self, action_id: str | None = None) -> None:
        """Clear the window for one action, or all of them. Test and
        maintenance use only — nothing in the dispatch path calls this."""
        with self._lock:
            if action_id is None:
                self._calls.clear()
            else:
                self._calls.pop(action_id, None)

    # -- internals ---------------------------------------------------------

    def _prune(self, action_id: str, now: float, limit: RateLimit) -> deque[float]:
        """Drop timestamps that have aged out. Caller holds the lock."""
        window = self._calls.setdefault(action_id, deque())
        cutoff = now - limit.window_seconds
        while window and window[0] <= cutoff:
            window.popleft()
        return window


# --------------------------------------------------------------------------
# Defaults
# --------------------------------------------------------------------------

# §12.2 tier defaults. The registry may override per action; these exist so
# that a newly added action has a sane limit before anyone thinks about it,
# NOT as a substitute for declaring one.
TIER_DEFAULTS: Mapping[int, RateLimit] = {
    0: RateLimit(max_calls=10, window_seconds=60),
    1: RateLimit(max_calls=5, window_seconds=60),
    2: RateLimit(max_calls=1, window_seconds=600),
}


def default_for_tier(tier: int) -> RateLimit:
    try:
        return TIER_DEFAULTS[int(tier)]
    except (KeyError, TypeError, ValueError):
        raise NoLimitConfigured(f"no default rate limit for tier {tier!r}") from None