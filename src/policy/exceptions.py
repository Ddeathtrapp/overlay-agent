"""Standing exceptions — the "always allow" store.

Implements action-registry.md §12.1: exceptions are permanent until
revoked, scoped to an action AND its exact parameter values, and Tier 2
can never be excepted.

The store answers exactly one question: "has the human already said yes
to this precise thing?" It does not know about tiers beyond refusing to
store Tier 2, does not know about rate limits, and cannot grant anything
on its own — engine.py calls grant() only after a human has confirmed.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Iterable, Mapping

log = logging.getLogger(__name__)

# A parameter signature: the action's parameters, canonicalised and sorted,
# so {"a": 1, "b": 2} and {"b": 2, "a": 1} are the same exception.
Signature = tuple[tuple[str, str], ...]

TIER_TWO = 2


class ExceptionRefused(Exception):
    """Raised when a grant is not storable. Never returns False — a
    silently-dropped grant would leave the user believing a permission
    exists when it does not."""


# --------------------------------------------------------------------------
# Canonicalisation
# --------------------------------------------------------------------------


def _canonical(value: object) -> str:
    """Render one parsed parameter value as a stable string.

    Takes PARSED values (what spec.parse returned), not raw input, so that
    "display" and "DISPLAY" — if the enum parser accepts both — collapse to
    the same signature instead of being two different exceptions.

    Unsupported types raise rather than falling back to str(). str() on an
    arbitrary object can embed a memory address, which would produce a
    signature that never matches again and an exception the user can see
    but never use.
    """
    if isinstance(value, Enum):
        return f"enum:{value.name}"
    if isinstance(value, bool):  # before int — bool is a subclass of int
        raise ExceptionRefused("bool parameters are not a defined param kind")
    if isinstance(value, int):
        return f"int:{value}"
    if isinstance(value, str):
        return f"str:{value}"
    raise ExceptionRefused(
        f"cannot canonicalise parameter of type {type(value).__name__}"
    )


def signature(params: Mapping[str, object]) -> Signature:
    """Build a comparable signature from parsed parameters.

    A parameterless action gets an empty signature. That is still an exact
    match, not a wildcard — there is nothing to vary.
    """
    return tuple(sorted((name, _canonical(v)) for name, v in params.items()))


# --------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Grant:
    """One standing exception. Displayed to the user verbatim by list()."""

    action_id: str
    signature: Signature
    granted_at: datetime

    def describe(self) -> str:
        if not self.signature:
            return self.action_id
        args = " ".join(f"{n}={v.split(':', 1)[1]}" for n, v in self.signature)
        return f"{self.action_id} {args}"

    def to_json(self) -> dict:
        return {
            "action_id": self.action_id,
            "params": [list(pair) for pair in self.signature],
            "granted_at": self.granted_at.isoformat(),
        }

    @classmethod
    def from_json(cls, raw: dict) -> "Grant":
        return cls(
            action_id=raw["action_id"],
            signature=tuple((str(n), str(v)) for n, v in raw["params"]),
            granted_at=datetime.fromisoformat(raw["granted_at"]),
        )


# --------------------------------------------------------------------------
# Store
# --------------------------------------------------------------------------


def default_store_path() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home())
    return Path(base) / "overlay-agent" / "exceptions.json"


class ExceptionStore:
    """Persistent set of standing exceptions.

    Not a cache. If loading fails for any reason the store starts EMPTY,
    which means every action confirms. That is the fail-closed direction:
    a corrupt file must never be read as "allow everything".
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or default_store_path()
        self._lock = threading.Lock()
        self._grants: dict[tuple[str, Signature], Grant] = {}
        self._load()

    # -- queries -----------------------------------------------------------

    def matches(self, action_id: str, params: Mapping[str, object]) -> bool:
        """True only if this exact action with these exact values was granted.

        There is no wildcard form. Not "wildcards are rejected" — there is
        no way to express one, so no check can be forgotten.
        """
        try:
            key = (action_id, signature(params))
        except ExceptionRefused:
            return False  # uncanonicalisable input cannot match anything
        with self._lock:
            return key in self._grants

    def list(self) -> list[Grant]:
        """Every active exception, newest first.

        §12.1 traded time-based expiry for inspectability: standing
        permissions that cannot be seen are the actual risk. This method
        is that trade being honoured, so it is part of the security
        contract rather than a convenience.
        """
        with self._lock:
            return sorted(self._grants.values(), key=lambda g: g.granted_at, reverse=True)

    # -- mutations ---------------------------------------------------------

    def grant(self, action_id: str, tier: int, params: Mapping[str, object]) -> Grant:
        """Record a standing exception. Caller must already have confirmed
        with a human — this method does not ask anyone anything.
        """
        if tier >= TIER_TWO:
            raise ExceptionRefused(
                f"{action_id} is tier {tier}; tier 2 actions can never be excepted"
            )
        sig = signature(params)  # raises on uncanonicalisable values
        grant = Grant(action_id, sig, datetime.now(timezone.utc))
        with self._lock:
            self._grants[(action_id, sig)] = grant
            self._save()
        log.info("exception granted: %s", grant.describe())
        return grant

    def revoke(self, action_id: str, params: Mapping[str, object]) -> bool:
        """Remove one exception. Returns False if it was not there."""
        try:
            key = (action_id, signature(params))
        except ExceptionRefused:
            return False
        with self._lock:
            removed = self._grants.pop(key, None)
            if removed is not None:
                self._save()
        if removed is not None:
            log.info("exception revoked: %s", removed.describe())
        return removed is not None

    def revoke_all(self) -> int:
        """Remove every exception. Returns how many were removed."""
        with self._lock:
            count = len(self._grants)
            self._grants.clear()
            self._save()
        log.info("all %d exceptions revoked", count)
        return count

    def prune_unknown(self, known_action_ids: Iterable[str]) -> int:
        """Drop exceptions for actions no longer in the registry.

        action-registry.md §4 retires IDs permanently, so a stale grant can
        never be re-attached to a different action. This is hygiene for
        list(), not a security control — but a store full of dead entries
        is one the user stops reading, which defeats §12.1.
        """
        known = set(known_action_ids)
        with self._lock:
            dead = [k for k in self._grants if k[0] not in known]
            for k in dead:
                self._grants.pop(k)
            if dead:
                self._save()
        return len(dead)

    # -- persistence -------------------------------------------------------

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            for entry in raw:
                g = Grant.from_json(entry)
                self._grants[(g.action_id, g.signature)] = g
        except Exception:
            # Fail closed: an unreadable store means no exceptions, which
            # means everything confirms. Loud, but safe.
            self._grants.clear()
            log.exception(
                "exception store at %s is unreadable; starting empty "
                "(every action will require confirmation)",
                self._path,
            )

    def _save(self) -> None:
        """Atomic write. Caller holds the lock."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".json.tmp")
        payload = [g.to_json() for g in self._grants.values()]
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(tmp, self._path)  # atomic on Windows and POSIX