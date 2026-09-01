"""Parameter kinds — §3 of the action registry. There is no fourth kind.

Each ParamSpec turns a raw string into a typed value, or rejects it via
`ParamRejected`. `parse()` lives here — not in the CLI, not in the handler —
so handlers stay validation-free (§4) and Phase 2's policy engine can reuse
the exact same parser instead of growing a second copy that drifts from
this one.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Final


class ParamRejected(Exception):
    """Raised by parse() for any invalid raw value. Callers fail closed:
    reject, never coerce, never fall back to a default (§2.4)."""


@dataclass(frozen=True)
class EnumParam:
    """§3 `Enum` kind. `raw` is matched against enum MEMBER NAMES only,
    case-insensitively — never against `.value`, which for SettingPage is a
    URI literal an attacker should not get to probe by string."""
    name: str
    enum: type[Enum]

    def parse(self, raw: str) -> Enum:
        # Reject non-str before touching it — Phase 2 hands raw values in
        # from parsed JSON, where a non-string is ordinary, and `.upper()`
        # on anything else raises AttributeError instead of failing closed
        # with ParamRejected (§2.4: reject and log, not crash uncaught).
        if not isinstance(raw, str):
            raise ParamRejected(f"{self.name}: expected str, got {type(raw).__name__}")
        try:
            return self.enum[raw.upper()]
        except KeyError:
            raise ParamRejected(
                f"{self.name}: {raw!r} is not one of "
                f"{sorted(self.enum.__members__)}"
            ) from None


@dataclass(frozen=True)
class BoundedIntParam:
    """§3 `BoundedInt` kind: strict int parse, then range check, reject on
    either. No Phase 1 action uses this — it exists because §3 defines the
    kind, not because §9 has a use for it. Do not invent set_volume."""
    name: str
    min: int
    max: int

    def parse(self, raw: str) -> int:
        # Reject non-str before int() — this must run before any numeric
        # coercion, not just before the try, or a float like 3.7 silently
        # truncates to 3 instead of being rejected (§2.4: never coerce).
        # Do not widen this to accept int/float "helpfully"; a non-string
        # raw is exactly what a malformed Phase 2 ActionRequest looks like.
        if not isinstance(raw, str):
            raise ParamRejected(f"{self.name}: expected str, got {type(raw).__name__}")
        try:
            value = int(raw)
        except (TypeError, ValueError):
            raise ParamRejected(f"{self.name}: {raw!r} is not an integer") from None
        if not (self.min <= value <= self.max):
            raise ParamRejected(
                f"{self.name}: {value} is outside [{self.min}, {self.max}]"
            )
        return value


@dataclass(frozen=True)
class WhitelistKeyParam:
    """§3 `WhitelistKey` kind: `raw` must be a literal key of `table`.
    Returns the KEY itself, never a value derived from it — the handler does
    its own dict lookup (§0.2), so this class never touches a Path."""
    name: str
    table: Mapping

    def parse(self, raw: str) -> str:
        # Reject non-str before the membership test — an unhashable raw
        # (e.g. a list) raises TypeError out of `in`, not ParamRejected
        # (§2.4: reject and log, not crash uncaught).
        if not isinstance(raw, str):
            raise ParamRejected(f"{self.name}: expected str, got {type(raw).__name__}")
        if raw not in self.table:
            raise ParamRejected(
                f"{self.name}: {raw!r} is not one of {sorted(self.table)}"
            )
        return raw


# Union, not a base class — §3's "no fourth kind" rule is easiest to keep
# true when there is nothing to subclass to sneak a fourth kind in under.
ParamSpec = EnumParam | BoundedIntParam | WhitelistKeyParam


class SettingPage(Enum):
    """Hardcoded `ms-settings:` URI literals (§9). Windows Security,
    Firewall, UAC, BitLocker, Sign-in options, Apps, and Network are
    excluded by absence from this enum — no denylist, because
    unrepresentable beats checked."""
    DISPLAY = "ms-settings:display"
    SOUND = "ms-settings:sound"
    NOTIFICATIONS = "ms-settings:notifications"
    POWER = "ms-settings:powersleep"
    BLUETOOTH = "ms-settings:bluetooth"
    PERSONALIZATION = "ms-settings:personalization"


_APPS: Final[dict[str, Path]] = {
    "notepad": Path(r"C:\Windows\System32\notepad.exe"),
    "calculator": Path(r"C:\Windows\System32\calc.exe"),
    # extend by hand, one reviewed line at a time — §0.2
}

# §2.1: "the registry is closed at build time." `Final` is a type-checker
# annotation only — it does not stop in-process code from mutating a plain
# dict at runtime, and APPS is the one table in this module a mutation of
# which becomes an arbitrary-launch primitive (§0.2). Wrap it so mutation
# raises TypeError instead of silently succeeding.
APPS: Final[Mapping[str, Path]] = MappingProxyType(_APPS)


APP_PARAM: Final = WhitelistKeyParam("app", APPS)
SETTING_PAGE_PARAM: Final = EnumParam("page", SettingPage)
