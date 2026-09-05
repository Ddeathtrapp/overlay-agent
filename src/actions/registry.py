"""The closed action registry — §1, §2.1. Every entry here is code, in git,
written and reviewed by a human. Nothing appends to this tuple at runtime.
"""
from __future__ import annotations

from typing import Final, Sequence

from actions.handlers.apps import open_application
from actions.handlers.desktops import open_new_desktop
from actions.handlers.power import restart_pc, shutdown_pc
from actions.handlers.settings import open_setting
from actions.handlers.theme import toggle_dark_mode
from actions.params import APP_PARAM, APPS, SETTING_PAGE_PARAM, SettingPage
from actions.schema import Action, Tier

# `toggle_night_light` is permanently retired — §0.1. It is never registered
# under this or any other ID; do not reassign the name.


def _list_options(items: Sequence[str]) -> str:
    """"a, b, or c" — used to build classifier-facing descriptions straight
    from the live tables/enums those actions are parameterized by, instead of
    hand-typing the option names into a string literal. A hand-typed list
    goes stale the moment `APPS` or `SettingPage` changes and nothing would
    catch it; reading the collection at registry-construction time means it
    cannot drift, by construction rather than by discipline.
    """
    items = list(items)
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} or {items[1]}"
    return f"{', '.join(items[:-1])}, or {items[-1]}"


REGISTRY: Final[tuple[Action, ...]] = (
    Action(
        id="toggle_dark_mode",
        tier=Tier.ZERO,
        description="Turn dark mode on or off.",
        params=(),
        reversible=True,
        handler=toggle_dark_mode,
    ),
    Action(
        id="open_new_desktop",
        tier=Tier.ZERO,
        description="Create a new virtual desktop.",
        params=(),
        reversible=True,
        handler=open_new_desktop,
    ),
    Action(
        id="open_application",
        tier=Tier.ONE,
        description=(
            f"Open one of the installed applications: {_list_options(list(APPS))}. "
            f"No other application can be opened this way."
        ),
        params=(APP_PARAM,),
        reversible=True,
        handler=open_application,
    ),
    Action(
        id="open_setting",
        tier=Tier.ONE,
        description=(
            "Open the "
            f"{_list_options([p.name.lower() for p in SettingPage])} "
            "settings page."
        ),
        params=(SETTING_PAGE_PARAM,),
        reversible=True,
        handler=open_setting,
    ),
    Action(
        id="shutdown_pc",
        tier=Tier.TWO,
        description="Shut down the computer.",
        params=(),
        reversible=False,
        handler=shutdown_pc,
    ),
    Action(
        id="restart_pc",
        tier=Tier.TWO,
        description="Restart the computer.",
        params=(),
        reversible=False,
        handler=restart_pc,
    ),
)

_BY_ID: Final[dict[str, Action]] = {action.id: action for action in REGISTRY}


def lookup(action_id: str) -> Action:
    """Fails closed (§2.4): unknown ID raises, never falls back to a guess."""
    try:
        return _BY_ID[action_id]
    except KeyError:
        raise KeyError(f"unknown action id: {action_id!r}") from None
