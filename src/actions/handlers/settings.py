"""open_setting — Tier 1.

Design test (§7): an attacker who can invoke this with any valid parameter
opens one of six Settings pages (display, sound, notifications, power,
bluetooth, personalization). None of them are security-relevant or a step
toward broader system control — Windows Security, Firewall, UAC, BitLocker,
Sign-in options, Apps, and Network are excluded by not existing in
`SettingPage` (§9): Apps is where software is uninstalled, Network is one
click from proxy configuration, which redirects traffic. Opening a settings
page is not itself a mutation. Acceptable at any moment.

The URI is read off the enum member's hardcoded value — never built from
the raw parameter, which only ever selects a member name (see
`EnumParam.parse` in params.py).
"""
from __future__ import annotations

import os

from actions.params import SettingPage


def open_setting(page: SettingPage) -> None:
    os.startfile(page.value)
