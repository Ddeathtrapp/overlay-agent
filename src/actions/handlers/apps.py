"""open_application — Tier 1. §0.2: highest-risk action in the registry.

Design test (§7): an attacker who can invoke this with any valid parameter
launches notepad.exe or calc.exe — both are standard, unprivileged, sandboxed
system binaries. Acceptable only because `APPS` is a closed, hand-reviewed
table; growing it carelessly is the actual risk (see §0.2), not this file.

The parameter is a `WhitelistKey` (`AppKey` in the registry). It is never
joined, formatted, or concatenated — the handler does exactly one dict
lookup and passes the resulting `Path` to `subprocess.Popen` as a
single-element list, `shell=False`.
"""
from __future__ import annotations

import subprocess

from actions.params import APPS


def open_application(app: str) -> None:
    subprocess.Popen([str(APPS[app])], shell=False, close_fds=True)
