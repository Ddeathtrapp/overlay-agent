"""Puts `src/` on `sys.path` so tests import `actions` / `dispatch` the same
way `dispatch/cli.py` does, with no packaging changes."""
from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
