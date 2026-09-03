"""policy.audit: `_safe_utterance` is the whole T9 mitigation (screen
content must never become a permanent on-disk record of whatever was on the
monitor -- a password manager, an email, a private document) and it had no
tests before this file.

Every `AuditLog` here is constructed with an explicit `tmp_path`-derived
path, per `test_test_hygiene.py`'s guard -- never bare, which would touch
the real `%LOCALAPPDATA%\\overlay-agent\\audit.jsonl`.
"""
from __future__ import annotations

import json

from _helpers import StubConfirmer, build_engine

from policy.audit import _safe_utterance
from policy.confirm import ConfirmationReply
from policy.types import ActionRequest, Source

CANARY = "CANARY-SCREEN-TEXT"


def _request(source: Source, utterance: str | None) -> ActionRequest:
    return ActionRequest(
        action_id="open_setting", raw_params={}, source=source, utterance=utterance
    )


# --- _safe_utterance(): the redaction rule itself --------------------------


def test_safe_utterance_is_none_for_screen_context() -> None:
    request = _request(Source.SCREEN_CONTEXT, CANARY)
    assert _safe_utterance(request) is None


def test_safe_utterance_passes_through_for_desktop_and_phone() -> None:
    for source in (Source.DESKTOP, Source.PHONE):
        request = _request(source, "open display settings")
        assert _safe_utterance(request) == "open display settings"


def test_safe_utterance_none_utterance_stays_none_for_trusted_sources() -> None:
    # Nothing to redact, but also nothing to invent.
    request = _request(Source.DESKTOP, None)
    assert _safe_utterance(request) is None


# --- end-to-end: the canary must not reach the file, full stop -------------


def test_screen_context_utterance_never_reaches_the_audit_file(tmp_path) -> None:
    """The regression this file exists to prevent: run a SCREEN_CONTEXT
    request with a distinctive utterance through a real engine, then read
    the actual `.jsonl` bytes back off disk and assert the canary appears
    NOWHERE in the file -- not in an `utterance` field, not anywhere else.

    Records are flat on disk (`decision()`/`note()` spread the payload into
    the top-level JSON object -- there is no nested `"payload"` key), so a
    whole-file substring search is the right check, not a field lookup.
    """
    confirmer = StubConfirmer(ConfirmationReply(approved=False))
    engine, _, _ = build_engine(tmp_path, confirmer)

    engine.execute(
        "open_setting",
        {"page": "display"},
        source=Source.SCREEN_CONTEXT,
        utterance=CANARY,
    )

    log_path = tmp_path / "audit.jsonl"
    raw = log_path.read_text(encoding="utf-8")
    assert CANARY not in raw

    records = [json.loads(line) for line in raw.splitlines() if line.strip()]
    assert records, "expected at least one record to have been written"
    decisions = [r for r in records if r["kind"] == "decision"]
    assert decisions and decisions[0]["action_id"] == "open_setting"
    for record in records:
        assert record.get("utterance") != CANARY
        assert CANARY not in json.dumps(record)


def test_desktop_utterance_does_reach_the_audit_file(tmp_path) -> None:
    """Contrast case: proves the SCREEN_CONTEXT test above is a real
    redaction, not a coincidence of nothing ever being written -- a trusted
    source's utterance IS expected to show up in the log.
    """
    confirmer = StubConfirmer(ConfirmationReply(approved=False))
    engine, _, _ = build_engine(tmp_path, confirmer)

    engine.execute(
        "open_setting",
        {"page": "display"},
        source=Source.DESKTOP,
        utterance="CANARY-DESKTOP-TEXT",
    )

    raw = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "CANARY-DESKTOP-TEXT" in raw
