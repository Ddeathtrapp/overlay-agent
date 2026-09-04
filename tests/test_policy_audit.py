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

from policy.audit import _params_for_log, _safe_action_id, _safe_reason, _safe_utterance
from policy.confirm import ConfirmationReply
from policy.types import ActionRequest, Decision, Outcome, RejectionCode, Source

CANARY = "CANARY-SCREEN-TEXT"
PARAM_CANARY = "CANARY-PASSWORD-9999"
UNKNOWN_ACTION_CANARY = "CANARY-ACTION-9999"


def _request(source: Source, utterance: str | None) -> ActionRequest:
    return ActionRequest(
        action_id="open_setting", raw_params={}, source=source, utterance=utterance
    )


def _request_params(
    source: Source, raw_params: dict[str, object], action_id: str = "open_setting"
) -> ActionRequest:
    return ActionRequest(action_id=action_id, raw_params=raw_params, source=source)


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


# --- _params_for_log(): keys survive, values redact for screen context -----


def test_params_for_log_redacts_values_but_keeps_keys_for_screen_context() -> None:
    request = _request_params(
        Source.SCREEN_CONTEXT, {"app": "CANARY-APP-VALUE", "page": 42}
    )
    result = _params_for_log(request)
    assert set(result.keys()) == {"app", "page"}
    assert all(v == "<redacted>" for v in result.values())


def test_params_for_log_keeps_real_values_for_desktop_and_phone() -> None:
    for source in (Source.DESKTOP, Source.PHONE):
        request = _request_params(source, {"app": "notepad", "count": 3})
        result = _params_for_log(request)
        assert result == {"app": "notepad", "count": "3"}


def test_params_for_log_key_set_identical_redacted_vs_unredacted() -> None:
    raw = {"app": "CANARY-KEYS", "page": "display"}
    redacted = _params_for_log(_request_params(Source.SCREEN_CONTEXT, raw))
    unredacted = _params_for_log(_request_params(Source.DESKTOP, raw))
    assert set(redacted.keys()) == set(unredacted.keys()) == set(raw.keys())


# --- _safe_reason(): rejection detail redacted, code/outcome preserved -----


def test_safe_reason_passes_through_for_desktop_and_phone() -> None:
    for source in (Source.DESKTOP, Source.PHONE):
        request = _request(source, None)
        decision = Decision.reject(
            request,
            RejectionCode.PARAM_REJECTED,
            "app: 'CANARY-REASON-TEXT' is not one of ['calculator', 'notepad']",
        )
        assert _safe_reason(request, decision) == decision.reason


def test_safe_reason_redacts_detail_for_screen_context_with_code() -> None:
    request = _request(Source.SCREEN_CONTEXT, None)
    decision = Decision.reject(
        request,
        RejectionCode.PARAM_REJECTED,
        "app: 'CANARY-REASON-TEXT' is not one of ['calculator', 'notepad']",
    )
    result = _safe_reason(request, decision)
    assert RejectionCode.PARAM_REJECTED.value in result
    assert "CANARY-REASON-TEXT" not in result
    assert result == (
        f"rejected: {RejectionCode.PARAM_REJECTED.value} (detail redacted: untrusted source)"
    )


def test_safe_reason_redacts_for_screen_context_when_code_is_none() -> None:
    request = _request(Source.SCREEN_CONTEXT, None)
    decision = Decision.auto_allow(request, "tier 0: CANARY-AUTO-ALLOW-DETAIL")
    result = _safe_reason(request, decision)
    assert result == f"{Outcome.AUTO_ALLOWED.value} (detail redacted: untrusted source)"
    assert "CANARY-AUTO-ALLOW-DETAIL" not in result


# --- _safe_action_id(): redacted only for SCREEN_CONTEXT + UNKNOWN_ACTION --


def test_safe_action_id_redacts_only_for_screen_context_unknown_action() -> None:
    request = ActionRequest(
        action_id="CANARY-ACTION-ID", raw_params={}, source=Source.SCREEN_CONTEXT
    )
    decision = Decision.reject(
        request, RejectionCode.UNKNOWN_ACTION, f"no action with id {request.action_id!r}"
    )
    assert _safe_action_id(request, decision) == "<redacted>"


def test_safe_action_id_keeps_id_for_screen_context_param_rejected() -> None:
    request = ActionRequest(
        action_id="open_application", raw_params={}, source=Source.SCREEN_CONTEXT
    )
    decision = Decision.reject(
        request, RejectionCode.PARAM_REJECTED, "app: 'x' is not one of [...]"
    )
    assert _safe_action_id(request, decision) == "open_application"


def test_safe_action_id_keeps_id_for_desktop_unknown_action() -> None:
    request = ActionRequest(
        action_id="CANARY-ACTION-ID", raw_params={}, source=Source.DESKTOP
    )
    decision = Decision.reject(
        request, RejectionCode.UNKNOWN_ACTION, f"no action with id {request.action_id!r}"
    )
    assert _safe_action_id(request, decision) == "CANARY-ACTION-ID"


def test_safe_action_id_keeps_id_for_screen_context_allowed_decision() -> None:
    request = ActionRequest(
        action_id="toggle_dark_mode", raw_params={}, source=Source.SCREEN_CONTEXT
    )
    decision = Decision.auto_allow(request, "tier 0: always allowed")
    assert _safe_action_id(request, decision) == "toggle_dark_mode"


# --- end-to-end: param and unknown-action canaries through a real engine ---


def test_screen_context_param_canary_never_reaches_the_audit_file(tmp_path) -> None:
    """A rejected param value (pre-parse, arbitrary text) must not leak into
    `reason` via `ParamRejected`'s message when the source is untrusted."""
    confirmer = StubConfirmer(ConfirmationReply(approved=False))
    engine, _, _ = build_engine(tmp_path, confirmer)

    engine.execute(
        "open_application",
        {"app": PARAM_CANARY},
        source=Source.SCREEN_CONTEXT,
    )

    raw = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert PARAM_CANARY not in raw

    records = [json.loads(line) for line in raw.splitlines() if line.strip()]
    decisions = [r for r in records if r["kind"] == "decision"]
    assert decisions, "expected a decision record"
    record = decisions[0]
    assert set(record["params"].keys()) == {"app"}
    assert record["code"] == "param_rejected"


def test_desktop_param_canary_does_reach_the_audit_file(tmp_path) -> None:
    """Contrast case: same request from a trusted source must NOT be
    redacted, or the SCREEN_CONTEXT result above proves nothing."""
    confirmer = StubConfirmer(ConfirmationReply(approved=False))
    engine, _, _ = build_engine(tmp_path, confirmer)

    engine.execute(
        "open_application",
        {"app": PARAM_CANARY},
        source=Source.DESKTOP,
    )

    raw = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert PARAM_CANARY in raw


def test_screen_context_unknown_action_canary_never_reaches_the_audit_file(tmp_path) -> None:
    """An unrecognised action id is, by definition, arbitrary caller text —
    it must not survive into either `action_id` or `reason` from screen
    context."""
    confirmer = StubConfirmer(ConfirmationReply(approved=False))
    engine, _, _ = build_engine(tmp_path, confirmer)

    engine.execute(
        UNKNOWN_ACTION_CANARY,
        {},
        source=Source.SCREEN_CONTEXT,
    )

    raw = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert UNKNOWN_ACTION_CANARY not in raw

    records = [json.loads(line) for line in raw.splitlines() if line.strip()]
    decisions = [r for r in records if r["kind"] == "decision"]
    assert decisions and decisions[0]["code"] == "unknown_action"
    assert decisions[0]["action_id"] == "<redacted>"


def test_desktop_unknown_action_canary_does_reach_the_audit_file(tmp_path) -> None:
    """Contrast case for the unknown-action canary."""
    confirmer = StubConfirmer(ConfirmationReply(approved=False))
    engine, _, _ = build_engine(tmp_path, confirmer)

    engine.execute(
        UNKNOWN_ACTION_CANARY,
        {},
        source=Source.DESKTOP,
    )

    raw = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert UNKNOWN_ACTION_CANARY in raw


def test_chain_intact_after_redacted_records(tmp_path) -> None:
    """Redaction happens before hashing, so a run mixing redacted and
    unredacted decisions must still verify as an intact chain."""
    confirmer = StubConfirmer(ConfirmationReply(approved=False))
    engine, _, audit = build_engine(tmp_path, confirmer)

    engine.execute("open_application", {"app": PARAM_CANARY}, source=Source.SCREEN_CONTEXT)
    engine.execute("open_application", {"app": PARAM_CANARY}, source=Source.DESKTOP)
    engine.execute(UNKNOWN_ACTION_CANARY, {}, source=Source.SCREEN_CONTEXT)
    engine.execute(UNKNOWN_ACTION_CANARY, {}, source=Source.DESKTOP)

    intact, _ = audit.verify_chain()
    assert intact
