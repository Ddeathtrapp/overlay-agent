"""Append-only audit log.

Implements the record shape in action-registry.md §6. Every request is
logged BEFORE the handler runs, so a process that dies mid-action still
leaves evidence the action was attempted.

This is what makes threat-model.md T5 (stolen phone or token) survivable:
the attacker is bounded by the registry, and the log is how you find out
what they did.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from .types import ActionRequest, Decision, Outcome, RejectionCode, Source

log = logging.getLogger(__name__)

MAX_BYTES = 5 * 1024 * 1024
KEEP_ROTATIONS = 5
GENESIS = "0" * 16


class AuditWriteFailed(Exception):
    """Raised when a record could not be written.

    engine.py treats this as fatal for the request: no log, no action. An
    unlogged execution is an unaccountable one, and the whole value of the
    log is that it is complete. Disk-full therefore stops the assistant
    rather than silently downgrading it to unaudited operation.
    """


def default_log_path() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home())
    return Path(base) / "overlay-agent" / "audit.jsonl"


# --------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------


def _safe_utterance(request: ActionRequest) -> str | None:
    """Utterance text, but never from an untrusted source.

    Screen-context text is whatever happened to be on the monitor: a
    password manager, an email, a private document. Writing it to a
    long-lived file on disk would turn the audit log into a keylogger
    with extra steps.

    Parameters are always safe to log by construction — §3 restricts them
    to enum members, bounded ints, and whitelist keys, none of which can
    carry arbitrary text. That property is what lets this log be detailed
    and safe at the same time.
    """
    if request.source is Source.SCREEN_CONTEXT:
        return None
    return request.utterance


def _params_for_log(request: ActionRequest) -> dict[str, str]:
    """Parameter values, redacted when the source is untrusted.

    §3 restricts VALID parameters to enum members, bounded ints, and
    whitelist keys — all registry constants, all safe. But this logs
    `raw_params`, which is pre-parse: a rejected value is arbitrary text
    that never had to satisfy any of that. From screen context, arbitrary
    text is whatever was on the monitor.

    Keys are always logged. They come from the action's own ParamSpec.
    """
    if request.source is Source.SCREEN_CONTEXT:
        return {str(k): "<redacted>" for k in request.raw_params}
    return {str(k): str(v) for k, v in request.raw_params.items()}


def _safe_reason(request: ActionRequest, decision: Decision) -> str:
    """Rejection reasons embed the offending value — `ParamRejected` says
    which value failed, which is the whole point of the message and
    exactly what must not be written for an untrusted source. The code
    already carries the category, so nothing diagnostic is lost."""
    if request.source is not Source.SCREEN_CONTEXT:
        return decision.reason
    if decision.code is not None:
        return f"rejected: {decision.code.value} (detail redacted: untrusted source)"
    return f"{decision.outcome.value} (detail redacted: untrusted source)"


def _safe_action_id(request: ActionRequest, decision: Decision) -> str:
    """An UNKNOWN_ACTION id is by definition not in the registry — it is
    whatever the caller sent. From screen context that is arbitrary text.
    Every other id is a registry constant and always safe to log."""
    if (
        request.source is Source.SCREEN_CONTEXT
        and decision.code is RejectionCode.UNKNOWN_ACTION
    ):
        return "<redacted>"
    return request.action_id

# --------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Record:
    kind: str  # "decision" | "completion"
    request_id: str
    ts: datetime
    payload: dict

    def to_json(self, prev_hash: str) -> dict:
        body = {
            "kind": self.kind,
            "request_id": self.request_id,
            "ts": self.ts.isoformat(),
            "prev": prev_hash,
            **self.payload,
        }
        body["hash"] = _chain_hash(prev_hash, body)
        return body


def _chain_hash(prev_hash: str, body: Mapping[str, object]) -> str:
    """Link each record to the one before it.

    This detects casual tampering — a deleted or edited line breaks the
    chain. It is NOT tamper-proof: there is no secret, so anyone who can
    edit the file can recompute the whole chain. Detecting deletion is
    still worth the ten lines; claiming more would be dishonest.
    """
    material = json.dumps(
        {k: v for k, v in body.items() if k != "hash"}, sort_keys=True, default=str
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


# --------------------------------------------------------------------------
# Log
# --------------------------------------------------------------------------


class AuditLog:
    """Append-only JSONL. One line per event, never rewritten.

    Two records per request rather than one: a `decision` written before
    execution, and a `completion` written after. §6 sketches a single
    record carrying both, but a single record cannot be both written
    beforehand and contain the outcome. Two append-only records preserve
    the ordering guarantee that matters.
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or default_log_path()
        self._lock = threading.Lock()
        self._prev_hash = self._read_last_hash()

    # -- writes ------------------------------------------------------------

    def decision(self, request: ActionRequest, decision: Decision, tier: int | None) -> None:
        """Write before the handler runs. Rejections are logged too — a
        rejected request is often the more interesting one."""
        self._append(
            Record(
                kind="decision",
                request_id=request.request_id,
                ts=datetime.now(timezone.utc),
                payload={
                    "action_id": _safe_action_id(request, decision),
                    "params": _params_for_log(request),
                    "tier": tier,
                    "source": request.source.value,
                    "utterance": _safe_utterance(request),
                    "decision": decision.outcome.value,
                    "code": decision.code.value if decision.code else None,
                    "reason": _safe_reason(request, decision),
                },
            )
        )

    def completion(self, request: ActionRequest, ok: bool, error: str | None = None) -> None:
        """Write after the handler returns or raises."""
        self._append(
            Record(
                kind="completion",
                request_id=request.request_id,
                ts=datetime.now(timezone.utc),
                payload={"outcome": "ok" if ok else "error", "error": error},
            )
        )

    def note(self, event: str, detail: Mapping[str, object] | None = None) -> None:
        """Non-request events worth recording: exception granted or
        revoked, store reset, service start."""
        self._append(
            Record(
                kind="note",
                request_id="-",
                ts=datetime.now(timezone.utc),
                payload={"event": event, **(dict(detail) if detail else {})},
            )
        )

    # -- reads -------------------------------------------------------------

    def verify_chain(self) -> tuple[bool, int]:
        """Walk the chain. Returns (intact, line_number_of_first_break).

        A break means a line was deleted or edited. It does not identify
        who did it, and a determined editor can recompute the chain.
        """
        prev = GENESIS
        try:
            with self._path.open("r", encoding="utf-8") as fh:
                for n, line in enumerate(fh, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    body = json.loads(line)
                    if body.get("prev") != prev:
                        return False, n
                    if body.get("hash") != _chain_hash(body["prev"], body):
                        return False, n
                    prev = body["hash"]
        except FileNotFoundError:
            return True, 0
        except Exception:
            log.exception("audit chain unreadable")
            return False, 0
        return True, 0

    # -- internals ---------------------------------------------------------

    def _read_last_hash(self) -> str:
        try:
            with self._path.open("r", encoding="utf-8") as fh:
                last = None
                for line in fh:
                    if line.strip():
                        last = line
                if last:
                    return json.loads(last).get("hash", GENESIS)
        except FileNotFoundError:
            pass
        except Exception:
            log.exception("could not read tail of audit log; starting a new chain")
        return GENESIS

    def _append(self, record: Record) -> None:
        with self._lock:
            try:
                self._rotate_if_needed()
                self._path.parent.mkdir(parents=True, exist_ok=True)
                body = record.to_json(self._prev_hash)
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(body, default=str) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())  # survive a crash mid-action
                self._prev_hash = body["hash"]
            except Exception as exc:
                raise AuditWriteFailed(f"could not write audit record: {exc}") from exc

    def _rotate_if_needed(self) -> None:
        """Caller holds the lock. The chain continues across rotations —
        the new file's first record still points at the old file's last."""
        try:
            if not self._path.exists() or self._path.stat().st_size < MAX_BYTES:
                return
        except OSError:
            return
        oldest = self._path.with_suffix(f".jsonl.{KEEP_ROTATIONS}")
        if oldest.exists():
            oldest.unlink()
        for i in range(KEEP_ROTATIONS - 1, 0, -1):
            src = self._path.with_suffix(f".jsonl.{i}")
            if src.exists():
                src.replace(self._path.with_suffix(f".jsonl.{i + 1}"))
        self._path.replace(self._path.with_suffix(".jsonl.1"))