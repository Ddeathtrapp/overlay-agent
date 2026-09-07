"""Append-only audit log.

Implements the record shape in action-registry.md §6. Every request is
logged BEFORE the handler runs, so a process that dies mid-action still
leaves evidence the action was attempted.

This is what makes threat-model.md T5 (stolen phone or token) survivable:
the attacker is bounded by the registry, and the log is how you find out
what they did.

Cross-process chaining (KI-2)
-----------------------------
The hash chain is inherently sequential: each record links to the one
before it. `_prev_hash` used to be cached at construction and the only
mutual exclusion was a per-process `threading.Lock`, so two processes
both appended from the same predecessor and produced a permanent `prev`
mismatch — indistinguishable from tampering.

That is the same failure as the rotation false-break already fixed, by a
different route, and it is worse than a missing feature: an integrity
control that cries wolf is one the reader learns to ignore, which is
exactly how T5's evidence trail is lost.

So the predecessor is resolved INSIDE a cross-process lock, immediately
before the write. The cached hash is used only when `(mtime_ns, size)`
proves nothing has appended since our own last write — the common
single-process case, where the tail read would be pure cost.
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

from .filelock import FileLock
from .types import ActionRequest, Decision, Outcome, RejectionCode, Source

log = logging.getLogger(__name__)

MAX_BYTES = 5 * 1024 * 1024
KEEP_ROTATIONS = 5
GENESIS = "0" * 16

# How much of the file's tail to read when resolving the predecessor.
# Records run a few hundred bytes, so this holds several; the reader
# widens automatically if it does not contain a complete line.
_TAIL_BYTES = 8192


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
    kind: str  # "decision" | "completion" | "note"
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
# Chain status
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ChainStatus:
    """Result of walking the hash chain."""

    intact: bool
    first_break_line: int = 0
    file: str | None = None
    anchored_at_genesis: bool = True
    reason: str = "ok"

    def __bool__(self) -> bool:
        return self.intact


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
        # Resolved lazily, inside the file lock, at the first write.
        # Reading it at construction is what made the chain break across
        # processes: a value read minutes before a write says nothing
        # about what the file looks like at write time.
        self._prev_hash: str | None = None
        self._stamp: tuple[int, int] | None = None

    # -- writes ------------------------------------------------------------

    def decision(
        self, request: ActionRequest, decision: Decision, tier: int | None
    ) -> None:
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

    def completion(
        self, request: ActionRequest, ok: bool, error: str | None = None
    ) -> None:
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

    def _chain_files(self) -> list[Path]:
        """Rotated files oldest-first, then the current log.

        The chain continues across rotations — the first record of a new
        file points at the last record of the previous one — so verifying
        only the current file reports a false break on line 1 after every
        rotation.
        """
        files: list[Path] = []
        for i in range(KEEP_ROTATIONS, 0, -1):
            candidate = self._path.with_suffix(f".jsonl.{i}")
            if candidate.exists():
                files.append(candidate)
        if self._path.exists():
            files.append(self._path)
        return files

    def verify_chain(self) -> ChainStatus:
        """Walk every retained file in order.

        A break means a line was deleted or edited. It does not identify
        who did it, and a determined editor can recompute the chain.

        A MISSING log reports as NOT intact. The old behaviour — returning
        "intact" for a file that does not exist — meant deleting the log
        entirely passed the integrity check, which is the one tamper case
        this control exists to catch.
        """
        files = self._chain_files()
        if not files:
            return ChainStatus(
                intact=False, reason="audit log is absent; nothing to verify"
            )

        prev: str | None = None
        anchored = True

        for path in files:
            try:
                with path.open("r", encoding="utf-8") as fh:
                    for n, line in enumerate(fh, start=1):
                        line = line.strip()
                        if not line:
                            continue
                        body = json.loads(line)
                        if prev is None:
                            # Oldest retained record. If it is not genesis,
                            # earlier files have rolled off and anything
                            # before this point is unverifiable.
                            prev = body.get("prev", GENESIS)
                            anchored = prev == GENESIS
                        if body.get("prev") != prev:
                            return ChainStatus(
                                False, n, path.name, anchored, "prev hash mismatch"
                            )
                        if body.get("hash") != _chain_hash(body["prev"], body):
                            return ChainStatus(
                                False, n, path.name, anchored, "record hash mismatch"
                            )
                        prev = body["hash"]
            except Exception as exc:
                log.exception("audit chain unreadable at %s", path)
                return ChainStatus(False, 0, path.name, anchored, f"unreadable: {exc!r}")

        return ChainStatus(
            intact=True,
            anchored_at_genesis=anchored,
            reason="ok"
            if anchored
            else "intact from oldest retained record; earlier files rotated away",
        )

    # -- internals ---------------------------------------------------------

    def _stamp_now(self) -> tuple[int, int] | None:
        try:
            st = self._path.stat()
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size)

    def _current_prev_hash(self) -> str:
        """The hash this record must link to. Caller holds the file lock.

        The cached value is trusted only when `(mtime_ns, size)` matches
        what it was after our own last write. Any change means another
        process appended, and the tail must be re-read — that check is
        the whole of the KI-2 fix.
        """
        if self._prev_hash is not None and self._stamp_now() == self._stamp:
            return self._prev_hash
        return self._read_last_hash()

    def _read_last_hash(self) -> str:
        """Hash of the final record, read from the tail of the file.

        Reads backwards from the end rather than iterating the whole file:
        this runs on every append that follows another process's write,
        and the log grows to 5MB before rotating.
        """
        try:
            with self._path.open("rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                if size == 0:
                    return GENESIS
                chunk = min(size, _TAIL_BYTES)
                while True:
                    fh.seek(size - chunk)
                    data = fh.read(chunk)
                    lines = [ln for ln in data.split(b"\n") if ln.strip()]
                    # If we did not read from byte zero, the first line in
                    # the chunk may be truncated — drop it.
                    if chunk < size and lines:
                        lines = lines[1:]
                    if lines or chunk >= size:
                        break
                    chunk = min(size, chunk * 4)
        except FileNotFoundError:
            return GENESIS
        except Exception:
            log.exception("could not read tail of audit log; starting a new chain")
            return GENESIS

        if not lines:
            return GENESIS
        try:
            return json.loads(lines[-1]).get("hash", GENESIS)
        except Exception:
            log.exception("last audit record is unparseable; starting a new chain")
            return GENESIS

    def _append(self, record: Record) -> None:
        with self._lock:
            try:
                with FileLock(self._path):
                    self._path.parent.mkdir(parents=True, exist_ok=True)
                    # Resolve the predecessor BEFORE rotating. Rotation
                    # moves the current file to .1 and leaves an empty
                    # one, and the chain continues across that boundary —
                    # reading afterwards would see an empty file and
                    # restart from genesis, which verify_chain would then
                    # correctly report as a break.
                    prev = self._current_prev_hash()
                    self._rotate_if_needed()

                    body = record.to_json(prev)
                    with self._path.open("a", encoding="utf-8") as fh:
                        fh.write(json.dumps(body, default=str) + "\n")
                        fh.flush()
                        os.fsync(fh.fileno())  # survive a crash mid-action

                    self._prev_hash = body["hash"]
                    self._stamp = self._stamp_now()
            except Exception as exc:
                # The cache cannot be trusted after a failed write; the
                # next append re-reads the tail rather than linking to a
                # record that may not be there.
                self._prev_hash = None
                self._stamp = None
                raise AuditWriteFailed(f"could not write audit record: {exc}") from exc

    def _rotate_if_needed(self) -> None:
        """Caller holds the threading lock AND the file lock.

        Under the file lock so two processes cannot rotate concurrently —
        which would shuffle the numbered files out from under each other
        and lose records that `_chain_files` still expects to walk.
        """
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