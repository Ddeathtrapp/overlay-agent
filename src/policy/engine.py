"""The policy engine.

This is the security boundary. It is the ONLY code in the application
permitted to call `action.handler`. Everything upstream — the CLI, the
classifier, the transport — produces a proposal; this module decides
whether it happens.

Read the whole thing. It is short on purpose (threat-model.md §5: "small
enough to audit"), and every branch either rejects or narrows.

Evaluation runs in three phases:

    A. resolve and validate      under the gate
       lookup, arity, parse, rate limit, permission
       -> if no human is needed, execute here and return

    B. ask the human             WITHOUT the gate
       with a timeout, on a daemon thread

    C. re-check and execute      under the gate again

Phase B is outside the lock deliberately. Holding it across a prompt
would let one unanswered dialog block every later request — tier 0
included — before any of them were even audited. T8 is denial of
service; a confirmation deadlock is the same outcome by accident.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Mapping

from actions import lookup
from actions.params import ParamRejected

from .audit import AuditLog, AuditWriteFailed
from .confirm import (
    ConfirmationPrompt,
    ConfirmationReply,
    Confirmer,
    NullConfirmer,
    build_prompt,
)
from .exceptions import ExceptionRefused, ExceptionStore
from .limits import NoLimitConfigured, RateLimit, RateLimiter, default_for_tier
from .types import ActionRequest, Decision, RejectionCode, Source

log = logging.getLogger(__name__)

TIER_TWO = 2

_SOURCE_LABELS = {
    Source.DESKTOP: "desktop",
    Source.PHONE: "phone",
    Source.SCREEN_CONTEXT: "screen context",
}


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """What happened. `decision.allowed` says whether it was permitted;
    `executed` says whether the handler actually ran."""

    decision: Decision
    executed: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.executed and self.error is None


def limits_from_registry(registry) -> dict[str, RateLimit]:
    """Build the limit table from the registry.

    §12.2 puts the values on the registry entry. Until `Action` grows a
    `rate_limit` field, fall back to the tier default — but never to
    "unlimited". A missing limit is a registry defect.
    """
    table: dict[str, RateLimit] = {}
    for action in registry:
        declared = getattr(action, "rate_limit", None)
        table[action.id] = declared or default_for_tier(int(action.tier))
    return table


class PolicyEngine:
    """Evaluates and executes. Construct one; share it.

    The `registry` argument feeds the rate-limit table and prune_unknown.
    It does NOT control dispatch — `_run` resolves through the module-global
    `actions.lookup`, deliberately, so a swapped-in registry cannot change
    what executes.
    """

    def __init__(
        self,
        registry,
        *,
        confirmer: Confirmer | None = None,
        exceptions: ExceptionStore | None = None,
        limiter: RateLimiter | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self._registry = registry
        # Default is NullConfirmer, which denies. Forgetting to attach a UI
        # must fail closed, not open.
        self._confirmer = confirmer or NullConfirmer()
        self._exceptions = exceptions or ExceptionStore()
        self._limiter = limiter or RateLimiter(limits_from_registry(registry))
        self._audit = audit or AuditLog()
        # §12.4: no two handlers run at once. The gate is held for
        # validation and for execution, but NOT across a human prompt —
        # see the module docstring. It does not guarantee strict FIFO
        # ordering; Python locks are not queued.
        self._gate = threading.Lock()

        self._exceptions.prune_unknown(a.id for a in registry)

    # ----------------------------------------------------------------------
    # Public entry point
    # ----------------------------------------------------------------------

    def execute(
        self,
        action_id: str,
        raw_params: Mapping[str, object] | None = None,
        *,
        source: Source,
        utterance: str | None = None,
    ) -> ExecutionResult:
        """Evaluate a proposal and run it if permitted.

        `source` is a keyword argument supplied by the CALLER, and the
        request is constructed here rather than handed in. That is
        deliberate (threat-model.md T12): there is no deserialisation path
        that can populate a Source, so a payload cannot claim to be
        DESKTOP. The CLI passes Source.DESKTOP as a literal; the transport
        passes Source.PHONE as a literal. Never add a `from_payload`
        helper that reads it out of JSON.
        """
        request = ActionRequest(
            action_id=action_id,
            raw_params=raw_params or {},
            source=source,
            utterance=utterance,
        )
        return self._run(request)

    def grant_exception(self, action_id: str, params: Mapping[str, object]) -> None:
        """Standing exception, for use by a settings UI. The confirmation
        path grants its own; this exists so §12.1's inspect-and-revoke
        contract has a matching grant path."""
        action = lookup(action_id)
        self._exceptions.grant(action_id, int(action.tier), params)
        self._audit.note("exception_granted", {"action_id": action_id})

    def revoke_exception(self, action_id: str, params: Mapping[str, object]) -> bool:
        removed = self._exceptions.revoke(action_id, params)
        if removed:
            self._audit.note("exception_revoked", {"action_id": action_id})
        return removed

    def revoke_all_exceptions(self) -> int:
        """Bulk revoke. Audited as one note per grant plus a summary, so the
        record is queryable per action rather than only as a count —
        §12.1 made inspect-and-revoke a security contract, and a bulk
        operation that leaves no per-action trace breaks it."""
        grants = self._exceptions.list()
        for grant in grants:
            self._audit.note("exception_revoked", {"action_id": grant.action_id})
        count = self._exceptions.revoke_all()
        self._audit.note("exceptions_revoke_all", {"count": count})
        return count

    def list_exceptions(self):
        """§12.1 traded expiry for inspectability. This is that trade."""
        return self._exceptions.list()

    # ----------------------------------------------------------------------
    # Orchestration
    # ----------------------------------------------------------------------

    def _run(self, request: ActionRequest) -> ExecutionResult:
        # --- phase A: resolve and validate, holding the gate --------------
        with self._gate:
            resolved = self._resolve(request)
            if isinstance(resolved, ExecutionResult):
                return resolved
            action, tier, parsed = resolved

            decision = self._evaluate_permission(request, action, tier, parsed)
            if decision is not None:
                return self._finalize(request, action, tier, parsed, decision)

        # --- phase B: ask the human, with the gate RELEASED ---------------
        decision = self._ask(request, action, tier, parsed)

        # --- phase C: re-acquire, re-check, execute -----------------------
        with self._gate:
            if decision.allowed:
                # The limit was checked before the prompt. Time passed and
                # other requests may have executed since, so check again —
                # otherwise two prompts outstanding at once could both
                # spend the last remaining slot.
                limited = self._check_limit(request, action, tier)
                if limited is not None:
                    return limited
            return self._finalize(request, action, tier, parsed, decision)

    # ----------------------------------------------------------------------
    # Phase A helpers
    # ----------------------------------------------------------------------

    def _resolve(self, request: ActionRequest):
        """Lookup, arity, parse, rate limit.

        Returns `(action, tier, parsed)` on success, or an ExecutionResult
        carrying the rejection.
        """
        # 1 — the action must exist.
        try:
            action = lookup(request.action_id)
        except Exception:
            return self._reject(
                request,
                None,
                RejectionCode.UNKNOWN_ACTION,
                f"no action with id {request.action_id!r}",
            )

        tier = int(action.tier)

        # 2 — arity, before parsing, so the error names the real problem.
        expected = {spec.name for spec in action.params}
        supplied = set(request.raw_params)
        if expected != supplied:
            return self._reject(
                request,
                tier,
                RejectionCode.BAD_ARITY,
                f"{action.id} takes {sorted(expected)}, got {sorted(supplied)}",
            )

        # 3 — parse with the registry's own specs. The engine does not
        # implement validation; a second copy would drift from the first.
        parsed: dict[str, object] = {}
        for spec in action.params:
            try:
                parsed[spec.name] = spec.parse(request.raw_params[spec.name])
            except ParamRejected as exc:
                return self._reject(request, tier, RejectionCode.PARAM_REJECTED, str(exc))

        # 4 — rate limit, before any prompt.
        limited = self._check_limit(request, action, tier)
        if limited is not None:
            return limited

        return action, tier, parsed

    def _check_limit(self, request: ActionRequest, action, tier: int):
        """Returns an ExecutionResult if the request is limited, else None."""
        try:
            status = self._limiter.check(action.id)
        except NoLimitConfigured as exc:
            return self._reject(
                request,
                tier,
                RejectionCode.UNKNOWN_ACTION,
                f"{action.id} resolved via the global registry but is absent from "
                f"this engine's limit table — engine built with a different "
                f"registry than the one dispatch uses ({exc})",
            )
        if not status.allowed:
            limit = self._limiter.limit_for(action.id)
            return self._reject(
                request, tier, RejectionCode.RATE_LIMITED, status.reason(action.id, limit)
            )
        return None

    def _evaluate_permission(
        self, request: ActionRequest, action, tier: int, parsed: Mapping[str, object]
    ) -> Decision | None:
        """Resolve without asking, if possible.

        Returns a Decision when the answer is settled, or None when a human
        must be asked.
        """
        trusted = request.source.trusted

        if tier >= TIER_TWO:
            # Never excepted, never auto-allowed, and — per §5 — never even
            # offered when the request came off the screen.
            if not trusted:
                return Decision.reject(
                    request,
                    RejectionCode.NOT_CONFIRMED,
                    f"{action.id} is tier {tier} and cannot originate from screen context",
                )
            return None

        if not trusted:
            # Provenance override: a standing exception does not apply to a
            # request whose parameters came off the screen.
            return None

        if tier == 0:
            return Decision.auto_allow(request, "tier 0")

        if self._exceptions.matches(action.id, parsed):
            return Decision.auto_allow(request, "standing exception")

        return None

    # ----------------------------------------------------------------------
    # Phase B — confirmation
    # ----------------------------------------------------------------------

    def _ask(self, request, action, tier: int, parsed: Mapping[str, object]) -> Decision:
        prompt = build_prompt(
            action_id=action.id,
            description=action.description,
            params={k: str(v) for k, v in parsed.items()},
            tier=tier,
            source_label=_SOURCE_LABELS[request.source],
            source_trusted=request.source.trusted,
        )

        if isinstance(self._confirmer, NullConfirmer):
            return Decision.reject(
                request,
                RejectionCode.NO_CONFIRMER,
                "no confirmation interface is attached",
            )

        try:
            reply = self._ask_with_timeout(prompt)
        except Exception as exc:
            # A confirmer that raises — including one returning a reply that
            # fails ConfirmationReply's type checks — must be a denial, not
            # an unhandled crash out of the engine.
            log.exception("confirmation interface failed for %s", action.id)
            return Decision.reject(
                request,
                RejectionCode.NOT_CONFIRMED,
                f"confirmation interface failed: {exc!r}",
            )

        if not Confirmer.verify(prompt, reply):
            return Decision.reject(
                request, RejectionCode.NOT_CONFIRMED, "declined or not confirmed"
            )

        if Confirmer.may_remember(prompt, reply):
            try:
                self._exceptions.grant(action.id, tier, parsed)
                self._audit.note("exception_granted", {"action_id": action.id})
            except ExceptionRefused:
                # A refused grant must not turn an approved action into a
                # rejected one — the human said yes to THIS invocation.
                log.warning("could not store exception for %s", action.id)

        return Decision.confirmed(request)

    def _ask_with_timeout(self, prompt: ConfirmationPrompt) -> ConfirmationReply:
        """Run the confirmer on a daemon thread and give up after
        `prompt.timeout_seconds`.

        `Confirmer.ask` is blocking by contract, and a console prompt on
        `input()` cannot be interrupted from outside. So the wait is
        bounded here rather than inside any one implementation: on timeout
        this returns a denial and the worker thread is abandoned. It is a
        daemon thread, so a stuck one never blocks interpreter exit.

        A real UI should also enforce its own timeout — this is the
        backstop, not the mechanism. Timing out is always a DENIAL; a
        confirmation that defaults to allow after waiting is not a
        confirmation, it is a delay.
        """
        box: list[object] = []

        def worker() -> None:
            try:
                box.append(self._confirmer.ask(prompt))
            except Exception as exc:  # re-raised on the calling thread
                box.append(exc)

        thread = threading.Thread(
            target=worker, daemon=True, name=f"confirm-{prompt.action_id}"
        )
        thread.start()
        try:
            thread.join(prompt.timeout_seconds)
        except KeyboardInterrupt:
            # Ctrl+C reaches the MAIN thread, which is here in join(), not
            # the worker blocked on input(). Treat it as a denial — the
            # user interrupting a confirmation prompt means no.
            log.info("confirmation for %s interrupted; denying", prompt.action_id)
            return ConfirmationReply(approved=False)

        if thread.is_alive():
            log.warning(
                "confirmation for %s timed out after %.0fs; denying",
                prompt.action_id,
                prompt.timeout_seconds,
            )
            return ConfirmationReply(approved=False)

        if not box:
            log.warning("confirmer returned nothing for %s; denying", prompt.action_id)
            return ConfirmationReply(approved=False)

        outcome = box[0]
        if isinstance(outcome, BaseException):
            raise outcome
        if not isinstance(outcome, ConfirmationReply):
            raise TypeError(
                f"confirmer returned {type(outcome).__name__}, expected ConfirmationReply"
            )
        return outcome

    # ----------------------------------------------------------------------
    # Phase C — audit and execute
    # ----------------------------------------------------------------------

    def _finalize(
        self,
        request: ActionRequest,
        action,
        tier: int,
        parsed: Mapping[str, object],
        decision: Decision,
    ) -> ExecutionResult:
        # Audit BEFORE execution. If this fails, nothing runs.
        try:
            self._audit.decision(request, decision, tier)
        except AuditWriteFailed:
            log.exception("audit write failed; refusing to execute unlogged")
            raise

        if not decision.allowed:
            return ExecutionResult(decision)

        # The limiter counts allowed executions only, so that a spammed
        # rejection cannot lock the user out of their own machine.
        self._limiter.record(action.id)

        # The one call site.
        try:
            action.handler(**parsed)
        except Exception as exc:
            self._audit.completion(request, ok=False, error=repr(exc))
            log.exception("%s failed", action.id)
            return ExecutionResult(decision, executed=True, error=repr(exc))

        self._audit.completion(request, ok=True)
        return ExecutionResult(decision, executed=True)

    def _reject(
        self,
        request: ActionRequest,
        tier: int | None,
        code: RejectionCode,
        reason: str,
    ) -> ExecutionResult:
        decision = Decision.reject(request, code, reason)
        self._audit.decision(request, decision, tier)
        return ExecutionResult(decision)