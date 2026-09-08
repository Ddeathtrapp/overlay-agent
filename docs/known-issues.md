# Known issues

Open defects and deferred work. Findings resolved here get deleted, not
struck through — git history is the record.

## Open


### KI-3 — ExecutionResult discarded in assistant.py:473  (MEDIUM)
A rate-limited shutdown, after the user has typed the challenge word, is
silent and indistinguishable from success.

### KI-4 — Dialog deadline vs Tk init and modal move loop  (MEDIUM)
The self-close deadline is computed after `_create_root()`, so the real
margin is 1.0s minus Tk init (150-400ms typical, more cold). Tk `after`
callbacks do not fire during a Windows modal move loop, so dragging the
dialog by its title bar defers the deadline indefinitely. Fail-closed
throughout, but it is the case where two Tk roots can coexist, after which
the next hotkey press dies silently on a cross-apartment Tcl call.

### KI-5 — False claims in assistant.py threading docstring  (LOW)
Three, including the claim that queued WM_HOTKEY presses are not replayed.
Windows does queue and replay them. Same defect class as the hardcoded
HONESTY banner and the copied `__init__.py` docstring: prose assertions
that nothing verifies.

### KI-6 — No test drives two concurrent execute() calls  (MEDIUM)
`_pending_confirmation` has no coverage. It was unreachable until the
CONFIRMATION_PENDING enum fix; it is still untested.

### KI-7 — RejectionCode mapped in two places  (LOW)
`cli.py` maps RejectionCode to exit codes; `ui/assistant.py` maps the same
enum to user-facing text. Two independent enumerations of one set, in files
owned by two different agents. `assistant.py` has a drift guard that
iterates the live enum and fails when a code has no explicit entry;
`cli.py` does not, so a new code there falls through to a default.

Proposed fix: keep both tables but move the ENUMERATION to
`src/policy/types.py`, beside RejectionCode — the one module both already
import, and human-owned, so neither agent reaches into the other's private
dict. The codomains differ (ints vs text), so this is about having one
place that lists the codes, not one table.

Not urgent. The guard in assistant.py catches the half that matters most.
Same defect class as the hardcoded description lists and the HONESTY
banner: a second copy of a truth that nothing checks.

### KI-8 — AuditWriteFailed swallowed in assistant.py  (MEDIUM)
`except Exception` at assistant.py:473 catches AuditWriteFailed, which
`PolicyEngine._finalize` deliberately re-raises rather than executing
unlogged. The design says: no log, no action — disk-full stops the
assistant rather than silently downgrading it to unaudited operation.

The refusal still happens, so this is not fail-open. But the user sees a
generic error instead of "blocked because the audit log could not be
written", which is the one message that tells them the assistant is
non-functional until they free disk space. An unactionable error on a
condition with an obvious action.

Changes behaviour rather than display, so it was out of scope for KI-3.
