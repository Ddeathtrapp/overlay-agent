# Known issues

Open defects and deferred work. Findings resolved here get deleted, not
struck through — git history is the record.

## Open


### KI-2 — Audit chain false break across processes  (HIGH)
`_prev_hash` is cached at construction and the only mutual exclusion is a
per-process `threading.Lock`. Two processes both append from H0, producing
a permanent `prev` mismatch indistinguishable from tampering. Same class as
the rotation false-break already fixed: an integrity control that cries
wolf is one the reader learns to ignore.

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