# Known issues

Open defects and deferred work. Findings resolved here get deleted, not
struck through — git history is the record.

Reference code by function or class name, not line number. Line numbers
drift with every commit and this file has already been wrong once: KI-8
cited assistant.py:473, which after the KI-3 commit was a docstring in a
different function. This is the same defect class as the hardcoded
description lists, the HONESTY banner, and the copied __init__.py
docstring — an assertion that was true when written, with nothing to
notice when it stopped being.

## Open


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
