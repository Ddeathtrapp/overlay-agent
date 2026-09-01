# Architecture

**Status:** draft v0.1
**Companion documents:** `action-registry.md` (the contract), `threat-model.md`
(why the boundaries are where they are)

---

## 1. What this is

A Windows 11 desktop assistant. The user speaks or types an instruction — from
the desktop or from their phone — and the system performs one action from a
fixed, closed registry. It can read the screen for context. It cannot do
anything that is not in the registry.

The design goal is not maximum capability. It is a system whose worst-case
behaviour is enumerable on a single page.

**Comparison point:** iOS Shortcuts, not an autonomous agent. The model selects
from a menu; it does not compose novel behaviour.

---

## 2. Design principles

1. **The model is not a security boundary.** It selects; code decides. Every
   safety property must hold even if the model is fully compromised.
2. **Closed action space.** Capability is added by a human writing code, never
   by the system learning at runtime.
3. **Fail closed, everywhere.** Ambiguity resolves to refusal, never to a
   guess.
4. **The untrusted input arrives last.** Screen context is the final component
   built, because it is the only untrusted input path.
5. **Small enough to audit.** If the security-relevant code cannot be read in
   one sitting, the design is wrong.

---

## 3. Components

```
┌─────────────┐        ┌─────────────┐
│ Phone (PWA) │        │  Desktop    │
└──────┬──────┘        │  overlay    │
       │               └──────┬──────┘
       │ WSS (Tailscale)      │ local IPC
       └───────────┬──────────┘
                   ▼
          ┌─────────────────┐
          │   Transport     │  auth, session, rate limit
          └────────┬────────┘
                   ▼
          ┌─────────────────┐      ┌──────────────┐
          │   Classifier    │◄─────│ Screen ctx   │ (untrusted)
          │ (local Ollama)  │      │ capture+OCR  │
          └────────┬────────┘      └──────────────┘
                   │ ActionRequest {id, params, source}
                   ▼
          ╔═════════════════╗
          ║  Policy engine  ║  ◄── HUMAN-OWNED. src/policy/
          ║  validate·tier  ║      The security boundary.
          ║  ·rate·confirm  ║
          ╚════════┬════════╝
                   │              ┌──────────────┐
                   ├─────────────►│  Audit log   │ append-only
                   ▼              └──────────────┘
          ┌─────────────────┐
          │ Action handlers │  typed params only
          └─────────────────┘
```

### 3.1 Transport (`src/transport/`)
WebSocket server bound to the Tailscale interface. Session auth, TOTP,
connection lifecycle. Serves the phone PWA. **Never** bound to `0.0.0.0`,
never port-forwarded.

### 3.2 Classifier (`src/classifier/`)
Local Ollama model. Maps an utterance to `{action_id} ∪ {NO_MATCH}` under
constrained decoding. Parameters extracted in a second constrained pass, one
per parameter. Never produces free-form output that gets parsed.

### 3.3 Screen context (`src/context/`) — Phase 6
Capture, frame diffing, OCR. Output is tagged `untrusted` and enters the
classifier prompt in a delimited block. Never enters the policy engine.

### 3.4 Policy engine (`src/policy/`) — human-owned
The only component that may invoke a handler. Validates parameter types
against the registry, enforces tier rules, checks exceptions, applies rate
limits, requests confirmation, writes the audit record. Roughly 300 lines.
Written and reviewed by a human; agents do not modify it.

### 3.5 Action handlers (`src/actions/`)
One handler per registry entry. Receives already-validated typed parameters.
Performs no validation of its own.

### 3.6 Overlay (`src/overlay/`)
Desktop status display. Glowing perimeter reflecting state
(`idle`/`listening`/`thinking`/`acting`). Click-through and non-focusable;
carries `WDA_EXCLUDEFROMCAPTURE` so it never appears in its own screen
captures. **Display only** — it is not an input surface and cannot dispatch.

---

## 4. Trust boundaries

| Boundary | Trusted side | Untrusted side |
|---|---|---|
| Transport auth | authenticated session | anything on the network |
| Classifier output | registry enum values | model output generally |
| Screen context | — | **all OCR text, always** |
| Policy engine | validated `ActionRequest` | everything upstream |

**The critical one:** the classifier's *output domain* is trusted because it is
structurally constrained to the enum. The classifier's *reasoning* is not
trusted at all. This distinction is what allows a small local model to sit in
the pipeline safely.

**Provenance rule:** any `ActionRequest` whose parameters derive from screen
context carries `source: screen_context` and requires confirmation regardless
of tier or standing exception.

---

## 5. Stack

| Layer | Choice | Why |
|---|---|---|
| Language | Python 3.14 | Win32 access via `ctypes`, fast iteration |
| Inference | Ollama, local | Screen contents never leave the machine |
| Model | `qwen2.5-coder:7b` Q4_K_M, ctx 8192 | Classification is easy; this is more than sufficient |
| GPU backend | Vulkan | RX 6600 XT (`gfx1032`) is not on Ollama's Windows ROCm list |
| Constrained decoding | GBNF grammar | Makes invalid output impossible, not just unlikely |
| Transport | WebSocket over Tailscale | No port forwarding, no public exposure |
| Phone UI | PWA | No app store, no native build |
| Overlay | See Phase 7 decision | Electron vs. PySide6 — RAM budget dependent |
| Tests | pytest | — |

**Hardware:** Ryzen 7 5800X3D, RX 6600 XT (8GB), 16GB RAM (~7GB free).
The 8GB VRAM ceiling shaped the original design; with classification-only
inference it is no longer a binding constraint.

---

## 6. Module ownership

| Path | Owner | Notes |
|---|---|---|
| `src/policy/` | **Human only** | Agents must not create, modify, or delete |
| `src/actions/` | `registry-engineer` | Human review required per action |
| `src/dispatch/` | `registry-engineer` | Human review — it touches the boundary |
| `src/classifier/` | `classifier-engineer` | — |
| `src/transport/` | `transport-engineer` | Human review of auth code |
| `src/context/` | `classifier-engineer` | Phase 6 |
| `src/overlay/` | `overlay-engineer` | — |
| `tests/` | `test-runner`, all | — |
| `docs/` | **Human only** | Specs are amended by humans, not agents |

---

## 7. Build order

Deliberately inverted from the original plan: the safe machine is built first,
the model is bolted on late, and the untrusted input path is last.

| Phase | Deliverable | Milestone |
|---|---|---|
| 1 | Action registry + 5 handlers | Working CLI tool, **no LLM anywhere** |
| 2 | Policy engine + audit log | Adversarial tests pass; everything fails closed |
| 3 | Classifier + eval set | Accuracy and false-action rate measured before wiring |
| 4 | Desktop confirmation UI | **Working local assistant — stop and live with it** |
| 5 | Transport + phone PWA | Verified unreachable outside the Tailscale mesh |
| 6 | Screen context | Untrusted input enters, last |
| 7 | Overlay + registry expansion | — |

**Phase 4 is a real stopping point.** It is a complete, useful product. Do not
treat phases 5–7 as obligatory.

---

## 8. What this is not

Recording these so they don't get relitigated at 2am six months in:

- **Not an autonomous agent.** No planning loops, no self-directed multi-step
  execution, no goal pursuit.
- **Not extensible at runtime.** No learned actions, no user-defined scripts,
  no plugin system.
- **Not a general computer-use agent.** No arbitrary clicking, no filesystem
  access, no shell.
- **Not cloud-dependent.** Screen contents stay on the machine.

Each of these is a load-bearing constraint. See `threat-model.md` §6 for what
happens if any is relaxed.