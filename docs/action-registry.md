# Action Registry Specification

**Status:** draft v0.1
**Owner:** human. Agents implement against this document; they do not amend it.

---

## 0. Read first — known risks in this spec

Three items in this document are flagged. Agents implementing against it must
read these before writing code.

**0.1 — `toggle_night_light` may not be implementable cleanly.**
Windows exposes no public API. State lives in a serialized blob under
`HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore\...` and the format
is undocumented and has changed across Windows builds.
*Rule:* attempt it, timebox it. If it resists, **stop and report** — do not
shell out, do not install a third-party utility, do not script the Settings UI.
Substitute `toggle_dark_mode` (a clean `AppsUseLightTheme` registry DWORD) as
the Tier 0 exemplar and move on. Phase 1 must not block on this action.

**0.2 — `open_application` is the highest-risk action in the registry.**
It is the one action where a dictionary key can quietly become a path, and a
path can quietly become a command. Every other action is boring by
construction; this one is boring only if kept so deliberately.
*Rule:* the parameter is a key into `APPS`. It is never joined, formatted,
concatenated, or passed to a shell. `subprocess` is called with a list and
`shell=False`, using the `Path` value from the dict — never the key, never
anything derived from input. Mandatory human review before merge.

**0.3 — §12 is unanswered and must stay that way until a human answers it.**
Those four decisions define the policy engine's shape. The recommendations in
§12 are defaults for discussion, **not decisions**. Agents must not implement
against them, and must not treat a recommendation as settled. If a task
requires one of these answers, stop and ask.

---

## 1. Purpose

The action registry is the complete, closed set of things this application can
do to the machine. It is the security boundary of the entire system.

The language model does not decide what is possible. It selects one entry from
this registry. A fully compromised model — one that has absorbed an injected
instruction and is actively trying to cause harm — can emit at most a valid
registry ID with valid parameters. If nothing in the registry is dangerous,
there is nothing dangerous for it to say.

Everything else in this project is a convenience layer on top of that property.

---

## 2. Invariants

These hold for every action, forever. A change to this list is a change to the
security model and requires re-running the threat model.

1. **The registry is closed at build time.** Actions are Python code, in git,
   written and reviewed by a human. Never runtime-registered, never
   config-file-defined, never LLM-authored.
2. **No free-form string reaches an OS call.** See §3 for the only permitted
   parameter types.
3. **The model's output is constrained to the enum.** Intent selection uses
   constrained decoding (GBNF grammar or logit restriction). Invalid output is
   structurally impossible, not merely improbable.
4. **Everything fails closed.** Unknown ID, out-of-range parameter, missing
   whitelist key, malformed request → reject and log. Never guess, never
   coerce, never fall through to a default.
5. **The policy engine is not in the model's reach.** `src/policy/` is
   human-owned. Actions do not import from it; it imports them.

---

## 3. Parameter type system

A parameter is exactly one of three kinds. There is no fourth kind.

| Kind | Definition | Example |
|---|---|---|
| `Enum` | A Python `Enum` defined in source | `SettingPage.DISPLAY` |
| `BoundedInt` | Integer with compile-time `min` and `max` | `volume: BoundedInt(0, 100)` |
| `WhitelistKey` | A key into a `dict[str, T]` literal in source | `app: AppKey` → `APPS["notepad"]` |

**Rejected by design:**
- Free strings, even "validated" ones
- Paths, even "sanitized" ones
- Anything requiring a regex to make safe — if you reach for a regex, the
  design is wrong; replace it with a lookup

**Rationale.** Every parameter kind above has a finite, enumerable domain that
exists in source code. An attacker choosing the worst possible value from that
domain is a scenario you can reason about completely. A string parameter has an
infinite domain and cannot be reasoned about completely.

---

## 4. Action schema

```python
@dataclass(frozen=True)
class Action:
    id: str                    # stable, snake_case, never reused after removal
    tier: Tier                 # see §5
    description: str           # human-readable; also fed to the classifier
    params: tuple[ParamSpec, ...]
    reversible: bool           # can the user trivially undo this?
    handler: Callable          # the implementation
```

**Rules**
- `id` is permanent. If an action is removed, its ID is retired, never
  reassigned. The audit log must remain interpretable.
- `description` is user-facing and classifier-facing. Write it as a plain
  sentence a person would say, because that is what it is matched against.
- `handler` receives already-validated typed parameters. Handlers perform no
  validation of their own — validation happened in the policy engine, and a
  second copy of validation logic is a second place for it to drift.

---

## 5. Tiers

Tier is a property of the action, declared in code alongside it. It is not a
user setting, and the user cannot promote an action to a lower tier.

| Tier | Meaning | Confirmation |
|---|---|---|
| **0** | Zero parameters, reversible, no security surface | May be auto-allowed by user exception |
| **1** | Parameterized, or touches a non-trivial surface | Always confirm; exception permitted only for `(action_id + exact parameter value)` |
| **2** | Irreversible, destructive, or security-relevant | Always confirm. **No exception ever.** Requires typed confirmation, not a tap |

**Tier 1 exception scoping is the load-bearing detail.** An exception is
`(open_application, "vscode")` — never `(open_application, *)`. An exception
that covers a whole action type reintroduces the parameter domain you
eliminated in §3.

**Tier 2 friction is intentional.** Habituation defeats confirmation dialogs;
after three weeks you will tap Yes without reading. Requiring a typed word for
irreversible actions is the only mechanism here that resists that.

---

## 6. Dispatch flow

```
utterance ──► classifier ──► ActionRequest ──► policy engine ──► handler
              (constrained)   {id, params}      (validate,
                                                 tier, rate,
                                                 confirm)
                                                      │
                                                      └──► audit log
```

**Every stage fails closed.** The policy engine is the only component that may
invoke a handler. Nothing else calls handlers directly — not the classifier,
not the transport layer, not the overlay.

**`NO_MATCH` is a first-class output.** The classifier must be able to say "no
registry entry matches this utterance," and that must be the default when
confidence is low. Refusing to act is always correct behaviour; guessing is
not. Budget for `NO_MATCH` in the eval set (§9).

**Audit record** — one per request, append-only, written before execution:

```json
{
  "ts": "2026-08-31T14:02:11Z",
  "utterance": "turn on night light",
  "action_id": "toggle_night_light",
  "params": {},
  "tier": 0,
  "source": "phone|desktop|screen_context",
  "decision": "auto_allowed|confirmed|rejected|rate_limited",
  "outcome": "ok|error",
  "error": null
}
```

`source` matters: an action whose parameters derive from OCR'd screen content
is untrusted-origin and requires confirmation regardless of tier or exception.

---

## 7. The design test

Run this before adding any action, and re-run it across the whole registry
every ten additions.

> **Assume an attacker can invoke any action in the registry, with any valid
> parameter, at any moment of their choosing. Is the outcome acceptable?**

If yes, ship it. If no, the problem is the registry, not the model, and no
amount of prompt engineering will fix it.

**Composition check.** Individually harmless actions compose into harmful ones.
`open_setting(SECURITY)` + `click_ui_element` + `confirm_dialog` = "disable
Defender", with no single action looking dangerous. When adding an action, ask
what it enables *in combination with everything already present*.

---

## 8. Permanent exclusion list

The following are never implemented. Not behind a tier, not behind a
confirmation, not "just for development."

- `run_command` / `execute` / `shell` — any arbitrary command execution
- `write_file` / `delete_file` / any filesystem mutation
- `download` / `install` / `update`
- `send_network_request` / any outbound HTTP the user did not initiate
- `read_credential_store` / password manager / browser profile access
- `modify_security_settings` — Defender, firewall, UAC, BitLocker
- `open_url(str)` — free-form URL is a string parameter wearing a costume
- Anything accepting a path

**Why this list exists in writing:** at some point a feature will be annoying
to implement with typed actions and one of these will look like a reasonable
shortcut. This list is the argument against it, written at a time when the
reasoning was clear.

---

## 9. Initial actions (v0.1)

Five actions. Deliberately small — the point of Phase 1 is a working dispatch
path, not coverage.

### `toggle_night_light`
- **Tier** 0 · **Params** none · **Reversible** yes
- **Description:** "Turn the night light on or off."
- **⚠ See §0.1 before implementing.** No clean Windows API exists. Timebox it;
  substitute `toggle_dark_mode` if it resists.

### `open_new_desktop`
- **Tier** 0 · **Params** none · **Reversible** yes
- **Description:** "Create a new virtual desktop."
- **Implementation:** synthesize `Win+Ctrl+D` via `SendInput`. The
  `IVirtualDesktopManager` COM interface is undocumented and breaks across
  Windows builds; the keystroke is stable.

### `open_application`
- **Tier** 1 · **Params** `app: AppKey` · **Reversible** yes
- **Description:** "Open an application."
- **⚠ See §0.2 before implementing.** Highest-risk action in the registry.
- **Implementation:** `APPS: dict[str, Path]` literal in source. Reject any key
  not present. The parameter is a dictionary key, never a path, never a command
  string.

```python
APPS: Final[dict[str, Path]] = {
    "notepad": Path(r"C:\Windows\System32\notepad.exe"),
    "calculator": Path(r"C:\Windows\System32\calc.exe"),
    # extend by hand, one reviewed line at a time
}
```

### `open_setting`
- **Tier** 1 · **Params** `page: SettingPage` · **Reversible** yes
- **Description:** "Open a Windows settings page."
- **Implementation:** `SettingPage` enum mapping to hardcoded `ms-settings:`
  URIs. Never construct the URI from input.
- **Excluded pages:** Windows Security, Firewall, UAC, BitLocker, Sign-in
  options. These are on the exclusion list in spirit — opening them is a step
  toward disabling protections and is not a convenience worth having.

### `shutdown_pc` / `restart_pc`
- **Tier** 2 · **Params** none · **Reversible** **no**
- **Description:** "Shut down the computer." / "Restart the computer."
- **Implementation:** `InitiateSystemShutdownExW` via `ctypes`. **Not**
  `subprocess("shutdown.exe /s")` — shelling out for this reintroduces a shell
  invocation for no benefit.
- **Requires:** typed confirmation. Rate limit: 1 per 10 minutes, hard.

---

## 10. Classifier contract

- Output domain: `{action_id} ∪ {NO_MATCH}`, enforced by constrained decoding.
- Temperature ≈ 0.
- Parameters are extracted in a second constrained pass, one per parameter,
  each restricted to its own domain. Never a free-form JSON generation step.
- **Eval set before wiring:** 100 labeled utterances across the five actions,
  plus 30 that must return `NO_MATCH`. Measure accuracy and, separately, the
  false-action rate (returned an action when `NO_MATCH` was correct). The
  second number matters more.

Screen-context OCR, when added, enters the prompt in a delimited block labeled
untrusted, with a standing rule that its contents are never instructions. This
is a defense-in-depth measure, not the security boundary — the enum constraint
is the boundary.

---

## 11. Adding a new action

1. Write the design test answer (§7) in the PR description. One sentence.
2. Confirm every parameter is `Enum`, `BoundedInt`, or `WhitelistKey`.
3. Confirm it is not on, or adjacent to, the exclusion list (§8).
4. Assign a tier by the §5 rules, not by how convenient confirmation feels.
5. Run the composition check against the existing registry.
6. Add eval-set entries: three phrasings that should hit it, one near-miss that
   should not.
7. Human review of the handler. No exceptions for "trivial" actions — the
   trivial ones are where `shell=True` gets pasted in.

---

## 12. Open questions — UNANSWERED

**Blocking Phase 2. Human decision required. See §0.3.** The recommendations
below are starting points for discussion, not decisions. Do not implement
against them.

- **Exception persistence:** do Tier 1 exceptions survive a restart, or expire?
  Recommendation: expire after 24h, forcing periodic reconsideration.
- **Rate limit granularity:** global, per-tier, or per-action? Per-action is
  more work but bounds the nuisance case tightly.
- **Dead-man switch threshold:** after how long with no human interaction do
  all exceptions auto-revoke? Recommendation: 30 minutes.
- **Concurrency:** can two actions be in flight at once? Recommendation: no —
  a serial queue removes an entire class of race condition for near-zero cost.