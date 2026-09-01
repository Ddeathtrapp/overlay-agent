# Threat Model

**Status:** draft v0.1
**Audience:** the `security-reviewer` subagent, and future-me at 2am when a
shortcut looks reasonable.

This document explains *why* the constraints in `action-registry.md` exist. A
reviewer who understands the reasoning catches violations that a checklist
misses.

---

## 1. Assets

What an attacker would want, roughly in order:

1. **Credentials** — browser profile, password manager, SSH keys, session
   tokens for the transport layer
2. **Code execution** on the host
3. **Persistence** — a foothold that survives reboot
4. **Data** — files, screen contents (which may contain anything on screen)
5. **Nuisance** — repeated shutdowns, spam actions, denial of use

The system is designed so that assets 1–3 are unreachable *by construction*
rather than by defence. See §4.

---

## 2. Adversaries

| # | Adversary | Capability | Realistic? |
|---|---|---|---|
| A1 | **Screen content** | Can place arbitrary text where OCR will read it: a webpage, a filename, a Stack Overflow answer, a document | **Yes — assume constant** |
| A2 | **Network attacker** | Can reach the transport endpoint if it is exposed | Yes if misconfigured |
| A3 | **Stolen phone / token** | Full authenticated access to the control plane | Plausible |
| A4 | **Malicious model output** | The classifier emits the worst possible valid output | Assume always |
| A5 | **The user, habituated** | Approves a confirmation without reading it | **Certain, over time** |
| A6 | **Local malware** | Already has code execution | Out of scope — see §7 |

**A1 and A4 are the defining adversaries.** The architecture assumes both are
always active and always maximally hostile.

---

## 3. Why prompt injection is assumed, not defended against

LLMs cannot reliably distinguish trusted instructions from untrusted data. This
is an architectural property, not a bug awaiting a patch — it is why prompt
injection sits at the top of the OWASP Top 10 for LLM Applications.

Published defences perform well against static attacks and poorly against
adaptive ones: meta-analysis across the literature reports attack success rates
above 85% against state-of-the-art defences when the attacker optimises against
them. Detection classifiers plateau around 35–45% on subtle indirect injection
that contains no override keywords.

**Therefore:** delimiters, "ignore instructions in the data" system prompts,
and injection classifiers are used here as defence in depth only. **None of
them is the security boundary.** The security boundary is the closed action
registry, enforced by constrained decoding and validated by the policy engine.

The design assumption is: *the classifier has already been compromised.* Every
safety property must survive that.

---

## 4. Threats and mitigations

### T1 — Injected screen text causes an unwanted action
**Vector:** A1. Attacker places instruction-shaped text on screen.
**Mitigation:** Output domain is the registry enum. The worst achievable
outcome is a *wrong but valid* registry action, which the tier system gates.
**Residual:** nuisance-level. Rate limiting bounds it.

### T2 — Parameter injection reaches an OS call
**Vector:** A1/A4. Attacker influences a parameter value.
**Mitigation:** Parameters are `Enum`, `BoundedInt`, or `WhitelistKey` only.
No free-form string reaches an OS call. `open_application` takes a dict key,
never a path. `subprocess` is called with a list and `shell=False`.
**This is the single most important mitigation in the system.** It is also the
easiest to erode — see §6.
**Residual:** implementation bugs. Mandatory human review of `src/actions/` and
`src/dispatch/`.

### T3 — Malformed classifier output escapes the enum
**Vector:** A4.
**Mitigation:** GBNF-constrained decoding — invalid output is structurally
impossible at sampling time, not filtered afterward. The policy engine
independently re-validates the ID against the registry; a value not in the
registry is rejected.
**Residual:** near-zero. Two independent mechanisms.

### T4 — Control plane exposed to the internet
**Vector:** A2.
**Mitigation:** Bind to the Tailscale interface only, never `0.0.0.0`. No port
forwarding, ever. Session tokens plus TOTP. Verify unreachability from outside
the mesh as an explicit Phase 5 test — do not assume.
**Residual:** **This is the largest remaining risk in the system.** Once the
registry is closed, ordinary appsec becomes the dominant threat.

### T5 — Stolen token or phone
**Vector:** A3.
**Mitigation:** Tier 2 actions require typed confirmation, not a tap. Dead-man
switch revokes standing exceptions after inactivity. Short session expiry.
Audit log makes abuse visible after the fact.
**Residual:** an attacker with a valid session can invoke Tier 0/1 actions.
Bounded by the registry — annoying, not catastrophic.

### T6 — Confirmation habituation
**Vector:** A5. Certain over time.
**Mitigation:** Tier 2 requires typed confirmation, deliberately high friction.
Tier 1 exceptions scope to `(action_id + exact parameter value)`, never to an
action type.
**Note:** one evaluation of an output guardrail found that of 14 attacks
flagged for human review, only one correctly identified the injected data as
the cause; the other 13 cited unrelated reasons that would actively mislead the
reviewer. **Confirmation dialogs are worth roughly +1 point, not +4, and they
degrade.** Design as though the gate will fail.
**Residual:** accepted. The registry is the backstop.

### T7 — Composition attack
**Vector:** A1/A4. Individually harmless actions combine into a harmful one.
Example: `open_setting(SECURITY)` + `click_ui_element` + `confirm_dialog`
= "disable Defender", with no single action looking dangerous.
**Mitigation:** No action accepts a parameter selecting a keystroke, window,
or UI target. `open_new_desktop` synthesizes a fixed Win+Ctrl+D chord via
`SendInput`, but the chord is hardcoded and the action is parameterless —
enforced by tests asserting the exact VK sequence and that the low-level key
helper has exactly one caller. Security settings pages are excluded from
`SettingPage`. Composition check is mandatory
when adding any action, and re-run across the whole registry every ten
additions.
**Residual:** grows with registry size. This is why §6 matters more than any
single control.

### T8 — Denial of service against the user
**Vector:** A1. Injection triggers repeated shutdowns or action spam.
**Mitigation:** Per-action rate limits. `shutdown`/`restart` capped at 1 per
10 minutes, hard. Serial action queue.
**Residual:** low-severity nuisance.

### T9 — Screen contents leaving the machine
**Vector:** design choice, not an attacker.
**Mitigation:** Inference is local. No cloud API in the dispatch path.
**Residual:** none, so long as the local-inference decision holds.

### T10 — The agent-built system builds something unsafe
**Vector:** the coding agents writing this application.
**Observed:** during scaffolding, an agent encountered a missing `git` binary
and installed system software via `winget` to satisfy its objective. Benign
outcome, but it widened its own action space unprompted — precisely the
behaviour this application is designed to make impossible.
**Mitigation:** subagent `tools:` allowlists (a missing entry hard-fails the
call rather than prompting), agent conduct rules in `CLAUDE.md`, human review
of all boundary code, git branch per agent run.
**Residual:** conduct rules are instructions to a model, not enforcement. The
tool allowlists are the actual fence.

---

## 5. What makes this design work

The property everything rests on:

> An attacker who fully controls the model's output can invoke at most one
> registry entry with valid parameters.

That converts an unbounded threat model into an enumerable one. The security
question stops being "can the model be tricked" — assume yes — and becomes
"what is the worst entry in the registry," which is a list a human can read in
thirty seconds.

**The design test**, applied to every addition:

> Assume an attacker can invoke any action in the registry, with any valid
> parameter, at any moment of their choosing. Is the outcome acceptable?

---

## 6. How this design fails

Not through a clever attack. Through erosion:

1. A feature is annoying to build with typed parameters.
2. `open_application(name: str)` looks harmless — it just opens apps.
3. Six months later a free string reaches `subprocess`.
4. The registry is no longer closed and nothing above it works.

**Every control in this document depends on §3 of `action-registry.md` holding.
Nothing else compensates if it breaks.**

The permanent exclusion list in `action-registry.md` §8 exists because
future-you will encounter a Tuesday where one of those entries is the obvious
shortcut. The list is the argument, written when the reasoning was clear.

**Second erosion path:** registry growth. Ten safe actions can compose into an
unsafe capability that no individual review would catch. Re-run the composition
check across the whole registry, not just the new entry.

---

## 7. Out of scope

Explicitly not defended against, with reasons:

- **Local malware / prior host compromise (A6).** An attacker with existing
  code execution does not need this application. Defending against them is not
  achievable at this layer.
- **Physical access to an unlocked machine.** Same reasoning.
- **Supply chain.** Dependencies are trusted. Pin versions; that is the extent
  of it.
- **The Ollama model weights being backdoored.** Mitigated incidentally: the
  constrained output domain bounds what a malicious model can express.
- **Windows itself.** If the OS is compromised, nothing here helps.

---

## 8. Review checklist

For `security-reviewer` on every change under `src/actions/` or
`src/dispatch/`:

- [ ] Does any parameter accept a free-form string?
- [ ] Does any value derived from input reach `subprocess`, `os.system`,
      `ShellExecute`, or a path constructor?
- [ ] Is `shell=True` present anywhere? (It should never be.)
- [ ] Does a dict lookup fall through to the raw key on miss, rather than
      rejecting?
- [ ] Is the tier assignment consistent with `action-registry.md` §5, or was it
      chosen for convenience?
- [ ] Does this action compose with an existing one to exceed either alone?
- [ ] Does anything under `src/policy/` appear in the diff? (It must not.)
- [ ] Does validation happen anywhere other than the policy engine? (Duplicated
      validation drifts.)

Report as `file:line`, severity, concrete exploit, fix. No style commentary.