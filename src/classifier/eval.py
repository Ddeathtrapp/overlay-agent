"""Classifier eval harness — a developer tool, not part of the dispatch path.

This module reads labeled utterances, runs them through `Classifier`, and
reports accuracy, parameter accuracy, and false-action rate SEPARATELY
(action-registry.md §10: "the second number [false-action rate] matters
more" — never collapse these into one score).

It constructs a `Classifier` directly against the registry in
`src/actions/`. It never imports or constructs a `PolicyEngine`: this is a
pre-wiring diagnostic (§10 "before wiring the classifier to anything"),
not a caller in the dispatch path, and `src/policy/` is human-owned.

Working directory
------------------
Run this from `src/`, NOT the repo root and NOT from `src/classifier/`:

    cd C:\\Scripts\\overlay-agent\\src
    ..\\.venv\\Scripts\\python.exe -m classifier.eval

Verified against this exact invocation. `python -m pkg.mod` puts the
current working directory at `sys.path[0]`; this module imports both
`classifier` (its own package) and `actions` (a sibling package under
`src/`), and `src/` is the only cwd from which both resolve without a
`sys.path` hack. Running from the repo root fails to import `classifier`
as `-m`'s target package; running from `src/classifier/` fails to import
`actions`. Neither is patched around here — if the cwd is wrong, the
`ImportError` should surface, not be papered over.

Eval-set honesty
-----------------
docs/action-registry.md §10 calls for 100 labeled utterances across the
registry plus 30 that must return NO_MATCH. `tests/eval/phase1.jsonl` has
far fewer rows than that (this harness prints the exact counts on every
run). Numbers produced here are indicative only and do NOT constitute
meeting the §10 gate — the report says so every time, on purpose.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from actions import REGISTRY, lookup

from .classify import Classification, Classifier, Reason
from .schema import NO_MATCH

# §10's target eval set shape. Used only to print an honesty comparison —
# never to fabricate rows or reshape the real eval file.
_TARGET_ACTION_ROWS = 100
_TARGET_NO_MATCH_ROWS = 30

# Fixed, innocuous, and NOT one of the eval rows: used only to pay the
# one-time model-load cost before timing starts. Its result is discarded
# unconditionally — never scored, never counted, never printed as a row.
_WARMUP_UTTERANCE = "what's the weather like today"

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_DATA = _REPO_ROOT / "tests" / "eval" / "phase1.jsonl"

_EXCLUDED_REASONS = (Reason.CLASSIFIER_UNAVAILABLE, Reason.REGISTRY_ERROR)


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Row:
    utterance: str
    expect: str
    params: dict[str, str]
    note: str = ""
    line_no: int = 0


@dataclass(frozen=True, slots=True)
class Outcome:
    row: Row
    classification: Classification


def load_rows(path: Path) -> list[Row]:
    rows: list[Row] = []
    with path.open("r", encoding="utf-8") as fh:
        for line_no, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()
            if not line:
                continue
            body = json.loads(line)
            rows.append(
                Row(
                    utterance=body["utterance"],
                    expect=body["expect"],
                    params=dict(body.get("params") or {}),
                    note=body.get("note", ""),
                    line_no=line_no,
                )
            )
    return rows


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _action_expects_params(action_id: str) -> bool:
    """Ground truth from the registry, not from what the model returned."""
    try:
        action = lookup(action_id)
    except KeyError:
        return False
    return bool(action.params)


def _recover_pass1_action(detail: str) -> str | None:
    """PARAM_UNDETERMINED's detail is f"{action_id}.{param_name}" (classify.py).

    Recovering it is the only way to tell "pass 1 picked the right action
    but pass 2 failed" apart from "pass 1 never recognised the action" —
    both collapse to action_id == NO_MATCH otherwise.
    """
    if "." not in detail:
        return None
    return detail.rsplit(".", 1)[0]

def _case_only_mismatch(expected: dict, actual: dict) -> bool:
    """True if the two param dicts differ ONLY by string case.

    Comparison elsewhere stays exact (case-sensitive) per §10/schema.py:
    enum member names and whitelist keys are case-sensitive domains. This
    is purely a diagnostic to flag "this is a real pass-2 finding, not a
    harness quirk" — it never feeds into the pass/fail verdict.
    """
    if expected == actual:
        return False
    if set(expected.keys()) != set(actual.keys()):
        return False
    all_ci_equal = all(
        str(v).lower() == str(actual[k]).lower() for k, v in expected.items()
    )
    any_exact_diff = any(v != actual[k] for k, v in expected.items())
    return all_ci_equal and any_exact_diff


def _is_parameterized_row(row: Row) -> bool:
    """Ground-truth latency bucket: did the expected action require a
    pass-2 extraction call at all? NO_MATCH rows only ever run pass 1."""
    if row.expect == NO_MATCH:
        return False
    return _action_expects_params(row.expect)


def _mean(values: Sequence[float]) -> float:
    return statistics.fmean(values) if values else float("nan")


def _p95(values: Sequence[float]) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    idx = min(len(ordered) - 1, math.ceil(0.95 * len(ordered)) - 1)
    return ordered[idx]


def _fmt_params(params: dict) -> str:
    if not params:
        return "{}"
    return "{" + ", ".join(f"{k}={v!r}" for k, v in sorted(params.items())) + "}"


def _honesty_line(action_rows: int, no_match_rows: int) -> str:
    """Derive the honesty message from the actual counts, every time.

    A hardcoded verdict goes stale the moment the data file changes size
    in either direction -- the same defect class as a hardcoded whitelist
    in a description (§10). This computes the shortfall (or its absence)
    fresh on each run so the printed sentence can never assert the
    opposite of what the row counts two lines above just reported.
    """
    action_short = max(0, _TARGET_ACTION_ROWS - action_rows)
    no_match_short = max(0, _TARGET_NO_MATCH_ROWS - no_match_rows)
    target = f"{_TARGET_ACTION_ROWS} action rows + {_TARGET_NO_MATCH_ROWS} NO_MATCH rows"
    if action_short or no_match_short:
        shortfall = f"{action_short} action row(s) and {no_match_short} NO_MATCH row(s)"
        return (
            f"action-registry.md S10 calls for {target}. This run has "
            f"{action_rows} + {no_match_rows}, short by {shortfall}. These "
            "numbers are indicative only and do NOT satisfy the S10 "
            "eval-set gate."
        )
    return (
        f"action-registry.md S10 calls for {target}. This run has "
        f"{action_rows} + {no_match_rows}, meeting or exceeding the "
        "target row counts -- the S10 eval-set size gate is met. This is "
        "a statement about row counts only: it says nothing about whether "
        "the rates reported below are good."
    )


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------


def run(rows: Iterable[Row], classifier: Classifier) -> list[Outcome]:
    """Sequentially, on purpose — one 7B call in flight at a time, per §10's
    "run rows sequentially" (concurrency would also make timing meaningless)."""
    outcomes: list[Outcome] = []
    for row in rows:
        classification = classifier.classify(row.utterance)
        outcomes.append(Outcome(row=row, classification=classification))
    return outcomes


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def report(outcomes: list[Outcome], data_path: Path) -> int:
    """Prints the report. Returns the process exit code."""
    total = len(outcomes)
    no_match_target_rows = [o for o in outcomes if o.row.expect == NO_MATCH]
    action_target_rows = [o for o in outcomes if o.row.expect != NO_MATCH]

    print("=" * 78)
    print("Overlay-agent classifier eval")
    print("=" * 78)
    print(f"Data file: {data_path}")
    print(
        f"Rows: {total} total "
        f"({len(action_target_rows)} expect an action, "
        f"{len(no_match_target_rows)} expect NO_MATCH)"
    )
    print(f"HONESTY: {_honesty_line(len(action_target_rows), len(no_match_target_rows))}")
    print()

    # -- exclude CLASSIFIER_UNAVAILABLE / REGISTRY_ERROR from all scoring --
    excluded = [o for o in outcomes if o.classification.reason in _EXCLUDED_REASONS]
    scored = [o for o in outcomes if o.classification.reason not in _EXCLUDED_REASONS]

    print("-" * 78)
    print(f"EXCLUDED FROM SCORING: {len(excluded)} row(s)")
    print("-" * 78)
    if excluded:
        print(
            "These rows returned CLASSIFIER_UNAVAILABLE or REGISTRY_ERROR, "
            "not a real classification. A dead daemon returns NO_MATCH for "
            "every row, which would otherwise look like a perfect "
            "false-action rate -- they are excluded from all three metrics "
            "below and counted here instead."
        )
        for o in excluded:
            c = o.classification
            print(
                f"  [{c.reason.value}] line {o.row.line_no}: "
                f"{o.row.utterance!r} -- {c.detail}"
            )
    else:
        print("(none)")
    print()

    no_match_rows = [o for o in scored if o.row.expect == NO_MATCH]
    action_rows = [o for o in scored if o.row.expect != NO_MATCH]
    param_expected_rows = [o for o in action_rows if o.row.params]

    # -- 1. FALSE-ACTION RATE (printed first, most prominent) --------------
    false_action_outcomes = [o for o in no_match_rows if o.classification.matched]
    fa_n = len(false_action_outcomes)
    fa_d = len(no_match_rows)

    print("#" * 78)
    print("1. FALSE-ACTION RATE  (most important number in this report)")
    print("#" * 78)
    if fa_d:
        pct = 100.0 * fa_n / fa_d
        print(f"  {fa_n}/{fa_d}  ({pct:.1f}%)")
    else:
        print("  no NO_MATCH rows were scored -- cannot compute")
    for o in false_action_outcomes:
        c = o.classification
        print(
            f"    FALSE ACTION: {o.row.utterance!r} -> "
            f"{c.action_id} {_fmt_params(dict(c.raw_params))} "
            f"(expected NO_MATCH)"
        )
    print()

    # -- 2. ACTION ACCURACY -------------------------------------------------
    print("=" * 78)
    print("2. ACTION ACCURACY  (over rows where expect != NO_MATCH)")
    print("=" * 78)
    action_hits = 0
    action_lines: list[str] = []
    for o in action_rows:
        c = o.classification
        if c.reason == Reason.PARAM_UNDETERMINED:
            selected = _recover_pass1_action(c.detail)
        else:
            selected = c.action_id
        correct = selected == o.row.expect
        action_hits += correct
        status = "PASS" if correct else "FAIL"
        note = ""
        if c.reason == Reason.PARAM_UNDETERMINED:
            note = "  [pass-1 result recovered from PARAM_UNDETERMINED detail]"
        action_lines.append(
            f"    [{status}] {o.row.utterance!r} -> expected {o.row.expect!r}, "
            f"got {selected!r}{note}"
        )
    a_d = len(action_rows)
    if a_d:
        print(f"  {action_hits}/{a_d}  ({100.0 * action_hits / a_d:.1f}%)")
    else:
        print("  no action rows were scored -- cannot compute")
    for line in action_lines:
        print(line)
    print()

    # -- 3. PARAMETER ACCURACY ----------------------------------------------
    print("=" * 78)
    print("3. PARAMETER ACCURACY  (over rows that expect non-empty params)")
    print("=" * 78)
    param_hits = 0
    param_lines: list[str] = []
    for o in param_expected_rows:
        c = o.classification
        actual_params = dict(c.raw_params)
        exact_match = actual_params == o.row.params
        param_hits += exact_match
        status = "PASS" if exact_match else "FAIL"
        line = (
            f"    [{status}] {o.row.utterance!r} -> expected "
            f"{_fmt_params(o.row.params)}, got {_fmt_params(actual_params)}"
        )
        if not exact_match and _case_only_mismatch(o.row.params, actual_params):
            line += (
                "  [CASE-ONLY MISMATCH -- comparison is case-sensitive by "
                "design (schema.py: enum member names / whitelist keys are "
                "case-sensitive domains); this is a genuine pass-2 finding, "
                "not a harness artifact]"
            )
        param_lines.append(line)
    p_d = len(param_expected_rows)
    if p_d:
        print(f"  {param_hits}/{p_d}  ({100.0 * param_hits / p_d:.1f}%)")
    else:
        print("  no rows expect non-empty params -- cannot compute")
    for line in param_lines:
        print(line)
    print()

    # -- PARAM_UNDETERMINED, reported on its own -----------------------------
    undetermined = [o for o in scored if o.classification.reason == Reason.PARAM_UNDETERMINED]
    print("-" * 78)
    print(f"PARAM_UNDETERMINED (pass-2 failures): {len(undetermined)} row(s)")
    print("-" * 78)
    print(
        "These collapse to action_id == NO_MATCH just like a pass-1 miss, "
        "but reason distinguishes them: pass 1 picked an action, pass 2 "
        "could not determine one of its parameters. Reported separately so "
        "a pass-2 failure is never misread as pass-1 not recognising the "
        "request."
    )
    for o in undetermined:
        c = o.classification
        recovered = _recover_pass1_action(c.detail)
        print(f"    line {o.row.line_no}: {o.row.utterance!r} -> {c.detail} "
              f"(pass-1 action recovered: {recovered!r})")
    print()

    # -- Latency --------------------------------------------------------------
    print("=" * 78)
    print("LATENCY (elapsed_ms, scored rows only)")
    print("=" * 78)
    parameterless_ms = [
        o.classification.elapsed_ms for o in scored if not _is_parameterized_row(o.row)
    ]
    parameterized_ms = [
        o.classification.elapsed_ms for o in scored if _is_parameterized_row(o.row)
    ]
    print(
        f"  parameterless (pass 1 only, incl. NO_MATCH-expected rows): "
        f"n={len(parameterless_ms)} mean={_mean(parameterless_ms):.0f}ms "
        f"p95={_p95(parameterless_ms):.0f}ms"
    )
    print(
        f"  parameterised (pass 1 + pass 2):                          "
        f"n={len(parameterized_ms)} mean={_mean(parameterized_ms):.0f}ms "
        f"p95={_p95(parameterized_ms):.0f}ms"
    )
    print()

    # -- Full per-row detail ---------------------------------------------------
    print("=" * 78)
    print("PER-ROW DETAIL (all scored rows)")
    print("=" * 78)
    for o in scored:
        c = o.classification
        if o.row.expect == NO_MATCH:
            ok = not c.matched
        else:
            if c.reason == Reason.PARAM_UNDETERMINED:
                ok = False
            else:
                ok = c.action_id == o.row.expect and dict(c.raw_params) == o.row.params
        status = "PASS" if ok else "FAIL"
        print(
            f"  [{status}] line {o.row.line_no:>3} "
            f"({c.elapsed_ms:7.0f}ms) {o.row.utterance!r}"
        )
        print(
            f"           expected: {o.row.expect} {_fmt_params(o.row.params)}"
        )
        print(
            f"           actual:   {c.action_id} {_fmt_params(dict(c.raw_params))} "
            f"[{c.reason.value}]"
        )
    print()

    print("=" * 78)
    print("SUMMARY")
    print("=" * 78)
    print(f"  excluded (CLASSIFIER_UNAVAILABLE / REGISTRY_ERROR): {len(excluded)}")
    print(f"  false-action rate:  {fa_n}/{fa_d}" if fa_d else "  false-action rate:  n/a")
    print(f"  action accuracy:    {action_hits}/{a_d}" if a_d else "  action accuracy:    n/a")
    print(f"  parameter accuracy: {param_hits}/{p_d}" if p_d else "  parameter accuracy: n/a")
    print(f"  PARAM_UNDETERMINED: {len(undetermined)}")
    print(
        f"  NOTE: {_honesty_line(len(action_target_rows), len(no_match_target_rows))}"
    )

    return 1 if excluded else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="classifier.eval",
        description="Run the classifier eval set and report accuracy, "
        "parameter accuracy, and false-action rate SEPARATELY.",
    )
    parser.add_argument(
        "--data",
        type=Path,
        default=_DEFAULT_DATA,
        help=f"path to the eval JSONL file (default: {_DEFAULT_DATA})",
    )
    args = parser.parse_args(argv)

    classifier = Classifier(REGISTRY)

    ok, detail = classifier.health()
    if not ok:
        print("Ollama is unreachable or the model is not pulled; refusing to run.")
        print(f"  detail: {detail}")
        print("No rows were run. Nothing was scored.")
        return 1
    print(f"Ollama health: ok -- {detail}")

    try:
        rows = load_rows(args.data)
    except FileNotFoundError:
        print(f"Eval data file not found: {args.data}")
        return 1
    if not rows:
        print(f"No rows found in {args.data}")
        return 1

    # Warm-up: pays the one-time model-load cost (observed ~11.7s cold vs.
    # ~365ms steady-state) before timing starts, so the reported latencies
    # are steady-state rather than dragged up by a cold-load outlier. Fixed
    # utterance, not an eval row; result is discarded unconditionally --
    # not scored, not counted, not printed as a row.
    print(f"Warm-up call ({_WARMUP_UTTERANCE!r}) -- discarding result, not scored...")
    classifier.classify(_WARMUP_UTTERANCE)
    print("Warm-up complete. Timed run starting now.")

    outcomes = run(rows, classifier)
    return report(outcomes, args.data)


if __name__ == "__main__":
    sys.exit(main())
