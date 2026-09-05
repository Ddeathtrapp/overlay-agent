"""Two-pass classification.

Pass 1 selects an action id from the registry enum, or NO_MATCH.
Pass 2 extracts each parameter, one constrained call per parameter.

What this module returns is a PROPOSAL: an action id and raw parameter
strings. It does not build an ActionRequest, does not choose a Source,
and never touches a handler. The caller stamps the source (threat-model.md
T12) and the policy engine decides.

Two rules shape everything here:

  - Never raise. Every failure — daemon down, timeout, unparseable
    output, an undeterminable parameter — becomes NO_MATCH with a reason.
    An inference failure must never become an action, and the only way to
    guarantee that is to have no path where one produces a value.

  - Never pre-parse. Parameters come back as raw strings and go to the
    engine unvalidated. Validation lives in ParamSpec.parse, called by
    the policy engine, and a second copy here would drift from it
    (action-registry.md §4).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from .ollama import OllamaClient, OllamaError
from .schema import (
    NO_MATCH,
    UnsupportedParamSpec,
    build_action_schema,
    build_param_prompt,
    build_param_schema,
    build_system_prompt,
    format_user_prompt,
    read_action_id,
    read_param_value,
)

log = logging.getLogger(__name__)


class Reason(Enum):
    """Why the classifier returned what it did.

    NO_MATCH is one outcome with several causes, and the caller needs to
    tell them apart: "I didn't understand that" and "the model isn't
    running" deserve different messages. Collapsing them would hide a
    dead daemon behind an apparent comprehension failure.
    """

    MATCHED = "matched"
    NO_ACTION_MATCHED = "no action matched"
    PARAM_UNDETERMINED = "parameter could not be determined"
    CLASSIFIER_UNAVAILABLE = "classifier unavailable"
    REGISTRY_ERROR = "registry could not be described to the model"


@dataclass(frozen=True, slots=True)
class Classification:
    """A proposal. Not permission to do anything."""

    action_id: str
    raw_params: Mapping[str, str] = field(default_factory=dict)
    reason: Reason = Reason.MATCHED
    detail: str = ""
    elapsed_ms: float = 0.0

    @property
    def matched(self) -> bool:
        return self.action_id != NO_MATCH

    def describe(self) -> str:
        """One line for a human."""
        if self.matched:
            args = " ".join(f"{k}={v}" for k, v in sorted(self.raw_params.items()))
            return f"{self.action_id} {args}".strip()
        if self.detail:
            return f"{self.reason.value}: {self.detail}"
        return self.reason.value


def _no_match(reason: Reason, detail: str, started: float) -> Classification:
    return Classification(
        action_id=NO_MATCH,
        reason=reason,
        detail=detail,
        elapsed_ms=(time.monotonic() - started) * 1000.0,
    )


class Classifier:
    """Utterance in, proposal out."""

    def __init__(self, registry: Sequence[Any], client: OllamaClient | None = None) -> None:
        self._registry = registry
        self._client = client or OllamaClient()

    def health(self) -> tuple[bool, str]:
        return self._client.health()

    # ----------------------------------------------------------------------

    def classify(
        self, utterance: str, screen_context: str | None = None
    ) -> Classification:
        """Map an utterance to an action proposal.

        `screen_context`, when present, is untrusted text from the screen.
        It is passed to the model as data inside a delimited block, and
        the CALLER must stamp Source.SCREEN_CONTEXT on the resulting
        request. This module cannot do that for them — it does not know
        where the utterance came from, and inferring it here would give a
        compromised classifier a say in its own provenance.
        """
        started = time.monotonic()

        if not utterance or not utterance.strip():
            return _no_match(Reason.NO_ACTION_MATCHED, "empty utterance", started)

        has_context = bool(screen_context)

        # --- pass 1: which action ----------------------------------------
        try:
            schema = build_action_schema(self._registry)
            system = build_system_prompt(self._registry, with_screen_context=has_context)
        except (ValueError, UnsupportedParamSpec) as exc:
            log.exception("could not build action schema")
            return _no_match(Reason.REGISTRY_ERROR, str(exc), started)

        user = format_user_prompt(utterance, screen_context)

        try:
            completion = self._client.complete(system, user, schema=schema)
        except OllamaError as exc:
            log.warning("pass 1 failed: %s", exc)
            return _no_match(Reason.CLASSIFIER_UNAVAILABLE, str(exc), started)

        action_id = read_action_id(completion.text, self._registry)
        if action_id == NO_MATCH:
            return _no_match(Reason.NO_ACTION_MATCHED, utterance[:80], started)

        action = next((a for a in self._registry if a.id == action_id), None)
        if action is None:  # read_action_id already checks; belt and braces
            return _no_match(Reason.NO_ACTION_MATCHED, action_id, started)

        # --- pass 2: each parameter, separately ---------------------------
        raw_params: dict[str, str] = {}
        for spec in action.params:
            value = self._extract(action, spec, utterance, screen_context, has_context)
            if value is None:
                # A parameterised action whose parameter is unknown is not
                # an action to run. Refusing beats defaulting: pass 2 is
                # constrained to the parameter's domain, so a guess here
                # would be a VALID wrong value, which nothing downstream
                # can reject. See action-registry.md §10.
                return _no_match(
                    Reason.PARAM_UNDETERMINED,
                    f"{action_id}.{spec.name}",
                    started,
                )
            raw_params[spec.name] = value

        return Classification(
            action_id=action_id,
            raw_params=raw_params,
            reason=Reason.MATCHED,
            elapsed_ms=(time.monotonic() - started) * 1000.0,
        )

    # ----------------------------------------------------------------------

    def _extract(
        self,
        action: Any,
        spec: Any,
        utterance: str,
        screen_context: str | None,
        has_context: bool,
    ) -> str | None:
        """One constrained call for one parameter. None on any failure."""
        try:
            schema = build_param_schema(spec)
        except UnsupportedParamSpec as exc:
            log.error("cannot describe parameter %s: %s", spec.name, exc)
            return None

        system = build_param_prompt(action, spec)
        if has_context:
            from .schema import _SCREEN_CONTEXT_RULES

            system += _SCREEN_CONTEXT_RULES
        user = format_user_prompt(utterance, screen_context)

        try:
            completion = self._client.complete(system, user, schema=schema)
        except OllamaError as exc:
            log.warning("param extraction failed for %s: %s", spec.name, exc)
            return None

        value = read_param_value(completion.text)
        if value is None:
            return None

        # Always a string. ParamSpec.parse rejects non-str by design — that
        # rejection exists so a JSON caller cannot smuggle an int past a
        # bounded-int check, and the classifier must not be the one caller
        # exempt from it.
        return str(value)