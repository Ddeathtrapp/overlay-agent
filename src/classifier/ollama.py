"""Ollama client.

A thin wrapper over the local Ollama HTTP API, with two jobs:

  1. Constrained decoding. Ollama's `format` parameter accepts a JSON
     Schema, which llama.cpp compiles into a grammar (XGrammar) and
     applies during sampling. Output that does not match the schema is
     not filtered out afterwards — it is never generated.

  2. Failing closed. Every failure mode here — daemon down, timeout,
     malformed response — raises. classifier.py turns that into
     NO_MATCH. An inference failure must never become an action.

Deliberately uses only the standard library. Agents cannot install
packages (CLAUDE.md), and a classifier that cannot run without `requests`
is a classifier that stops working the day a venv is rebuilt.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping

log = logging.getLogger(__name__)

DEFAULT_HOST = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen2.5-coder:7b-instruct-q4_K_M"

# Classification emits a handful of tokens. A cap this low means a model
# that ignores the schema produces a truncated failure rather than a wall
# of text, and bounds the worst-case latency of a single request.
DEFAULT_MAX_TOKENS = 64

CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 30.0

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


# --------------------------------------------------------------------------
# Errors — all of these mean "no answer", never "no match"
# --------------------------------------------------------------------------


class OllamaError(Exception):
    """Base for every failure. Callers catch this and fail closed."""


class OllamaUnavailable(OllamaError):
    """The daemon is not reachable. Usually: Ollama is not running."""


class OllamaTimeout(OllamaError):
    """The model did not answer in time. A cold load can take 10-15s;
    beyond the read timeout something is wrong."""


class OllamaProtocolError(OllamaError):
    """The response was not the shape we expect. Never guess at a
    malformed response — a partially-understood reply is worse than none."""


class NonLocalHost(OllamaError):
    """The configured host is not loopback.

    threat-model.md T9 states that screen contents never leave the
    machine, and the mitigation is "inference is local". That is a
    configuration promise unless something enforces it — so this does.
    A remote Ollama would ship OCR'd screen text to another host while
    every document still claimed it could not happen.
    """


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Completion:
    """One response, plus the timing worth logging."""

    text: str
    total_ms: float
    eval_count: int
    load_ms: float

    @property
    def was_cold(self) -> bool:
        """A cold load means the model was evicted. With
        OLLAMA_KEEP_ALIVE=-1 this should be rare after the first call;
        if it is not, keep-alive is not taking effect."""
        return self.load_ms > 500.0


def _assert_loopback(host: str) -> None:
    parsed = urllib.parse.urlparse(host)
    hostname = parsed.hostname or ""
    if hostname not in _LOOPBACK_HOSTS:
        raise NonLocalHost(
            f"refusing to use Ollama at {host!r}: inference must be local. "
            f"Screen context would otherwise leave the machine (threat-model.md T9)."
        )


class OllamaClient:
    """Blocking client for the local Ollama chat endpoint.

    One instance per process is fine; there is no connection state.
    """

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        model: str = DEFAULT_MODEL,
        *,
        connect_timeout: float = CONNECT_TIMEOUT,
        read_timeout: float = READ_TIMEOUT,
    ) -> None:
        _assert_loopback(host)
        self._host = host.rstrip("/")
        self._model = model
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout

    @property
    def model(self) -> str:
        return self._model

    # -- health ------------------------------------------------------------

    def health(self) -> tuple[bool, str]:
        """Is the daemon up and is our model pulled?

        Returns (ok, human-readable detail). Used by the CLI so a missing
        daemon produces "Ollama is not running" rather than a stack trace
        on the first utterance.
        """
        try:
            body = self._get("/api/tags")
        except OllamaError as exc:
            return False, str(exc)

        names = {m.get("name", "") for m in body.get("models", [])}
        if self._model not in names:
            return False, (
                f"model {self._model!r} is not pulled. "
                f"Run: ollama pull {self._model}"
            )
        return True, f"ollama up, {self._model} available"

    # -- inference ---------------------------------------------------------

    def complete(
        self,
        system: str,
        user: str,
        *,
        schema: Mapping[str, Any] | None = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = 0.0,
        seed: int = 0,
    ) -> Completion:
        """One non-streaming turn.

        `schema` is a JSON Schema passed as Ollama's `format`. When set,
        sampling is constrained to outputs matching it — this is the
        mechanism behind architecture.md §4's claim that the classifier's
        output DOMAIN is trusted even though its reasoning is not.

        temperature 0 and a fixed seed because this is classification.
        The same utterance should map to the same action every time; a
        classifier that is occasionally creative is a bug.
        """
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            # Request-level residency. A machine-wide OLLAMA_KEEP_ALIVE can
            # be unset, overridden, or invisible to the daemon depending on
            # how it was launched. Declaring it per request means the
            # assistant states its own requirement and cannot silently lose
            # it: a cold load costs ~13s against ~107ms warm, which is the
            # difference between a hotkey feeling instant and feeling broken.
            "keep_alive": -1,
            "options": {
                "temperature": temperature,
                "seed": seed,
                "num_predict": max_tokens,
            },
        }
        if schema is not None:
            payload["format"] = schema

        started = time.monotonic()
        body = self._post("/api/chat", payload)
        elapsed_ms = (time.monotonic() - started) * 1000.0

        try:
            text = body["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise OllamaProtocolError(
                f"response had no message.content: {body!r}"
            ) from exc

        if not isinstance(text, str):
            raise OllamaProtocolError(
                f"message.content was {type(text).__name__}, expected str"
            )

        completion = Completion(
            text=text,
            total_ms=elapsed_ms,
            eval_count=int(body.get("eval_count") or 0),
            load_ms=float(body.get("load_duration") or 0) / 1e6,
        )

        if completion.was_cold:
            log.info(
                "model cold-loaded (%.0fms). Set OLLAMA_KEEP_ALIVE=-1 to keep "
                "it resident.",
                completion.load_ms,
            )
        log.debug(
            "ollama: %d tokens in %.0fms", completion.eval_count, completion.total_ms
        )
        return completion

    # -- transport ---------------------------------------------------------

    def _post(self, path: str, payload: Mapping[str, Any]) -> dict:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self._host + path,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        return self._send(request)

    def _get(self, path: str) -> dict:
        request = urllib.request.Request(self._host + path, method="GET")
        return self._send(request)

    def _send(self, request: urllib.request.Request) -> dict:
        try:
            with urllib.request.urlopen(request, timeout=self._read_timeout) as fh:
                raw = fh.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:400]
            raise OllamaProtocolError(f"HTTP {exc.code} from ollama: {detail}") from exc
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, TimeoutError):
                raise OllamaTimeout(f"ollama did not respond within "
                                    f"{self._read_timeout:.0f}s") from exc
            raise OllamaUnavailable(
                f"cannot reach ollama at {self._host}: {reason}. Is it running?"
            ) from exc
        except TimeoutError as exc:
            raise OllamaTimeout(
                f"ollama did not respond within {self._read_timeout:.0f}s"
            ) from exc

        try:
            body = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise OllamaProtocolError(
                f"ollama returned non-JSON: {raw[:200]!r}"
            ) from exc

        if not isinstance(body, dict):
            raise OllamaProtocolError(
                f"ollama returned {type(body).__name__}, expected an object"
            )
        return body