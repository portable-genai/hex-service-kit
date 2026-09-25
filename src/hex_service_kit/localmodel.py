"""The one client every laptop ``live`` profile uses to reach a local open-weight model.

The fleet's laptop lane serves each app without a core online search tool from ONE local
model behind an OpenAI-compatible ``/chat/completions`` endpoint (MLX, Ollama, vLLM and
llama.cpp all speak it). Before this module each app that did so hand-rolled its own client,
and each learned the same three facts about local servers separately, or did not:

* **No schema is enforced.** ``response_format`` is ignored by some servers and rejected
  outright by others, so the schema is stated in the prompt, and the answer is parsed and
  validated HERE. A model that wraps its JSON in a markdown fence (Gemma does) or adds a
  sentence before it is still answering; one that omits a required field is not, and gets
  told which field before it is asked again.
* **No usage is reported.** MLX returns an empty ``usage``; a client that reads zeros from it
  reports a free call. :attr:`LocalCompletion.usage` is ``None`` when the server said nothing,
  never a fabricated zero.
* **Sampling is the caller's decision.** ``temperature=None`` sends no temperature at all, so
  drafting runs at the server's own sampling; a call that must reproduce passes ``0.0``.

The server is somebody else's process. :meth:`LocalModelClient.probe` asks it which models it
serves, and every failure message carries :data:`START_RECIPE`, the two lines that start one,
so a presenter is never told only that a URL did not answer.

Pure standard library, like the rest of the kernel: ``urllib`` for transport and a small JSON
Schema subset (:func:`schema_errors`) for validation, covering what Pydantic's
``model_json_schema()`` emits for the fleet's response models (``type``, ``properties``,
``required``, ``additionalProperties``, ``items``, ``enum``, ``const``, ``anyOf``/``oneOf``,
local ``$ref`` into ``$defs``, and the numeric and length bounds).
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from . import provenance
from .netdefaults import read_env_setting
from .observability import TokenUsage

#: The fleet's shared local model endpoint and model. Gemma 4 31B was chosen over faster,
#: larger models so a laptop result reproduces on a 48 GB MacBook.
DEFAULT_LOCAL_MODEL_URL = "http://127.0.0.1:8001/chat/completions"
DEFAULT_LOCAL_MODEL = "mlx-community/gemma-4-31b-it-8bit"
DEFAULT_TIMEOUT_SECONDS = 240.0
DEFAULT_MAX_RETRIES = 2

#: The environment variables :meth:`LocalModelSettings.from_env` reads. One set for the whole
#: fleet, because the laptop runs one model server for every app.
URL_ENV = "LOCAL_MODEL_URL"
MODEL_ENV = "LOCAL_MODEL"
TIMEOUT_ENV = "LOCAL_MODEL_TIMEOUT"

START_RECIPE = (
    "Start a local model server, then retry:\n"
    "  uv venv --python 3.13 .mlx-venv && uv pip install --python .mlx-venv mlx-vlm\n"
    f"  .mlx-venv/bin/python -m mlx_vlm.server --model {DEFAULT_LOCAL_MODEL} --port 8001"
)

_FENCE = re.compile(r"```(?:json|JSON)?\s*(.*?)```", re.DOTALL)

_JSON_INSTRUCTION = (
    "Answer with a single JSON value and nothing else: no prose before or after it and no "
    "markdown code fence. It must satisfy this JSON Schema, including every required "
    "property:\n{schema}"
)

_RETRY_INSTRUCTION = (
    "That answer was not usable: {problem}. Reply again with ONLY the corrected JSON value, "
    "starting with {{ or [ and ending with }} or ]."
)

# Servers disagree on usage field names (OpenAI: prompt/completion; MLX: input/output).
_INPUT_KEYS = ("prompt_tokens", "input_tokens")
_OUTPUT_KEYS = ("completion_tokens", "output_tokens")

#: ``(url, body, timeout) -> response body``. Injected by tests; the default is ``urllib``.
Transport = Callable[[str, bytes | None, float], bytes]


class LocalModelUnavailable(RuntimeError):
    """The local model server did not answer, or answered with something that is not a chat
    completion. The message always ends with :data:`START_RECIPE`."""


class LocalModelOutputError(ValueError):
    """The model answered, but no attempt produced JSON that satisfies the schema."""

    def __init__(self, message: str, *, last_text: str, attempts: int) -> None:
        super().__init__(message)
        self.last_text = last_text
        self.attempts = attempts


@dataclass(frozen=True)
class LocalModelSettings:
    url: str = DEFAULT_LOCAL_MODEL_URL
    model: str = DEFAULT_LOCAL_MODEL
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_retries: int = DEFAULT_MAX_RETRIES

    @classmethod
    def from_env(
        cls,
        *,
        url_env: str = URL_ENV,
        model_env: str = MODEL_ENV,
        timeout_env: str = TIMEOUT_ENV,
    ) -> LocalModelSettings:
        """Read the three settings, each unset -> the fleet default, set-and-empty -> refused."""
        url = _setting(url_env, DEFAULT_LOCAL_MODEL_URL)
        model = _setting(model_env, DEFAULT_LOCAL_MODEL)
        timeout = _setting(timeout_env, str(DEFAULT_TIMEOUT_SECONDS))
        try:
            timeout_seconds = float(timeout)
        except ValueError as exc:
            raise ValueError(f"{timeout_env} must be a number of seconds, got {timeout!r}") from exc
        return cls(url=url, model=model, timeout_seconds=timeout_seconds)

    @property
    def models_url(self) -> str:
        """The server's model listing, derived from the chat endpoint it sits beside."""
        base = self.url.rstrip("/")
        for suffix in ("/v1/chat/completions", "/chat/completions"):
            if base.endswith(suffix):
                base = base[: -len(suffix)]
                break
        return f"{base}/v1/models"


def _setting(name: str, default: str) -> str:
    setting = read_env_setting(name)
    if setting.is_configured_empty:
        raise ValueError(f"{name} is set but empty; unset it to use {default!r}, or name a value")
    return setting.value or default


@dataclass(frozen=True)
class LocalCompletion:
    """One answered call. ``data`` is the validated JSON value for a structured call."""

    text: str
    model: str
    usage: TokenUsage | None
    attempts: int = 1
    data: Any = None


def _urllib_transport(url: str, body: bytes | None, timeout: float) -> bytes:
    request = urllib.request.Request(  # noqa: S310 - the URL is operator configuration
        url,
        data=body,
        headers={"Content-Type": "application/json"} if body is not None else {},
        method="POST" if body is not None else "GET",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        payload: bytes = response.read()
        return payload


class LocalModelClient:
    """Call the shared local model; validate and retry structured output."""

    def __init__(
        self, settings: LocalModelSettings | None = None, *, transport: Transport | None = None
    ) -> None:
        self._settings = settings or LocalModelSettings()
        self._transport = transport or _urllib_transport

    @property
    def settings(self) -> LocalModelSettings:
        return self._settings

    # ------------------------------------------------------------------ #
    # Liveness
    # ------------------------------------------------------------------ #
    def probe(self) -> tuple[str, ...]:
        """Return the model ids the server lists; raise if it does not answer or lacks ours."""
        url = self._settings.models_url
        try:
            body = json.loads(self._transport(url, None, min(self._settings.timeout_seconds, 5)))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise LocalModelUnavailable(
                f"no local model server answered at {url} ({exc}).\n{START_RECIPE}"
            ) from exc
        data = body.get("data") if isinstance(body, dict) else None
        entries = [entry for entry in data or () if isinstance(entry, dict) and "id" in entry]
        ids = tuple(str(entry["id"]) for entry in entries)
        if self._settings.model not in ids:
            raise LocalModelUnavailable(
                f"the server at {url} does not serve {self._settings.model!r} "
                f"(it lists {', '.join(ids) or 'nothing'}).\n{START_RECIPE}"
            )
        return ids

    # ------------------------------------------------------------------ #
    # Calls
    # ------------------------------------------------------------------ #
    def complete(
        self,
        messages: Sequence[Mapping[str, Any]],
        *,
        temperature: float | None = None,
        max_tokens: int = 2048,
    ) -> LocalCompletion:
        """One chat completion, returned as text."""
        payload: dict[str, Any] = {
            "model": self._settings.model,
            "messages": [dict(m) for m in messages],
            "max_tokens": max_tokens,
        }
        if temperature is not None:
            payload["temperature"] = temperature
        url = self._settings.url
        try:
            raw = self._transport(
                url, json.dumps(payload).encode("utf-8"), self._settings.timeout_seconds
            )
            body = json.loads(raw)
        except (urllib.error.URLError, OSError) as exc:
            raise LocalModelUnavailable(
                f"the local model server at {url} did not answer ({exc}).\n{START_RECIPE}"
            ) from exc
        except ValueError as exc:
            raise LocalModelUnavailable(
                f"the local model server at {url} returned non-JSON ({exc}).\n{START_RECIPE}"
            ) from exc
        choices = body.get("choices") if isinstance(body, dict) else None
        if not choices or not isinstance(choices[0], dict):
            raise LocalModelUnavailable(
                f"the local model server at {url} returned no choices.\n{START_RECIPE}"
            )
        message = choices[0].get("message") or {}
        text = str(message.get("content") or "")
        answered_by = str(body.get("model") or self._settings.model)
        provenance.note_model(answered_by)
        return LocalCompletion(text=text, model=answered_by, usage=_usage(body.get("usage")))

    def complete_json(
        self,
        messages: Sequence[Mapping[str, Any]],
        *,
        schema: Mapping[str, Any] | None = None,
        validate: Callable[[Any], None] | None = None,
        temperature: float | None = None,
        max_tokens: int = 2048,
    ) -> LocalCompletion:
        """A structured call: the schema goes in the prompt, the answer is checked here.

        ``validate`` is an optional extra check (a Pydantic ``model_validate``, say) that raises
        on a value the schema admits but the caller cannot use; its message is fed back to the
        model like a schema error. Raises :class:`LocalModelOutputError` after
        ``max_retries`` corrections have all failed.
        """
        convo = [dict(m) for m in messages]
        if schema is not None:
            instruction = _JSON_INSTRUCTION.format(schema=json.dumps(schema, sort_keys=True))
            convo = _prepend_system(convo, instruction)
        attempts = 0
        last = ""
        problem = ""
        total_in = total_out = 0
        usage_seen = False
        while attempts <= self._settings.max_retries:
            attempts += 1
            answer = self.complete(convo, temperature=temperature, max_tokens=max_tokens)
            if answer.usage is not None:
                usage_seen = True
                total_in += answer.usage.input_tokens
                total_out += answer.usage.output_tokens
            last = answer.text
            try:
                value = extract_json(answer.text)
                errors = schema_errors(value, schema) if schema is not None else []
                if errors:
                    raise ValueError("; ".join(errors[:5]))
                if validate is not None:
                    validate(value)
            except ValueError as exc:
                problem = str(exc) or type(exc).__name__
                convo = [
                    *convo,
                    {"role": "assistant", "content": answer.text[:4000]},
                    {"role": "user", "content": _RETRY_INSTRUCTION.format(problem=problem)},
                ]
                continue
            return LocalCompletion(
                text=answer.text,
                model=answer.model,
                usage=TokenUsage(total_in, total_out) if usage_seen else None,
                attempts=attempts,
                data=value,
            )
        raise LocalModelOutputError(
            f"the local model gave no valid JSON in {attempts} attempts; last problem: {problem}",
            last_text=last,
            attempts=attempts,
        )


def _prepend_system(messages: list[dict[str, Any]], instruction: str) -> list[dict[str, Any]]:
    if messages and messages[0].get("role") == "system":
        first = dict(messages[0])
        first["content"] = f"{first.get('content') or ''}\n\n{instruction}".strip()
        return [first, *messages[1:]]
    return [{"role": "system", "content": instruction}, *messages]


def _usage(raw: object) -> TokenUsage | None:
    if not isinstance(raw, dict) or not raw:
        return None
    found_in = next((raw[k] for k in _INPUT_KEYS if k in raw), None)
    found_out = next((raw[k] for k in _OUTPUT_KEYS if k in raw), None)
    if found_in is None and found_out is None:
        return None
    try:
        return TokenUsage(int(found_in or 0), int(found_out or 0))
    except (TypeError, ValueError):
        return None


def extract_json(text: str) -> Any:
    """Parse the JSON value in a model's answer, tolerating a fence or surrounding prose.

    Tries, in order: the whole answer, the first fenced block, then the span from the first
    ``{`` or ``[`` to the last matching closer. Raises ``ValueError`` when none parses.
    """
    candidates = [text.strip()]
    fenced = _FENCE.search(text)
    if fenced:
        candidates.append(fenced.group(1).strip())
    for opener, closer in (("{", "}"), ("[", "]")):
        start, end = text.find(opener), text.rfind(closer)
        if start != -1 and end > start:
            candidates.append(text[start : end + 1])
    for candidate in candidates:
        if not candidate:
            continue
        try:
            return json.loads(candidate)
        except ValueError:
            continue
    raise ValueError("the answer contains no parseable JSON value")


# ---------------------------------------------------------------------- #
# A JSON Schema subset, enough for Pydantic's model_json_schema()
# ---------------------------------------------------------------------- #
_TYPES: dict[str, Callable[[Any], bool]] = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, int | float) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


def schema_errors(value: Any, schema: Mapping[str, Any] | None) -> list[str]:
    """Every way ``value`` fails ``schema``, as ``path: problem`` strings; empty when it fits."""
    if schema is None:
        return []
    errors: list[str] = []
    _check(value, schema, schema, "$", errors)
    return errors


def _resolve(schema: Mapping[str, Any], root: Mapping[str, Any]) -> Mapping[str, Any]:
    seen = 0
    while "$ref" in schema and seen < 32:
        ref = str(schema["$ref"])
        if not ref.startswith("#/"):
            return {}
        target: Any = root
        for part in ref[2:].split("/"):
            target = target.get(part, {}) if isinstance(target, Mapping) else {}
        schema = target if isinstance(target, Mapping) else {}
        seen += 1
    return schema


def _check(
    value: Any, schema: Mapping[str, Any], root: Mapping[str, Any], at: str, errors: list[str]
) -> None:
    schema = _resolve(schema, root)
    for key in ("anyOf", "oneOf"):
        if key in schema:
            branches = [b for b in schema[key] if isinstance(b, Mapping)]
            if not any(not _branch_errors(value, b, root, at) for b in branches):
                errors.append(f"{at}: matches none of the allowed shapes")
            return
    for sub in schema.get("allOf", ()):
        if isinstance(sub, Mapping):
            _check(value, sub, root, at, errors)
    declared = schema.get("type")
    if declared is not None:
        names = [declared] if isinstance(declared, str) else list(declared)
        if not any(_TYPES.get(str(n), lambda _v: True)(value) for n in names):
            errors.append(f"{at}: expected {' or '.join(map(str, names))}")
            return
    if "const" in schema and value != schema["const"]:
        errors.append(f"{at}: must equal {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{at}: must be one of {list(schema['enum'])!r}")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < int(schema["minLength"]):
            errors.append(f"{at}: shorter than {schema['minLength']}")
        if "maxLength" in schema and len(value) > int(schema["maxLength"]):
            errors.append(f"{at}: longer than {schema['maxLength']}")
    if _TYPES["number"](value):
        bounds: dict[str, Callable[[float], bool]] = {
            "minimum": lambda b: bool(value >= b),
            "maximum": lambda b: bool(value <= b),
            "exclusiveMinimum": lambda b: bool(value > b),
            "exclusiveMaximum": lambda b: bool(value < b),
        }
        for key, ok in bounds.items():
            if key in schema and not ok(float(schema[key])):
                errors.append(f"{at}: violates {key} {schema[key]}")
    if isinstance(value, dict):
        props = schema.get("properties") or {}
        for name in schema.get("required", ()):
            if name not in value:
                errors.append(f"{at}: missing required property {name!r}")
        for name, sub in props.items():
            if name in value and isinstance(sub, Mapping):
                _check(value[name], sub, root, f"{at}.{name}", errors)
        extra = schema.get("additionalProperties", True)
        for name in value:
            if name in props:
                continue
            if extra is False:
                errors.append(f"{at}: unexpected property {name!r}")
            elif isinstance(extra, Mapping):
                _check(value[name], extra, root, f"{at}.{name}", errors)
    if isinstance(value, list):
        if "minItems" in schema and len(value) < int(schema["minItems"]):
            errors.append(f"{at}: fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            errors.append(f"{at}: more than {schema['maxItems']} items")
        items = schema.get("items")
        if isinstance(items, Mapping):
            for index, item in enumerate(value):
                _check(item, items, root, f"{at}[{index}]", errors)


def _branch_errors(
    value: Any, branch: Mapping[str, Any], root: Mapping[str, Any], at: str
) -> list[str]:
    found: list[str] = []
    _check(value, branch, root, at, found)
    return found


__all__ = [
    "DEFAULT_LOCAL_MODEL",
    "DEFAULT_LOCAL_MODEL_URL",
    "MODEL_ENV",
    "START_RECIPE",
    "TIMEOUT_ENV",
    "URL_ENV",
    "LocalCompletion",
    "LocalModelClient",
    "LocalModelOutputError",
    "LocalModelSettings",
    "LocalModelUnavailable",
    "extract_json",
    "schema_errors",
]
