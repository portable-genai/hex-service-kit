"""The shared local-model client: fences, schema checks, retries, no fabricated usage."""

from __future__ import annotations

import json
import urllib.error
from typing import Any

import pytest

from hex_service_kit import TokenUsage
from hex_service_kit.localmodel import (
    DEFAULT_LOCAL_MODEL,
    START_RECIPE,
    LocalModelClient,
    LocalModelOutputError,
    LocalModelSettings,
    LocalModelUnavailable,
    extract_json,
    schema_errors,
)

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["pass", "fail"]},
        "score": {"type": "number", "minimum": 0, "maximum": 1},
        "items": {"type": "array", "items": {"$ref": "#/$defs/Item"}},
        "note": {"anyOf": [{"type": "string"}, {"type": "null"}]},
    },
    "required": ["verdict", "score"],
    "additionalProperties": False,
    "$defs": {
        "Item": {
            "type": "object",
            "properties": {"id": {"type": "integer"}},
            "required": ["id"],
        }
    },
}


class FakeServer:
    """Answers each chat call with the next scripted reply and records what it was sent."""

    def __init__(self, replies: list[str], usage: dict[str, int] | None = None) -> None:
        self.replies = list(replies)
        self.usage = usage
        self.calls: list[dict[str, Any]] = []

    def __call__(self, url: str, body: bytes | None, timeout: float) -> bytes:
        if body is None:
            return json.dumps({"data": [{"id": DEFAULT_LOCAL_MODEL}]}).encode()
        payload = json.loads(body)
        self.calls.append(payload)
        reply = {
            "model": payload["model"],
            "choices": [{"message": {"content": self.replies.pop(0)}}],
            "usage": self.usage or {},
        }
        return json.dumps(reply).encode()


def _client(server: FakeServer) -> LocalModelClient:
    return LocalModelClient(LocalModelSettings(), transport=server)


def test_a_fenced_answer_with_prose_still_parses() -> None:
    text = 'Here you go:\n```json\n{"verdict": "pass", "score": 0.9}\n```\nThanks.'
    assert extract_json(text) == {"verdict": "pass", "score": 0.9}


def test_no_json_at_all_is_a_value_error() -> None:
    with pytest.raises(ValueError, match="no parseable JSON"):
        extract_json("I cannot answer that.")


def test_schema_subset_names_each_problem() -> None:
    bad = {"verdict": "maybe", "score": 2, "items": [{"id": "x"}], "extra": 1}
    problems = schema_errors(bad, SCHEMA)
    assert any("verdict" in p and "one of" in p for p in problems)
    assert any("score" in p and "maximum" in p for p in problems)
    assert any("items[0].id" in p and "integer" in p for p in problems)
    assert any("unexpected property 'extra'" in p for p in problems)
    missing = schema_errors({"verdict": "pass"}, SCHEMA)
    assert missing == ["$: missing required property 'score'"]
    assert schema_errors({"verdict": "fail", "score": 0, "note": None}, SCHEMA) == []


def test_a_bool_is_not_a_number() -> None:
    assert schema_errors(True, {"type": "number"})
    assert schema_errors(True, {"type": "integer"})


def test_a_wrong_answer_is_retried_with_the_problem_named() -> None:
    server = FakeServer(['{"verdict": "pass"}', '```json\n{"verdict": "pass", "score": 1}\n```'])
    result = _client(server).complete_json(
        [{"role": "user", "content": "judge"}], schema=SCHEMA, temperature=0.0
    )
    assert result.data == {"verdict": "pass", "score": 1}
    assert result.attempts == 2
    retry_prompt = server.calls[1]["messages"][-1]["content"]
    assert "missing required property 'score'" in retry_prompt
    # The schema travels in the prompt, never as response_format.
    assert "response_format" not in server.calls[0]
    assert '"required"' in server.calls[0]["messages"][0]["content"]
    assert server.calls[0]["temperature"] == 0.0


def test_retries_are_bounded_and_the_last_answer_is_kept() -> None:
    server = FakeServer(["nope", "still nope", "no"])
    with pytest.raises(LocalModelOutputError) as caught:
        _client(server).complete_json([{"role": "user", "content": "x"}], schema=SCHEMA)
    assert caught.value.attempts == 3
    assert caught.value.last_text == "no"


def test_a_caller_validator_is_fed_back_like_a_schema_error() -> None:
    def no_fail(value: Any) -> None:
        if value["verdict"] == "fail":
            raise ValueError("verdict fail needs a note")

    server = FakeServer(['{"verdict": "fail", "score": 0}', '{"verdict": "pass", "score": 1}'])
    result = _client(server).complete_json(
        [{"role": "user", "content": "x"}], schema=SCHEMA, validate=no_fail
    )
    assert result.attempts == 2
    assert "verdict fail needs a note" in server.calls[1]["messages"][-1]["content"]


def test_unset_temperature_is_not_sent() -> None:
    server = FakeServer(["hello"])
    _client(server).complete([{"role": "user", "content": "hi"}])
    assert "temperature" not in server.calls[0]


def test_empty_usage_is_none_not_zero() -> None:
    server = FakeServer(["hello"])
    assert _client(server).complete([{"role": "user", "content": "hi"}]).usage is None
    counted = FakeServer(["hello"], usage={"input_tokens": 7, "output_tokens": 3})
    usage = _client(counted).complete([{"role": "user", "content": "hi"}]).usage
    assert usage == TokenUsage(7, 3)


def test_an_unreachable_server_says_how_to_start_one() -> None:
    def down(url: str, body: bytes | None, timeout: float) -> bytes:
        raise urllib.error.URLError("connection refused")

    client = LocalModelClient(transport=down)
    with pytest.raises(LocalModelUnavailable) as caught:
        client.complete([{"role": "user", "content": "hi"}])
    assert START_RECIPE in str(caught.value)
    with pytest.raises(LocalModelUnavailable):
        client.probe()


def test_probe_refuses_a_server_that_lacks_the_model() -> None:
    def other(url: str, body: bytes | None, timeout: float) -> bytes:
        assert url.endswith("/v1/models")
        return json.dumps({"data": [{"id": "some-other-model"}]}).encode()

    with pytest.raises(LocalModelUnavailable, match="some-other-model"):
        LocalModelClient(transport=other).probe()
    assert DEFAULT_LOCAL_MODEL in _client(FakeServer([])).probe()


def test_models_url_follows_the_chat_endpoint() -> None:
    assert (
        LocalModelSettings(url="http://h:1/v1/chat/completions").models_url
        == "http://h:1/v1/models"
    )
    assert (
        LocalModelSettings(url="http://h:1/chat/completions").models_url == "http://h:1/v1/models"
    )


def test_from_env_is_three_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LOCAL_MODEL_URL", raising=False)
    monkeypatch.setenv("LOCAL_MODEL", "m")
    settings = LocalModelSettings.from_env()
    assert settings.model == "m"
    assert settings.url.startswith("http://127.0.0.1:8001")
    monkeypatch.setenv("LOCAL_MODEL_URL", "  ")
    with pytest.raises(ValueError, match="set but empty"):
        LocalModelSettings.from_env()
