"""The pills' source: what the adapters noted during one request, as two headers."""

from __future__ import annotations

import json

from fastapi import FastAPI
from fastapi.testclient import TestClient

from hex_service_kit import provenance
from hex_service_kit.localmodel import LocalModelClient
from hex_service_kit.web import install_answer_provenance


def _app() -> FastAPI:
    app = FastAPI()
    install_answer_provenance(app)

    @app.get("/sync")
    def sync_endpoint() -> dict[str, str]:  # runs in the worker threadpool
        provenance.note_model("gemini-3.5-flash")
        provenance.note_model("gemini-3.5-flash")
        provenance.note_search()
        return {"ok": "yes"}

    @app.get("/async")
    async def async_endpoint() -> dict[str, str]:
        provenance.note_model("model-a")
        provenance.note_model("model-b")
        return {"ok": "yes"}

    @app.get("/none")
    def silent() -> dict[str, str]:
        return {"ok": "yes"}

    return app


def test_a_sync_endpoint_in_a_worker_thread_still_reaches_the_headers() -> None:
    response = TestClient(_app()).get("/sync")
    assert response.headers["x-answered-by"] == "gemini-3.5-flash"
    assert response.headers["x-search-used"] == "true"
    assert "X-Answered-By" in response.headers["access-control-expose-headers"]


def test_distinct_models_are_named_in_call_order() -> None:
    response = TestClient(_app()).get("/async")
    assert response.headers["x-answered-by"] == "model-a, model-b"
    assert "x-search-used" not in response.headers


def test_a_request_that_noted_nothing_names_no_model() -> None:
    response = TestClient(_app()).get("/none")
    assert "x-answered-by" not in response.headers
    assert "x-search-used" not in response.headers


def test_requests_do_not_share_a_record() -> None:
    client = TestClient(_app())
    client.get("/sync")
    assert "x-answered-by" not in client.get("/none").headers


def test_outside_a_scope_noting_is_a_no_op() -> None:
    provenance.note_model("nobody-listens")
    assert provenance.current() is None


def test_the_local_model_client_notes_the_model_that_answered() -> None:
    def server(url: str, body: bytes | None, timeout: float) -> bytes:
        reply = {"model": "served-model", "choices": [{"message": {"content": "hi"}}]}
        return json.dumps(reply).encode()

    with provenance.scope() as record:
        LocalModelClient(transport=server).complete([{"role": "user", "content": "hi"}])
    assert record.models == ["served-model"]
