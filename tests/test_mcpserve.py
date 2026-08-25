"""Serving a governed tool catalog over MCP, exercised through a real client session.

The catalogs these repos declare are strict on purpose: every tool carries an explicit JSON
Schema with ``additionalProperties: false``, so an argument nobody designed for cannot arrive.
Declaring that is free. The tests here are about whether it is TRUE of the served surface,
which is a different claim and the one a caller actually relies on.

Everything runs over the SDK's in-memory streams: a real client, a real server, a real
``server/discover`` exchange, no socket and no subprocess, so the offline gate exercises the
same code path a client would. What is asserted is deliberately narrow:

* the connection runs on the MODERN stateless era (2026-07-28), and the deprecated handshake
  era is refused rather than quietly served;
* the served tool list is the catalog's, not a copy that can drift from it;
* a tool the catalog does not declare is refused, and so is one the catalog declares but
  nothing can answer, because both are ways for the served surface to stop matching the
  governed one;
* arguments are judged by the tool's OWN declared schema;
* the two evidence tools read the ledger and never reshape it.

Each check below was observed red against a deliberate defect first; those defects are kept as
the falsification cases at the bottom rather than described in a comment.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anyio
import pytest

from hex_service_kit.audit import HashChainedAuditLog
from hex_service_kit.mcpserve import (
    AUDIT_EXPORT_TOOL,
    AUDIT_VERIFY_TOOL,
    CATALOG_PROTOCOL_VERSION,
    ToolDispatchError,
    bind,
    build_server,
    is_modern_era,
)

# --------------------------------------------------------------------------- #
# A catalog shaped exactly like the sixteen repos declare one
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """The repos' own ToolSpec: name, description, and an explicit input schema."""

    name: str
    description: str
    input_schema: dict[str, Any]


RETRIEVE = ToolSpec(
    name="retrieve_regulations",
    description="Retrieve ranked passages with page-level citations.",
    input_schema={
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "top_k": {"type": "integer", "minimum": 1, "maximum": 50},
        },
        "required": ["query"],
        "additionalProperties": False,
    },
)

CHECKLIST = ToolSpec(
    name="generate_checklist",
    description="Generate a control checklist with cited rationale.",
    input_schema={
        "type": "object",
        "properties": {"use_case": {"type": "string"}},
        "required": ["use_case"],
        "additionalProperties": False,
    },
)


class Catalog:
    """A ToolCatalogPort: the kit never imports an application, it binds structurally."""

    def __init__(self, *specs: ToolSpec) -> None:
        self._specs = list(specs)

    def list_tools(self) -> list[Any]:
        return list(self._specs)

    def get_tool(self, name: str) -> Any:
        return next((s for s in self._specs if s.name == name), None)


def _handlers() -> dict[str, Callable[..., object]]:
    def retrieve(query: str, top_k: int = 10) -> dict[str, Any]:
        return {"query": query, "passages": [{"cite": "MAS 626 p.14"}][:top_k]}

    def checklist(use_case: str) -> dict[str, Any]:
        return {"use_case": use_case, "controls": ["encryption at rest"]}

    return {"retrieve_regulations": retrieve, "generate_checklist": checklist}


@asynccontextmanager
async def _session(server: Any, *, legacy: bool = False) -> AsyncIterator[Any]:
    """A live client session against ``server`` over in-memory streams.

    Opens on the MODERN era by calling ``server/discover``. That is the whole point: MCP
    2026-07-28 removed ``initialize``, and the SDK routes a connection into whichever era the
    client's first frame opens, so a test that called ``initialize()`` would silently exercise
    the deprecated handshake path and report a 2025 revision as if it were current. Pass
    ``legacy=True`` only to prove that path is refused.
    """
    from mcp import ClientSession
    from mcp.shared.memory import create_client_server_memory_streams

    async with (
        create_client_server_memory_streams() as (client_streams, server_streams),
        anyio.create_task_group() as tg,
    ):

        async def _run() -> None:
            await server.run(
                server_streams[0],
                server_streams[1],
                server.create_initialization_options(),
                raise_exceptions=False,
            )

        tg.start_soon(_run)
        async with ClientSession(client_streams[0], client_streams[1]) as session:
            if legacy:
                await session.initialize()
            else:
                await session.discover()
            yield session
        tg.cancel_scope.cancel()


def _run(coro: Callable[[], Any]) -> Any:
    return anyio.run(coro)


def _text(result: Any) -> str:
    return "".join(block.text for block in result.content if block.type == "text")


# --------------------------------------------------------------------------- #
# Binding: the served surface and the governed one are the same surface
# --------------------------------------------------------------------------- #


def test_bind_pairs_every_declared_tool_with_its_handler() -> None:
    bound = bind(Catalog(RETRIEVE, CHECKLIST), _handlers())
    assert sorted(bound) == ["generate_checklist", "retrieve_regulations"]


def test_a_declared_tool_with_no_handler_refuses_to_start() -> None:
    """A capability the service advertises and cannot perform is not served.

    Failing at start-up rather than on the first call is the point: the alternative is a client
    that lists a tool, calls it, and gets an error nobody saw coming.
    """
    handlers = _handlers()
    del handlers["generate_checklist"]
    with pytest.raises(ToolDispatchError, match="no handler"):
        bind(Catalog(RETRIEVE, CHECKLIST), handlers)


def test_a_handler_for_an_undeclared_tool_refuses_to_start() -> None:
    """The other direction, and the one that actually matters for governance.

    A handler with no catalog entry is a reachable entry point that no least-privilege review
    ever saw. It does not get served just because someone wrote the function.
    """
    handlers = _handlers()
    handlers["delete_everything"] = lambda: None
    with pytest.raises(ToolDispatchError, match="does not declare"):
        bind(Catalog(RETRIEVE, CHECKLIST), handlers)


# --------------------------------------------------------------------------- #
# The served surface, over a real client session
# --------------------------------------------------------------------------- #


def test_list_tools_serves_exactly_what_the_catalog_declares() -> None:
    server = build_server("compliance-advisory", "0.1.0", Catalog(RETRIEVE, CHECKLIST), _handlers())

    async def go() -> None:
        async with _session(server) as session:
            listed = await session.list_tools()
            assert [t.name for t in listed.tools] == ["retrieve_regulations", "generate_checklist"]
            served = {t.name: t.input_schema for t in listed.tools}
            assert served["retrieve_regulations"] == RETRIEVE.input_schema
            assert served["generate_checklist"] == CHECKLIST.input_schema

    _run(go)


def test_a_tool_call_round_trips_through_the_handler() -> None:
    server = build_server("compliance-advisory", "0.1.0", Catalog(RETRIEVE, CHECKLIST), _handlers())

    async def go() -> None:
        async with _session(server) as session:
            result = await session.call_tool("retrieve_regulations", {"query": "outsourcing"})
            assert json.loads(_text(result))["query"] == "outsourcing"

    _run(go)


def test_a_tool_the_catalog_does_not_declare_is_refused() -> None:
    server = build_server("compliance-advisory", "0.1.0", Catalog(RETRIEVE, CHECKLIST), _handlers())

    async def go() -> None:
        async with _session(server) as session:
            result = await session.call_tool("delete_everything", {})
            assert result.is_error, "an undeclared tool must not be answered"

    _run(go)


@pytest.mark.parametrize(
    "arguments",
    [
        {},  # required property missing
        {"query": "x", "unexpected": 1},  # additionalProperties: false
        {"query": 7},  # wrong type
        {"query": "x", "top_k": 999},  # outside the declared maximum
    ],
)
def test_arguments_are_judged_by_the_tools_own_declared_schema(arguments: dict[str, Any]) -> None:
    """The strictness the catalog declares is enforced at the wire, not just documented.

    Each case here is a different clause of the SAME schema, so a validator that checked only
    presence, or only types, would leave one of them green.
    """
    server = build_server("compliance-advisory", "0.1.0", Catalog(RETRIEVE, CHECKLIST), _handlers())

    async def go() -> None:
        async with _session(server) as session:
            result = await session.call_tool("retrieve_regulations", arguments)
            assert result.is_error, f"schema-violating arguments were accepted: {arguments}"

    _run(go)


# --------------------------------------------------------------------------- #
# The ledger, reachable and unchanged
# --------------------------------------------------------------------------- #


def _store(tmp_path: Path) -> HashChainedAuditLog:
    (tmp_path / "anchor").mkdir(parents=True, exist_ok=True)
    store = HashChainedAuditLog(
        str(tmp_path / "audit.db"), anchor_path=str(tmp_path / "anchor" / "witness.json")
    )
    for actor in ("analyst.one", "analyst.two"):
        store.record({"action": "assess", "actor": actor, "decision": "escalated"})
    return store


def test_audit_verify_reports_an_intact_chain(tmp_path: Path) -> None:
    server = build_server(
        "compliance-advisory",
        "0.1.0",
        Catalog(RETRIEVE),
        {"retrieve_regulations": lambda **k: {}},
        audit_store=_store(tmp_path),
    )

    async def go() -> None:
        async with _session(server) as session:
            listed = await session.list_tools()
            assert AUDIT_VERIFY_TOOL in {t.name for t in listed.tools}
            report = json.loads(_text(await session.call_tool(AUDIT_VERIFY_TOOL, {})))
            assert report["ok"] is True
            assert report["entries"] == 2

    _run(go)


def test_audit_verify_reports_a_tampered_chain(tmp_path: Path) -> None:
    """The falsification that makes the check above mean something.

    A verifier that returned ``ok`` unconditionally would pass the intact case. This edits a
    stored record in place, which is precisely what the hash chain exists to catch, and
    requires the answer to change.
    """
    import sqlite3

    store = _store(tmp_path)
    conn = sqlite3.connect(str(tmp_path / "audit.db"))
    # The WORM triggers reject UPDATE, so tamper the way a real attacker would have to: by
    # going around the table's own protections rather than through them.
    conn.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
    conn.execute("UPDATE audit_log SET event_json = ? WHERE seq = 1", ('{"action":"forged"}',))
    conn.commit()
    conn.close()

    server = build_server(
        "compliance-advisory",
        "0.1.0",
        Catalog(RETRIEVE),
        {"retrieve_regulations": lambda **k: {}},
        audit_store=store,
    )

    async def go() -> None:
        async with _session(server) as session:
            report = json.loads(_text(await session.call_tool(AUDIT_VERIFY_TOOL, {})))
            assert report["ok"] is False
            assert report["first_bad_seq"] == 1

    _run(go)


def test_audit_export_writes_the_portable_format_under_plugin_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Export reaches the ledger through the port, so the format stays the ledger's own."""
    from hex_service_kit.audit import EXPORT_FORMAT

    data_dir = tmp_path / "plugin-data"
    data_dir.mkdir()
    monkeypatch.setenv("PLUGIN_DATA", str(data_dir))
    server = build_server(
        "compliance-advisory",
        "0.1.0",
        Catalog(RETRIEVE),
        {"retrieve_regulations": lambda **k: {}},
        audit_store=_store(tmp_path),
    )

    async def go() -> None:
        async with _session(server) as session:
            result = await session.call_tool(AUDIT_EXPORT_TOOL, {"filename": "trail.jsonl"})
            body = json.loads(_text(result))
            assert body["records"] == 2
            written = Path(body["path"])
            assert written.is_relative_to(data_dir)
            header = json.loads(written.read_text(encoding="utf-8").splitlines()[0])
            assert header["format"] == EXPORT_FORMAT, "the export format is the ledger's, unchanged"

    _run(go)


@pytest.mark.parametrize("escape", ["../outside.jsonl", "/etc/trail.jsonl"])
def test_audit_export_refuses_a_path_outside_plugin_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, escape: str
) -> None:
    """A tool call does not choose where on the host an evidence trail lands."""
    data_dir = tmp_path / "plugin-data"
    data_dir.mkdir()
    monkeypatch.setenv("PLUGIN_DATA", str(data_dir))
    server = build_server(
        "compliance-advisory",
        "0.1.0",
        Catalog(RETRIEVE),
        {"retrieve_regulations": lambda **k: {}},
        audit_store=_store(tmp_path),
    )

    async def go() -> None:
        async with _session(server) as session:
            result = await session.call_tool(AUDIT_EXPORT_TOOL, {"filename": escape})
            assert result.is_error

    _run(go)


def test_audit_export_fails_closed_when_plugin_data_is_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unset is not a writable directory, and it is not the current directory either."""
    monkeypatch.delenv("PLUGIN_DATA", raising=False)
    server = build_server(
        "compliance-advisory",
        "0.1.0",
        Catalog(RETRIEVE),
        {"retrieve_regulations": lambda **k: {}},
        audit_store=_store(tmp_path),
    )

    async def go() -> None:
        async with _session(server) as session:
            result = await session.call_tool(AUDIT_EXPORT_TOOL, {"filename": "trail.jsonl"})
            assert result.is_error

    _run(go)


def test_no_write_tool_reaches_the_ledger(tmp_path: Path) -> None:
    """Access, never authority.

    Appending to the trail is something a service does as it works, not something a caller
    asks for. If a write tool is ever added here, this is the check that has to be deleted
    deliberately rather than a gap nobody noticed.
    """
    server = build_server(
        "compliance-advisory",
        "0.1.0",
        Catalog(RETRIEVE),
        {"retrieve_regulations": lambda **k: {}},
        audit_store=_store(tmp_path),
    )

    async def go() -> None:
        async with _session(server) as session:
            listed = {t.name for t in (await session.list_tools()).tools}
            assert listed == {"retrieve_regulations", AUDIT_VERIFY_TOOL, AUDIT_EXPORT_TOOL}

    _run(go)


# --------------------------------------------------------------------------- #
# Protocol era
# --------------------------------------------------------------------------- #


def test_the_connection_runs_on_the_modern_stateless_era() -> None:
    """The served connection is on 2026-07-28, not the deprecated handshake era.

    This is the assertion the previous version of this file got wrong. It called
    ``initialize()``, which opens a handshake-era connection, and then checked the negotiated
    revision against a floor. The floor passed, so the suite reported success while every
    connection it made ran on the era MCP 2026-07-28 removed.
    """
    server = build_server(
        "compliance-advisory", "0.1.0", Catalog(RETRIEVE), {"retrieve_regulations": lambda **k: {}}
    )

    async def go() -> None:
        async with _session(server) as session:
            assert session.protocol_version == CATALOG_PROTOCOL_VERSION
            assert is_modern_era(str(session.protocol_version))

    _run(go)


def test_a_handshake_era_connection_is_refused() -> None:
    """The deprecated era is refused rather than quietly served.

    The SDK will serve whichever era the client opens with, so this is the check that keeps the
    old path from staying reachable behind the new one. The refusal names the served revision,
    which is what a client needs in order to retry with ``server/discover``.
    """
    server = build_server(
        "compliance-advisory", "0.1.0", Catalog(RETRIEVE), {"retrieve_regulations": lambda **k: {}}
    )

    async def go() -> None:
        async with _session(server, legacy=True) as session:
            assert session.protocol_version != CATALOG_PROTOCOL_VERSION
            result = await session.call_tool("retrieve_regulations", {"query": "x"})
            assert result.is_error, "a handshake-era caller must not be served"

    _run(go)


def test_era_membership_rejects_an_unrecognised_revision() -> None:
    """Membership, not comparison.

    ``"zzz" >= "2026-07-28"`` is True, so any hand-written version floor accepts an
    unrecognised peer string. That is exactly the bug this replaced: asking which era a
    revision belongs to has no such failure mode.
    """
    assert is_modern_era(CATALOG_PROTOCOL_VERSION)
    # A real revision, and a recent one, but handshake era. It must not be treated as current.
    assert not is_modern_era("2025-11-25")
    assert not is_modern_era("zzz")
    assert not is_modern_era("9999-99-99")
    # The bug, kept executable rather than described: a hand-written floor would accept this.
    naive_floor_accepts_garbage = CATALOG_PROTOCOL_VERSION < "zzz"
    assert naive_floor_accepts_garbage
    assert not is_modern_era("zzz")
