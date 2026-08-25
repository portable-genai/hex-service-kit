"""Serve a governed tool catalog over MCP, once, for every repo that declares one.

Sixteen repos already declare a least-privilege tool catalog: a name, a description and an
explicit JSON Schema per tool, with ``additionalProperties: false`` so an argument nobody
designed for cannot arrive. None of it was ever served. This is the missing half, kept here
rather than copied into each repo so the dispatch rule, the argument check and the failure
mode are stated once.

The catalog stays the authority. This module adds no tool of its own beyond the two read-only
evidence tools below, renames nothing, and refuses to serve a tool the catalog does not
declare or a handler cannot answer. A served surface that drifted from the declared one would
make the catalog a description of something else.

Transport follows the client. Agent Plugins clients spawn a subprocess and speak stdio, which
is also the only transport an offline gate can prove end to end, so it is the default;
a deployed profile mounts :func:`streamable_http_app` on the API it already runs.

**This server speaks the modern, stateless era only.** MCP 2026-07-28 removed the
``initialize`` / ``notifications/initialized`` handshake and protocol-level sessions: every
request now carries its own protocol version and client capabilities in ``_meta``, and
``server/discover`` advertises what the server speaks. The SDK will still serve the older
handshake era to a client that opens with it, and this module deliberately refuses that, so a
connection is either on the current revision or it is told plainly that it is not. A reference
implementation that quietly accepted the deprecated era would be documenting the previous
generation of the protocol.

Like :mod:`hex_service_kit.web` and :mod:`hex_service_kit.tracing`, this module is NOT
re-exported from the package root: the MCP SDK lives in the ``interop`` extra, every import of
it is lazy and inside a function, and ``import hex_service_kit`` keeps working with none of it
installed.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .audit import AuditStorePort
from .netdefaults import read_env_setting

#: The revision this server serves, and the one the tool catalogs are governed against. It is
#: a member of the modern, stateless era; the handshake era is refused rather than negotiated
#: down to. See :func:`is_modern_era`.
CATALOG_PROTOCOL_VERSION = "2026-07-28"

#: Where a client guarantees a plugin may write. An export target outside it is refused rather
#: than silently written somewhere the client will not clean up or hand back.
PLUGIN_DATA_ENV = "PLUGIN_DATA"

AUDIT_VERIFY_TOOL = "audit_verify"
AUDIT_EXPORT_TOOL = "audit_export"


class ToolDispatchError(RuntimeError):
    """A tool call was refused before it reached a handler.

    Refusals are deliberate and specific (unknown tool, unbound handler, arguments the declared
    schema rejects) so a client is told what was wrong rather than handed an empty result.
    """


@runtime_checkable
class ToolSpecLike(Protocol):
    """Structural view of a repo's ``ToolSpec``: the kit never imports an application."""

    @property
    def name(self) -> str: ...

    @property
    def description(self) -> str: ...

    @property
    def input_schema(self) -> dict[str, Any]: ...


@runtime_checkable
class ToolCatalogLike(Protocol):
    """Structural view of a repo's ``ToolCatalogPort``."""

    def list_tools(self) -> list[Any]: ...


Handler = Callable[..., object]


@dataclass(frozen=True, slots=True)
class _Bound:
    """One declared tool and the callable that answers it."""

    spec: ToolSpecLike
    handler: Handler


def is_modern_era(version: str) -> bool:
    """Is ``version`` a revision of the stateless, per-request-envelope era?

    Membership, deliberately, not a comparison. Revisions look like dates and therefore appear
    to order lexically, but they are an enumerated set: the SDK's own registry warns that an
    unrecognised peer string such as ``"zzz"`` sorts ABOVE a real revision and would satisfy any
    ``>=`` floor written by hand. Asking the registry which era a revision belongs to has no
    such failure mode, and it states the thing actually required here, which is not "new enough"
    but "not the handshake era at all".
    """
    from mcp.types.version import MODERN_PROTOCOL_VERSIONS  # noqa: PLC0415

    return version in MODERN_PROTOCOL_VERSIONS


def bind(catalog: ToolCatalogLike, handlers: Mapping[str, Handler]) -> dict[str, _Bound]:
    """Pair every declared tool with its handler, refusing any mismatch in either direction.

    Both directions matter. A declared tool with no handler is a capability the service
    advertises and cannot perform; a handler for an undeclared tool is a reachable entry point
    nobody governed. Neither is allowed to start.
    """
    specs = {spec.name: spec for spec in catalog.list_tools()}
    undeclared = sorted(set(handlers) - set(specs))
    if undeclared:
        raise ToolDispatchError(
            "handlers bound for tools the catalog does not declare: "
            + ", ".join(undeclared)
            + ". Declare them in the catalog or remove the handler; an ungoverned entry point "
            "is not served"
        )
    unhandled = sorted(set(specs) - set(handlers))
    if unhandled:
        raise ToolDispatchError(
            "catalog declares tools with no handler: "
            + ", ".join(unhandled)
            + ". A tool the service advertises and cannot perform is not served"
        )
    return {name: _Bound(spec=spec, handler=handlers[name]) for name, spec in specs.items()}


def _validate(name: str, schema: Mapping[str, Any], arguments: Mapping[str, Any]) -> None:
    """Check arguments against the tool's own declared schema, failing closed.

    The schema is the catalog's, not one derived here, so what is enforced at the wire is
    exactly what was governed. ``jsonschema`` is imported lazily: it belongs to the ``interop``
    extra and the portable core must import without it.
    """
    import jsonschema  # noqa: PLC0415

    try:
        jsonschema.validate(instance=dict(arguments), schema=dict(schema))
    except jsonschema.ValidationError as exc:
        raise ToolDispatchError(
            f"arguments rejected by the declared schema for {name!r}: {exc.message}"
        ) from exc


def _as_text(result: object) -> str:
    """Render a handler result as the text payload of a tool response."""
    if isinstance(result, str):
        return result
    from .serialization import to_jsonable  # noqa: PLC0415

    return json.dumps(to_jsonable(result), ensure_ascii=False, indent=2)


def _export_target(raw: str) -> Path:
    """Resolve an export path, refusing anything outside the client's writable root.

    The specification names ``PLUGIN_DATA`` as the one directory a client guarantees is
    writable and persistent. Honouring it is what keeps an export somewhere the caller can
    actually collect, and refusing everything else is what stops a tool call from choosing a
    path on the host. Unset fails closed: no root was named, so no export is written.
    """
    setting = read_env_setting(PLUGIN_DATA_ENV)
    if not setting.has_value:
        raise ToolDispatchError(
            f"{PLUGIN_DATA_ENV} is not set to a writable directory, so there is nowhere this "
            "export may be written. A client sets it when it launches the plugin"
        )
    root = Path(setting.value).resolve()
    target = (root / raw).resolve() if not Path(raw).is_absolute() else Path(raw).resolve()
    if not target.is_relative_to(root):
        raise ToolDispatchError(
            f"export path {raw!r} resolves outside {PLUGIN_DATA_ENV} ({root}): a tool call does "
            "not choose where on the host an evidence trail lands"
        )
    return target


@dataclass(frozen=True, slots=True)
class _SimpleSpec:
    """A ``ToolSpecLike`` for tools the kit itself contributes."""

    name: str
    description: str
    input_schema: dict[str, Any]


def audit_tools(store: AuditStorePort) -> tuple[list[Any], dict[str, Handler]]:
    """The two read-only evidence tools, and their handlers.

    Access, never authority. Both go through :class:`~hex_service_kit.audit.AuditStorePort`,
    so the chain rule, the anchor rule and the export format stay exactly where they are and a
    client reaching the ledger over MCP reads the same bytes the CLI writes. There is no write
    tool here and there should not be: appending to the trail is something a service does as it
    works, not something a caller asks for.
    """
    specs: list[Any] = [
        _SimpleSpec(
            name=AUDIT_VERIFY_TOOL,
            description=(
                "Verify the append-only hash chain over the stored evidence trail. Reports "
                "whether it is intact, how many records were chained, and the first record "
                "that failed."
            ),
            input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        ),
        _SimpleSpec(
            name=AUDIT_EXPORT_TOOL,
            description=(
                "Export the evidence trail as JSON Lines in the portable audit format, into "
                "the client-provided PLUGIN_DATA directory. Returns the record count and the "
                "sha256 of the file written."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": (
                            "Destination relative to PLUGIN_DATA. A path outside it is refused."
                        ),
                    }
                },
                "required": ["filename"],
                "additionalProperties": False,
            },
        ),
    ]

    def verify() -> dict[str, Any]:
        report = store.verify_chain()
        return {
            "ok": report.ok,
            "entries": report.entries,
            "chained": report.chained,
            "legacy": report.legacy,
            "first_bad_seq": report.first_bad_seq,
            "detail": report.detail,
        }

    def export(filename: str) -> dict[str, Any]:
        target = _export_target(filename)
        target.parent.mkdir(parents=True, exist_ok=True)
        written = store.export_jsonl(target)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        return {"records": written, "path": str(target), "sha256": digest}

    return specs, {AUDIT_VERIFY_TOOL: verify, AUDIT_EXPORT_TOOL: export}


class _CombinedCatalog:
    """A repo's catalog plus the kit's evidence tools, presented as one catalog."""

    def __init__(self, catalog: ToolCatalogLike, extra: Sequence[Any]) -> None:
        self._catalog = catalog
        self._extra = list(extra)

    def list_tools(self) -> list[Any]:
        return [*self._catalog.list_tools(), *self._extra]


def build_server(
    name: str,
    version: str,
    catalog: ToolCatalogLike,
    handlers: Mapping[str, Handler],
    *,
    audit_store: AuditStorePort | None = None,
) -> Any:
    """Build an MCP server that serves exactly ``catalog``, answered by ``handlers``.

    When ``audit_store`` is supplied the two read-only evidence tools are added, so a client
    that can call the service can also verify and carry out its trail. Binding happens here,
    before the server exists, so a mismatched catalog fails at start-up rather than on the
    first call from a client.
    """
    from mcp import types  # noqa: PLC0415
    from mcp.server.lowlevel import Server  # noqa: PLC0415

    effective_catalog: ToolCatalogLike = catalog
    effective_handlers = dict(handlers)
    if audit_store is not None:
        extra_specs, extra_handlers = audit_tools(audit_store)
        effective_catalog = _CombinedCatalog(catalog, extra_specs)
        effective_handlers.update(extra_handlers)

    bound = bind(effective_catalog, effective_handlers)

    def _require_modern(ctx: Any) -> None:
        """Refuse a connection opened on the deprecated handshake era.

        The SDK serves whichever era the client's first frame opens, so without this the
        deprecated path stays quietly reachable and a caller could not tell which one it got.
        Refusing names the served revision, which is what a client needs in order to retry with
        ``server/discover`` instead of ``initialize``.
        """
        version = getattr(ctx, "protocol_version", None)
        if not isinstance(version, str) or not is_modern_era(version):
            raise ToolDispatchError(
                f"this server serves MCP {CATALOG_PROTOCOL_VERSION} only, and this connection "
                f"negotiated {version!r}. The initialize handshake was removed in "
                f"{CATALOG_PROTOCOL_VERSION}; open the connection with server/discover instead"
            )

    async def on_list_tools(ctx: Any, _params: Any) -> Any:
        _require_modern(ctx)
        # Deterministic order: the specification asks for it so a client can cache the list and
        # keep an LLM prompt prefix stable. `bound` preserves the catalog's declared order.
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name=item.spec.name,
                    description=item.spec.description,
                    input_schema=item.spec.input_schema,
                )
                for item in bound.values()
            ]
        )

    def _refused(message: str) -> Any:
        """A refusal the caller can read, rather than a transport failure.

        Returning ``isError`` keeps the session alive and tells the client which call was
        rejected and why. Raising instead would tear down the connection, so one bad argument
        from one caller would take out every tool on the server.
        """
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=message)], is_error=True
        )

    async def on_call_tool(ctx: Any, params: Any) -> Any:
        try:
            _require_modern(ctx)
        except ToolDispatchError as exc:
            return _refused(str(exc))
        item = bound.get(params.name)
        if item is None:
            return _refused(
                f"no tool named {params.name!r} in this catalog: "
                f"declared tools are {', '.join(sorted(bound))}"
            )
        arguments = dict(params.arguments or {})
        try:
            _validate(item.spec.name, item.spec.input_schema, arguments)
            result = item.handler(**arguments)
        except ToolDispatchError as exc:
            return _refused(str(exc))
        except Exception as exc:  # noqa: BLE001
            # A handler that raised is this tool failing, not the server failing. The other
            # tools stay callable and the caller is told which one broke.
            return _refused(f"{item.spec.name} failed: {type(exc).__name__}: {exc}")
        return types.CallToolResult(content=[types.TextContent(type="text", text=_as_text(result))])

    return Server(name, version=version, on_list_tools=on_list_tools, on_call_tool=on_call_tool)


def run_stdio(server: Any) -> None:
    """Serve on stdin/stdout, the transport an Agent Plugins client spawns.

    Nothing binds a socket, so this is also the shape the offline gate can exercise.
    """
    import anyio  # noqa: PLC0415
    from mcp.server.stdio import stdio_server  # noqa: PLC0415

    async def _serve() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    anyio.run(_serve)


def streamable_http_app(server: Any, *, path: str = "/mcp") -> Any:
    """The ASGI app a deployed profile mounts on the API it already serves.

    Returned rather than run, so the host application keeps ownership of the port, the bind
    host and the service-caller authentication it already enforces. This adds a transport, not
    a second way in: mount it behind the same guard as every other service route.
    """
    return server.streamable_http_app(streamable_http_path=path)
