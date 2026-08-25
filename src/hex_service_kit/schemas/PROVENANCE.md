# Vendored schemas: Agent Plugins 1.0.0

These two files are copied byte for byte from the specification repository. They are vendored
rather than fetched so the offline gate can validate a generated plugin against the real
published schema with no network, no credentials and no cloud SDK.

| File | Upstream path | sha256 |
|---|---|---|
| `agent-plugins-1.0.0-plugin.schema.json` | `schemas/1.0.0/plugin.schema.json` | `0a4aad95ce337878ad38802ebf0daa3fde76abe3f65400c86bcbb1ec0b3ab883` |
| `agent-plugins-1.0.0-mcp.schema.json` | `schemas/1.0.0/mcp.schema.json` | `6539175bfcdf43085855183e86da40ea94b166547a72b47ae9a0a390516d3acb` |

- Source: <https://github.com/agentplugins/agent-plugins-spec>
- Commit pinned: `d92e6f443b8edcea42c039727a82afdc565779e2`
- Specification version: 1.0.0, published 2026-08-06
- Licence: CC-BY-4.0 (specification text and schemas)

`tests/test_plugin_render.py` re-hashes both files and fails if either byte differs from the
table above. Upgrading to a later specification revision is therefore a deliberate change
that has to edit this file, never a silent drift in what the gate is validating against.

Do not edit the schema files. A local rule this workspace wants to add belongs in
`hex_service_kit.plugin`, which applies its own checks on top of schema validity, not in a
patched copy of someone else's schema.
