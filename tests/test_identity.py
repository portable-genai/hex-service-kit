"""Identity value objects + the local seeded-persona adapter."""

from __future__ import annotations

import pytest

from hex_service_kit.identity import (
    ANONYMOUS,
    DEFAULT_PERSONAS,
    IdentityError,
    IdentityPort,
    LocalPersonaIdentityAdapter,
    Principal,
    RequestContext,
)


def _ctx(persona: str | None = None) -> RequestContext:
    headers = {"x-dev-persona": persona} if persona is not None else {}
    return RequestContext(headers=headers)


def test_principal_actor_is_the_verified_subject():
    p = Principal(subject="a@bank.example", principals=("group:analyst",), tenant="t")
    assert p.actor == "a@bank.example"
    assert ANONYMOUS.actor == "anonymous"


def test_entitlement_principals_use_verified_scope_when_no_narrowing_is_requested():
    principal = Principal(
        subject="reviewer@fictional-bank.example",
        principals=("group:reader", "group:risk", "group:reader", ""),
    )

    assert principal.entitlement_principals() == ("group:reader", "group:risk")
    assert principal.entitlement_principals(()) == ("group:reader", "group:risk")


def test_entitlement_principals_can_only_narrow_and_preserve_request_order():
    principal = Principal(
        subject="reviewer@fictional-bank.example",
        principals=("group:reader", "group:risk"),
    )

    assert principal.entitlement_principals(
        ("group:risk", "group:foreign-admin", "group:risk", "group:reader")
    ) == ("group:risk", "group:reader")


def test_nonempty_but_blank_narrowing_request_fails_closed():
    principal = Principal(
        subject="reviewer@fictional-bank.example",
        principals=("group:reader",),
    )

    assert principal.entitlement_principals(("", "")) == ()


def test_request_context_header_is_case_insensitive():
    ctx = RequestContext(headers={"x-dev-persona": "auditor"})
    assert ctx.header("X-Dev-Persona") == "auditor"
    assert ctx.header("missing") == ""


def test_default_persona_is_first_when_none_selected():
    adapter = LocalPersonaIdentityAdapter()
    assert adapter.resolve(_ctx()) == DEFAULT_PERSONAS[0]
    assert adapter.resolve(_ctx("")) == DEFAULT_PERSONAS[0]


def test_named_persona_resolves():
    adapter = LocalPersonaIdentityAdapter()
    resolved = adapter.resolve(_ctx("other-tenant"))
    assert resolved.tenant == "other-bank"
    assert resolved.source == "local-persona:other-tenant"


def test_unknown_persona_fails_closed():
    adapter = LocalPersonaIdentityAdapter()
    with pytest.raises(IdentityError, match="unknown dev persona"):
        adapter.resolve(_ctx("nope"))


def test_personas_listing_for_the_picker():
    listed = LocalPersonaIdentityAdapter().personas()
    assert {p["id"] for p in listed} == {"analyst", "approver", "auditor", "other-tenant"}
    assert all({"id", "subject", "tenant", "principals"} <= p.keys() for p in listed)


def test_custom_personas_override_the_seed():
    custom = (
        Principal(subject="only@x.example", tenant="x", source="local-persona:only"),
        Principal(subject="two@x.example", tenant="x", source="local-persona:two"),
    )
    adapter = LocalPersonaIdentityAdapter(custom)
    assert adapter.resolve(_ctx()).subject == "only@x.example"
    assert adapter.resolve(_ctx("two")).subject == "two@x.example"


def test_empty_personas_rejected():
    with pytest.raises(ValueError, match="at least one"):
        LocalPersonaIdentityAdapter([])


def test_adapter_satisfies_the_identity_port():
    # Runtime-checkable structural conformance (the hexagon boundary).
    assert isinstance(LocalPersonaIdentityAdapter(), IdentityPort)
