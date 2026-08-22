from __future__ import annotations

import pytest

from hex_service_kit import (
    AssuranceLevel,
    Capability,
    CapabilityManifest,
    CapabilityMode,
)


def test_local_manifest_is_honestly_demo_only() -> None:
    manifest = CapabilityManifest(
        service="example-agent",
        profile="local",
        region="local",
        demo_only=True,
        capabilities=(
            Capability(
                name="workflow",
                available=True,
                mode=CapabilityMode.LOCAL,
                assurance=AssuranceLevel.DEMO_ONLY,
            ),
            Capability(
                name="immutable-audit",
                available=False,
                mode=CapabilityMode.DISABLED,
                assurance=AssuranceLevel.UNAVAILABLE,
                required_for_production=True,
                reason="managed WORM service is not present on the laptop",
            ),
        ),
    )
    assert manifest.production_ready is False
    with pytest.raises(RuntimeError, match="immutable-audit"):
        manifest.require_production_ready()


def test_managed_manifest_requires_attestation_for_required_capabilities() -> None:
    item = Capability(
        name="immutable-audit",
        available=True,
        mode=CapabilityMode.MANAGED,
        assurance=AssuranceLevel.ATTESTED,
        required_for_production=True,
    )
    manifest = CapabilityManifest(
        service="example-agent",
        profile="gcp",
        region="us-central1",
        capabilities=(item,),
    )
    assert manifest.production_ready is True
    manifest.require_production_ready()
