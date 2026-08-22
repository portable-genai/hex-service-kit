"""Vendor-neutral runtime capability and assurance manifest.

The manifest is a wire contract, not a cloud discovery client. Each application builds
it from the adapters it actually selected. A laptop can therefore expose a functional
workflow while stating that managed audit, observability, and guardrails are unavailable;
a production profile can fail readiness when a required attested capability is absent.
"""

from __future__ import annotations

from dataclasses import dataclass

from .enums import StrEnum


class CapabilityMode(StrEnum):
    MANAGED = "managed"
    LOCAL = "local"
    EXTERNAL = "external"
    DISABLED = "disabled"


class AssuranceLevel(StrEnum):
    ATTESTED = "attested"
    DEMO_ONLY = "demo-only"
    NOT_ATTESTED = "not-attested"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class Capability:
    """One selected capability implementation and its honest assurance level."""

    name: str
    available: bool
    mode: CapabilityMode
    assurance: AssuranceLevel
    provider: str = ""
    reason: str = ""
    required_for_production: bool = False

    @property
    def production_ready(self) -> bool:
        if not self.required_for_production:
            return True
        return self.available and self.assurance is AssuranceLevel.ATTESTED


@dataclass(frozen=True, slots=True)
class CapabilityManifest:
    """The capabilities selected for one running service instance."""

    service: str
    profile: str
    region: str
    capabilities: tuple[Capability, ...]
    schema_version: str = "capability-manifest/v1"
    portable_core: bool = True
    demo_only: bool = False

    @property
    def production_ready(self) -> bool:
        return not self.demo_only and all(item.production_ready for item in self.capabilities)

    def require_production_ready(self) -> None:
        """Raise with exact missing assurances instead of starting falsely green."""
        missing = [
            item.name
            for item in self.capabilities
            if item.required_for_production and not item.production_ready
        ]
        if self.demo_only:
            missing.insert(0, "demo-only profile")
        if missing:
            raise RuntimeError(
                "production assurance requirements are not satisfied: " + ", ".join(missing)
            )
