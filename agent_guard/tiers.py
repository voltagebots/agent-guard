from __future__ import annotations

TRUST_TIERS: tuple[str, ...] = (
    "local.process",
    "local.container",
    "remote.gvisor",
    "remote.microvm",
)


def rank(tier: str) -> int:
    try:
        return TRUST_TIERS.index(tier)
    except ValueError as err:
        raise ValueError(f"unknown trust tier '{tier}'; expected one of {TRUST_TIERS}") from err


def meets(actual: str, required: str) -> bool:
    return rank(actual) >= rank(required)
