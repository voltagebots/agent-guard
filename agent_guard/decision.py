from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_HUMAN = "require_human"


@dataclass(frozen=True)
class Verdict:
    decision: Decision
    reason: str
    rule_id: str | None = None

    @property
    def blocked(self) -> bool:
        return self.decision is Decision.DENY
