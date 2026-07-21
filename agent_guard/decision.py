from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_HUMAN = "require_human"


PERMISSIVENESS: dict[Decision, int] = {
    Decision.DENY: 0,
    Decision.REQUIRE_HUMAN: 1,
    Decision.ALLOW: 2,
}


def clamp(decision: Decision, ceiling: Decision) -> Decision:
    return decision if PERMISSIVENESS[decision] <= PERMISSIVENESS[ceiling] else ceiling


@dataclass(frozen=True)
class Verdict:
    decision: Decision
    reason: str
    rule_id: str | None = None
    module: str | None = None
    layer: int | None = None
    needs_judge: bool = False
    judge_ceiling: Decision = Decision.REQUIRE_HUMAN

    @property
    def blocked(self) -> bool:
        return self.decision is Decision.DENY

    def trace(self) -> str:
        where = f"{self.module or '-'}#{self.rule_id or 'default'}@L{self.layer if self.layer is not None else '-'}"
        return f"{self.decision.value} [{where}] :: {self.reason}"
