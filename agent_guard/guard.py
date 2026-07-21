from __future__ import annotations

from typing import Any, Callable

from .audit import AuditSink, build_record
from .decision import Decision
from .policy import Policy
from .tiers import TRUST_TIERS

ToolDispatch = Callable[[str, dict], Any]
HumanApprover = Callable[["ApprovalRequest"], bool]


class BlockedError(Exception):
    def __init__(self, tool: str, reason: str) -> None:
        super().__init__(f"blocked tool call '{tool}': {reason}")
        self.tool = tool
        self.reason = reason


class ApprovalRequest:
    def __init__(self, agent_id: str, tool: str, args: dict[str, Any], reason: str) -> None:
        self.agent_id = agent_id
        self.tool = tool
        self.args = args
        self.reason = reason


def deny_by_default(_: ApprovalRequest) -> bool:
    return False


class Guard:
    def __init__(
        self,
        policy: Policy,
        audit: AuditSink,
        agent_id: str,
        approver: HumanApprover = deny_by_default,
        trust_tier: str = TRUST_TIERS[0],
    ) -> None:
        self._policy = policy
        self._audit = audit
        self._agent_id = agent_id
        self._approver = approver
        self._trust_tier = trust_tier

    def wrap(self, dispatch: ToolDispatch) -> ToolDispatch:
        def guarded(tool: str, args: dict[str, Any]) -> Any:
            return self.call(dispatch, tool, args)

        return guarded

    def call(self, dispatch: ToolDispatch, tool: str, args: dict[str, Any]) -> Any:
        verdict = self._policy.evaluate(tool, args, self._trust_tier)

        if verdict.decision is Decision.DENY:
            self._audit.write(build_record(self._agent_id, tool, args, verdict, executed=False))
            raise BlockedError(tool, verdict.reason)

        if verdict.decision is Decision.REQUIRE_HUMAN:
            approved = self._approver(ApprovalRequest(self._agent_id, tool, args, verdict.reason))
            if not approved:
                self._audit.write(build_record(self._agent_id, tool, args, verdict, executed=False))
                raise BlockedError(tool, f"human approval denied: {verdict.reason}")

        result = dispatch(tool, args)
        self._audit.write(build_record(self._agent_id, tool, args, verdict, executed=True))
        return result
