from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable

from .audit import AuditSink, build_record
from .decision import Decision, Verdict, clamp
from .judge import Judge, JudgeRequest
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
        judge: Judge | None = None,
    ) -> None:
        self._policy = policy
        self._audit = audit
        self._agent_id = agent_id
        self._approver = approver
        self._trust_tier = trust_tier
        self._judge = judge

    def wrap(self, dispatch: ToolDispatch) -> ToolDispatch:
        def guarded(tool: str, args: dict[str, Any]) -> Any:
            return self.call(dispatch, tool, args)

        return guarded

    def call(self, dispatch: ToolDispatch, tool: str, args: dict[str, Any]) -> Any:
        verdict = self._policy.evaluate(tool, args, self._trust_tier)
        if verdict.needs_judge:
            verdict = self._consult_judge(verdict, tool, args)

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

    def _consult_judge(self, verdict: Verdict, tool: str, args: dict[str, Any]) -> Verdict:
        fallback = verdict.decision
        if self._judge is None:
            return replace(verdict, reason=f"judge required, none configured; fail-closed to {fallback.value}")
        try:
            decision, why = self._judge.evaluate(
                JudgeRequest(self._agent_id, tool, args, verdict.reason, verdict.judge_ceiling)
            )
        except Exception as err:  # noqa: BLE001 - judge is an untrusted edge; fail closed to the rule fallback
            return replace(verdict, reason=f"judge error ({err}); fail-closed to {fallback.value}")
        final = clamp(decision, verdict.judge_ceiling)
        return replace(verdict, decision=final, reason=f"judge->{final.value} (ceiling {verdict.judge_ceiling.value}): {why}")
