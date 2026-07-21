from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .decision import Decision


@dataclass
class JudgeRequest:
    agent_id: str
    tool: str
    args: dict[str, Any]
    reason: str
    ceiling: Decision


class Judge(Protocol):
    def evaluate(self, request: JudgeRequest) -> tuple[Decision, str]: ...


class CallableJudge:
    def __init__(self, fn) -> None:
        self._fn = fn

    def evaluate(self, request: JudgeRequest) -> tuple[Decision, str]:
        return self._fn(request)
