from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from .decision import Verdict


@dataclass(frozen=True)
class AuditRecord:
    ts: str
    agent_id: str
    tool: str
    args: dict[str, Any]
    decision: str
    reason: str
    rule_id: str | None
    executed: bool


class AuditSink(Protocol):
    def write(self, record: AuditRecord) -> None: ...


class JsonlAuditSink:
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, record: AuditRecord) -> None:
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(record)) + "\n")


class MemoryAuditSink:
    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def write(self, record: AuditRecord) -> None:
        self.records.append(record)


def build_record(agent_id: str, tool: str, args: dict[str, Any], verdict: Verdict, executed: bool) -> AuditRecord:
    return AuditRecord(
        ts=datetime.now(timezone.utc).isoformat(),
        agent_id=agent_id,
        tool=tool,
        args=args,
        decision=verdict.decision.value,
        reason=verdict.reason,
        rule_id=verdict.rule_id,
        executed=executed,
    )
