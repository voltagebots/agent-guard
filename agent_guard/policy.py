from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .decision import Decision, Verdict


@dataclass(frozen=True)
class Rule:
    id: str
    decision: Decision
    tools: tuple[str, ...]
    arg_patterns: tuple[str, ...] = ()
    reason: str = ""

    def matches(self, tool: str, rendered_args: str) -> bool:
        if not any(fnmatch.fnmatch(tool, pattern) for pattern in self.tools):
            return False
        if not self.arg_patterns:
            return True
        return any(re.search(pattern, rendered_args) for pattern in self.arg_patterns)


@dataclass
class Policy:
    default: Decision
    rules: list[Rule] = field(default_factory=list)

    def evaluate(self, tool: str, args: dict[str, Any]) -> Verdict:
        rendered_args = _render_args(args)
        for rule in self.rules:
            if rule.matches(tool, rendered_args):
                return Verdict(
                    decision=rule.decision,
                    reason=rule.reason or f"matched rule '{rule.id}'",
                    rule_id=rule.id,
                )
        return Verdict(decision=self.default, reason="no rule matched; policy default")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        if "default" not in data:
            raise ValueError("policy must declare an explicit 'default' decision (allow|deny|require_human)")
        rules = [_rule_from_dict(index, raw) for index, raw in enumerate(data.get("rules", []))]
        return cls(default=Decision(data["default"]), rules=rules)


def _render_args(args: dict[str, Any]) -> str:
    return json.dumps(args, sort_keys=True, default=str)


def _rule_from_dict(index: int, raw: dict[str, Any]) -> Rule:
    tools = raw.get("tools")
    if not tools:
        raise ValueError(f"rule #{index} is missing a non-empty 'tools' list")
    return Rule(
        id=raw.get("id", f"rule-{index}"),
        decision=Decision(raw["decision"]),
        tools=tuple(tools),
        arg_patterns=tuple(raw.get("arg_patterns", ())),
        reason=raw.get("reason", ""),
    )


def load_policy(path: str | Path) -> Policy:
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    if path.suffix in {".yaml", ".yml"}:
        data = _load_yaml(text)
    else:
        data = json.loads(text)
    return Policy.from_dict(data)


def _load_yaml(text: str) -> dict[str, Any]:
    try:
        import yaml
    except ImportError as err:
        raise ImportError("PyYAML is required to load .yaml policies; `pip install pyyaml` or use JSON") from err
    return yaml.safe_load(text)
