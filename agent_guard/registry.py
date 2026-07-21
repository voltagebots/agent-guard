from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field, replace
from typing import Any

from .decision import Decision, Verdict
from .policy import Policy, Rule, _render_args, verdict_for_rule
from .tiers import TRUST_TIERS


def _as_namespaces(value: Any) -> tuple[str, ...]:
    if value is None:
        return ("*",)
    if isinstance(value, str):
        return (value,)
    return tuple(value)


@dataclass
class PolicyModule:
    name: str
    rules: list[Rule]
    namespace: tuple[str, ...] = ("*",)
    layer: int = 0

    def __post_init__(self) -> None:
        self.namespace = _as_namespaces(self.namespace)

    def covers(self, tool: str) -> bool:
        return any(ns == "*" or fnmatch.fnmatch(tool, ns) for ns in self.namespace)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyModule:
        policy = Policy.from_dict({"default": "deny", "rules": data.get("rules", [])})
        return cls(
            name=data.get("name", "module"),
            rules=policy.rules,
            namespace=_as_namespaces(data.get("namespace")),
            layer=int(data.get("layer", 0)),
        )


class PolicyRegistry:
    def __init__(self, default: Decision) -> None:
        self._default = default
        self._modules: list[PolicyModule] = []
        self._compiled: list[tuple[PolicyModule, Rule]] | None = None

    def register(self, module: PolicyModule) -> PolicyRegistry:
        self._modules.append(module)
        self._compiled = None
        return self

    def compile(self) -> CompiledPolicy:
        ordered = sorted(
            ((module, rule) for order, module in enumerate(self._modules) for rule in module.rules),
            key=lambda pair: (-pair[0].layer, self._modules.index(pair[0])),
        )
        self._compiled = ordered
        return CompiledPolicy(self._default, ordered)


@dataclass
class CompiledPolicy:
    default: Decision
    ordered: list[tuple[PolicyModule, Rule]] = field(default_factory=list)

    def evaluate(self, tool: str, args: dict[str, Any], trust_tier: str = TRUST_TIERS[0]) -> Verdict:
        rendered_args = _render_args(args)
        for module, rule in self.ordered:
            if not module.covers(tool):
                continue
            if not rule.matches(tool, rendered_args):
                continue
            verdict = verdict_for_rule(rule, tool, trust_tier)
            return replace(verdict, module=module.name, layer=module.layer)
        return Verdict(decision=self.default, reason="no rule matched; registry default", module=None, layer=None)
