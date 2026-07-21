from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from .attestation import Attestation

ToolFn = Callable[[str, dict], Any]


@dataclass(frozen=True)
class RuntimeSpec:
    code_digest: str
    kind: str = "local.container"


class Sandbox(Protocol):
    def attest(self) -> Attestation: ...
    def dispatch(self, tool: str, args: dict) -> Any: ...
    def close(self) -> None: ...


class LocalSandbox:
    def __init__(self, spec: RuntimeSpec, tool_fn: ToolFn) -> None:
        self._spec = spec
        self._tool_fn = tool_fn
        self._sandbox_id = f"sbx-{uuid.uuid4().hex[:8]}"
        self._closed = False

    def attest(self) -> Attestation:
        return Attestation(
            runtime_kind=self._spec.kind,
            code_digest=self._spec.code_digest,
            sandbox_id=self._sandbox_id,
            evidence={"pid_namespaced": True, "kind": self._spec.kind},
        )

    def dispatch(self, tool: str, args: dict) -> Any:
        if self._closed:
            raise RuntimeError("sandbox is closed")
        return self._tool_fn(tool, args)

    def close(self) -> None:
        self._closed = True


class LocalRuntime:
    def __init__(self, tool_fn: ToolFn) -> None:
        self._tool_fn = tool_fn

    def spawn(self, spec: RuntimeSpec) -> LocalSandbox:
        return LocalSandbox(spec, self._tool_fn)
