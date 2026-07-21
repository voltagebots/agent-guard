from __future__ import annotations

from .decision import Decision
from .registry import PolicyModule, PolicyRegistry

BUNDLED_LAYER = 0

_MODULES: dict[str, dict] = {
    "shell": {
        "namespace": ["shell*", "exec*", "bash*"],
        "rules": [
            {
                "id": "shell-rm-rf",
                "decision": "deny",
                "tools": ["shell*", "exec*", "bash*"],
                "arg_patterns": [r"\brm\s+-rf\b", r"\brm\s+-fr\b"],
                "reason": "recursive force delete",
            },
            {
                "id": "shell-disk-wipe",
                "decision": "deny",
                "tools": ["shell*", "exec*", "bash*"],
                "arg_patterns": [r"\bmkfs\b", r"\bdd\s+.*of=/dev/"],
                "reason": "disk-destroying command",
            },
            {
                "id": "shell-curl-pipe-sh",
                "decision": "require_human",
                "tools": ["shell*", "exec*", "bash*"],
                "arg_patterns": [r"curl\b.*\|\s*(sh|bash)", r"wget\b.*\|\s*(sh|bash)"],
                "reason": "piping remote script to a shell",
            },
            {
                "id": "shell-chmod-777",
                "decision": "require_human",
                "tools": ["shell*", "exec*", "bash*"],
                "arg_patterns": [r"chmod\s+-R\s+777"],
                "reason": "world-writable recursive chmod",
            },
        ],
    },
    "git": {
        "namespace": ["git*", "shell*", "exec*"],
        "rules": [
            {
                "id": "git-force-push",
                "decision": "require_human",
                "tools": ["git*", "shell*", "exec*"],
                "arg_patterns": [r"git\s+push\b.*--force", r"git\s+push\b.*-f\b"],
                "reason": "force-push rewrites shared history",
            },
            {
                "id": "git-hard-reset",
                "decision": "require_human",
                "tools": ["git*", "shell*", "exec*"],
                "arg_patterns": [r"git\s+reset\b.*--hard"],
                "reason": "hard reset discards work",
            },
        ],
    },
    "postgres": {
        "namespace": ["postgres*", "sql*", "db_*"],
        "rules": [
            {
                "id": "pg-drop-truncate",
                "decision": "deny",
                "tools": ["postgres*", "sql*", "db_*"],
                "arg_patterns": [r"(?i)\bdrop\s+table\b", r"(?i)\btruncate\b"],
                "reason": "destructive schema change",
            },
            {
                "id": "pg-unscoped-delete",
                "decision": "require_human",
                "tools": ["postgres*", "sql*", "db_*"],
                "arg_patterns": [r"(?i)delete\s+from\s+\w+\s*;?\s*$"],
                "reason": "DELETE without a WHERE clause",
            },
        ],
    },
    "filesystem": {
        "namespace": ["fs*", "write_file*"],
        "rules": [
            {
                "id": "fs-write-secrets",
                "decision": "require_human",
                "tools": ["fs_write*", "write_file*"],
                "arg_patterns": [r"(?i)\.env\b", r"(?i)id_rsa", r"(?i)/etc/"],
                "reason": "writing to a sensitive path",
            },
        ],
    },
    "kubernetes": {
        "namespace": ["k8s*", "kubectl*", "shell*"],
        "rules": [
            {
                "id": "k8s-delete",
                "decision": "require_human",
                "tools": ["k8s*", "kubectl*", "shell*"],
                "arg_patterns": [r"kubectl\s+delete\b"],
                "reason": "deleting cluster resources",
            },
        ],
    },
}


def bundled_module(name: str) -> PolicyModule:
    if name not in _MODULES:
        raise ValueError(f"unknown bundled module '{name}'; have {sorted(_MODULES)}")
    spec = _MODULES[name]
    return PolicyModule.from_dict(
        {"name": f"bundled:{name}", "namespace": spec["namespace"], "layer": BUNDLED_LAYER, "rules": spec["rules"]}
    )


def bundled_names() -> list[str]:
    return sorted(_MODULES)


def with_bundled(default: Decision, names: list[str] | None = None) -> PolicyRegistry:
    registry = PolicyRegistry(default=default)
    for name in names or bundled_names():
        registry.register(bundled_module(name))
    return registry
