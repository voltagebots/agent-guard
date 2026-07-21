from __future__ import annotations

import time

from .attestation import AttestationResult
from .token import Token


class RefusedError(Exception):
    pass


class Broker:
    def __init__(self, secret: bytes, ttl_seconds: int = 300) -> None:
        if not secret:
            raise ValueError("broker requires a non-empty signing secret")
        self._secret = secret
        self._ttl = ttl_seconds

    def mint(
        self,
        attestation: AttestationResult,
        subject: str,
        human_grant: set[str],
        task_scope: set[str],
        now: float | None = None,
    ) -> Token:
        if not attestation.verified:
            raise RefusedError(f"unverified attestation, no token minted: {attestation.reason}")
        now = now or time.time()
        scopes = human_grant & task_scope
        return Token(
            subject=subject,
            agent_id=f"agent:{attestation.sandbox_id}",
            sandbox_id=attestation.sandbox_id,
            trust_tier=attestation.trust_tier,
            scopes=tuple(sorted(scopes)),
            exp=now + self._ttl,
        )
