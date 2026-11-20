"""Nonce tracking used by the lab's anti-replay defense."""

from dataclasses import dataclass, field


@dataclass
class NonceReplayCache:
    """Remember authenticated nonces separately for every session.

    A nonce is only meaningful in its authenticated session, so callers must
    always provide a non-empty ``session_id``.
    """

    by_session: dict[str, set[str]] = field(default_factory=dict)

    def accept(self, nonce: str, session_id: str) -> bool:
        """Record a new nonce and return False for a duplicate in its session."""
        if not session_id:
            raise ValueError("session_id is required")
        session_seen = self.by_session.setdefault(session_id, set())
        if nonce in session_seen:
            return False
        session_seen.add(nonce)
        return True
