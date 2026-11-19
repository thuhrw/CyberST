"""Nonce tracking used by the lab's anti-replay defense."""

from dataclasses import dataclass, field


@dataclass
class NonceReplayCache:
    """Remember authenticated nonces separately for every session.

    ``accept(nonce)`` remains supported for callers that model one unnamed
    session.  The simulator passes ``session_id`` explicitly so a nonce used
    in one session does not affect another session.
    """

    seen: set[str] = field(default_factory=set)
    by_session: dict[str, set[str]] = field(default_factory=dict)

    def accept(self, nonce: str, session_id: str = "") -> bool:
        """Record a new nonce and return False for a duplicate in its session."""
        if session_id:
            session_seen = self.by_session.setdefault(session_id, set())
            if nonce in session_seen:
                return False
            session_seen.add(nonce)
            return True
        if nonce in self.seen:
            return False
        self.seen.add(nonce)
        return True
