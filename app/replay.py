"""Nonce tracking used by the lab's anti-replay defense."""

from dataclasses import dataclass, field


@dataclass
class NonceReplayCache:
    """Remember every authenticated nonce received in one session."""

    seen: set[str] = field(default_factory=set)

    def accept(self, nonce: str) -> bool:
        """Record a new nonce and return False for a duplicate."""
        if nonce in self.seen:
            return False
        self.seen.add(nonce)
        return True
