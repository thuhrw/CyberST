"""Sequence numbers and the sliding anti-replay window used by the lab."""

from dataclasses import dataclass


MAX_SEQUENCE = (1 << 32) - 1


@dataclass
class SequenceCounter:
    """Monotonic sender sequence number for one security association."""

    value: int = 0

    def next(self) -> int:
        if self.value >= MAX_SEQUENCE:
            raise OverflowError("security association sequence space exhausted")
        self.value += 1
        return self.value


@dataclass
class ReplayWindow:
    """A fixed-size bitmap window, with the newest sequence at bit zero."""

    size: int = 64
    highest: int = 0
    bitmap: int = 0

    def __post_init__(self) -> None:
        if self.size <= 0:
            raise ValueError("window size must be positive")
        self._mask = (1 << self.size) - 1

    def accept(self, sequence: int) -> bool:
        """Record an authenticated sequence and return whether it is new."""
        if not 1 <= sequence <= MAX_SEQUENCE:
            return False
        if self.highest == 0:
            self.highest = sequence
            self.bitmap = 1
            return True
        if sequence > self.highest:
            shift = sequence - self.highest
            self.bitmap = 1 if shift >= self.size else ((self.bitmap << shift) | 1) & self._mask
            self.highest = sequence
            return True

        offset = self.highest - sequence
        if offset >= self.size or self.bitmap & (1 << offset):
            return False
        self.bitmap |= 1 << offset
        return True
