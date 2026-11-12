import pytest

from app.replay import MAX_SEQUENCE, ReplayWindow, SequenceCounter
from app.simulation import run


def test_normal_communication_preserves_message_and_transmits_envelope():
    result = run("Meet at 10:00", "none", True)
    assert result["success"] is True
    assert result["received"] == "Meet at 10:00"
    assert result["integrity"] is True
    packet = result["transcript"][1]["data"]
    assert set(packet) == {"session_id", "sequence", "ciphertext", "nonce", "tag"}
    assert packet["sequence"] == 1


def test_key_replacement_is_visible_without_defense_and_blocked_with_defense():
    attack = run("secret", "key_replace", False)
    assert attack["received"] == "secret [intercepted]"
    assert attack["integrity"] is True

    blocked = run("secret", "key_replace", True)
    assert blocked["success"] is False
    assert blocked["transcript"] == []


def test_tampering_fails_integrity_and_is_rejected_by_defense():
    attack = run("hello", "tamper", False)
    assert attack["integrity"] is False
    assert attack["received"] != "hello"

    blocked = run("hello", "tamper", True)
    assert blocked["success"] is True
    assert blocked["received"] == "[Rejected]"
    assert blocked["integrity"] is False


def test_replay_is_accepted_without_defense_and_rejected_with_sequence_window():
    attack = run("hello", "replay", False)
    assert attack["replay_detected"] is True
    assert len(attack["transcript"]) == 3
    assert attack["received"] == "hello"
    assert attack["integrity"] is True
    assert sum(log["action"] == "Receive" for log in attack["logs"]) == 2

    blocked = run("hello", "replay", True)
    assert blocked["replay_detected"] is True
    assert blocked["received"] == "[Replay rejected]"
    assert blocked["integrity"] is True
    assert any("Replay detected" in log["detail"] for log in blocked["logs"])


def test_sliding_window_accepts_new_out_of_order_packets_and_rejects_old_duplicates():
    window = ReplayWindow(size=4)
    assert [window.accept(sequence) for sequence in [1, 3, 2, 4]] == [True, True, True, True]
    assert window.accept(3) is False
    assert window.accept(1) is False
    assert window.accept(5) is True
    assert window.accept(2) is False


def test_sequence_counter_stops_before_wraparound():
    counter = SequenceCounter(MAX_SEQUENCE - 1)
    assert counter.next() == MAX_SEQUENCE
    with pytest.raises(OverflowError):
        counter.next()


def test_unknown_attack_is_rejected():
    with pytest.raises(ValueError):
        run("hello", "unknown", False)
