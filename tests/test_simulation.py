import pytest

from app.replay import NonceReplayCache
from app.simulation import run


def test_normal_communication_preserves_message_and_transmits_envelope():
    result = run("Meet at 10:00", "none", True)
    assert result["success"] is True
    assert result["received"] == "Meet at 10:00"
    assert result["integrity"] is True
    packet = result["transcript"][1]["data"]
    assert set(packet) == {"ciphertext", "nonce", "tag"}


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


def test_replay_is_accepted_without_defense_and_rejected_with_nonce_cache():
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


def test_nonce_cache_remembers_all_seen_nonces():
    cache = NonceReplayCache()
    assert cache.accept("nonce-a") is True
    assert cache.accept("nonce-b") is True
    assert cache.accept("nonce-a") is False
    assert cache.seen == {"nonce-a", "nonce-b"}


def test_unknown_attack_is_rejected():
    with pytest.raises(ValueError):
        run("hello", "unknown", False)
