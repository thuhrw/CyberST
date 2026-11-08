import pytest

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


def test_unknown_attack_is_rejected():
    with pytest.raises(ValueError):
        run("hello", "unknown", False)
