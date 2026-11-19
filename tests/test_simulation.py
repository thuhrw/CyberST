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


def test_key_replacement_is_visible_without_defense_and_encrypted_with_defense():
    attack = run("secret", "key_replace", False)
    assert attack["received"] == "secret"
    assert attack["integrity"] is True
    assert any(log["action"] == "解密并重新加密消息" for log in attack["logs"])
    assert (
        attack["transcript"][0]["data"]["ciphertext"]
        != attack["transcript"][1]["data"]["ciphertext"]
    )

    defended = run("secret", "key_replace", True)
    assert defended["success"] is True
    assert defended["received"] == "secret"
    assert any(
        log["action"] == "发现这是密文" and log["detail"] == "放弃替换"
        for log in defended["logs"]
    )
    assert len(defended["sessions"]) == 2
    assert (
        defended["session_ids"]["key_exchange"]
        != defended["session_ids"]["communication"]
    )


def test_defended_session_key_exchange_contains_only_authenticated_ciphertext():
    result = run("secret", "none", True)
    assert all(
        set(item["data"]) == {"ciphertext", "nonce", "tag"}
        for item in result["exchange_transcript"]
    )
    key_session = result["session_ids"]["key_exchange"]
    communication_session = result["session_ids"]["communication"]
    assert {log["session_id"] for log in result["logs"]} == {
        key_session,
        communication_session,
    }


def test_unauthenticated_flow_has_a_session_for_encrypted_messages_only():
    result = run("hello", "none", False)
    assert set(result["session_ids"]) == {"communication"}
    communication_id = result["session_ids"]["communication"]
    assert result["sessions"] == [
        {"session_id": communication_id, "type": "communication", "label": "普通通信"}
    ]
    assert all(log["kind"] != "generate_session_id" for log in result["logs"])

    communication_kinds = {
        "send_message",
        "forward_message",
        "receive_message",
        "tamper_message",
        "replay_message",
        "decrypt_forward_message",
        "reject_integrity",
        "reject_replay",
    }
    assert all(
        log.get("session_id") == communication_id
        for log in result["logs"]
        if log["kind"] in communication_kinds
    )
    assert all(
        "session_id" not in log
        for log in result["logs"]
        if log["kind"] not in communication_kinds
    )
    assert all(
        packet["session_id"] == communication_id for packet in result["transcript"]
    )
    assert all("session_id" not in packet for packet in result["exchange_transcript"])


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
    assert sum(log["action"] == "接收消息" for log in attack["logs"]) == 2

    blocked = run("hello", "replay", True)
    assert blocked["replay_detected"] is True
    assert blocked["received"] == "[Replay rejected]"
    assert blocked["integrity"] is True
    assert any("检测到重放" in log["detail"] for log in blocked["logs"])


def test_nonce_cache_remembers_all_seen_nonces():
    cache = NonceReplayCache()
    assert cache.accept("nonce-a") is True
    assert cache.accept("nonce-b") is True
    assert cache.accept("nonce-a") is False
    assert cache.seen == {"nonce-a", "nonce-b"}


def test_nonce_cache_is_scoped_to_session():
    cache = NonceReplayCache()
    assert cache.accept("same", "session-a") is True
    assert cache.accept("same", "session-b") is True
    assert cache.accept("same", "session-a") is False


def test_unknown_attack_is_rejected():
    with pytest.raises(ValueError):
        run("hello", "unknown", False)
