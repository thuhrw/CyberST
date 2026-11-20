import hashlib
import hmac

import pytest

import app.simulation as simulation
from app.core import P, decrypt, dh_keypair, dh_shared
from app.replay import NonceReplayCache
from app.simulation import _encrypted_value, _long_term_keys, _open_value, run


def log_kinds(result):
    return [log["kind"] for log in result["logs"]]


def packet(result, index):
    return result["transcript"][index]["data"]


def authenticated_tag(ciphertext, shared, nonce, session_id):
    key = hashlib.sha256(f"mitm-lab:{shared}".encode()).digest()
    payload = f"{session_id}:{nonce}:{ciphertext}".encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def test_normal_defended_flow_completes_authenticated_key_and_message_sessions():
    result = run("Meet at 10:00", "none", True)
    key_session = result["session_ids"]["key_exchange"]
    communication_session = result["session_ids"]["communication"]

    assert result["success"] is True
    assert result["defense"] is True
    assert result["received"] == "Meet at 10:00"
    assert result["integrity"] is True
    assert key_session != communication_session
    assert [session["session_id"] for session in result["sessions"]] == [
        key_session,
        communication_session,
    ]
    assert log_kinds(result) == [
        "long_term",
        "generate_session_key",
        "generate_session_key",
        "send_session_key",
        "forward_alice_key",
        "receive_session_key",
        "send_session_key",
        "forward_bob_key",
        "receive_session_key",
        "session_ready",
        "send_message",
        "forward_message",
        "receive_message",
    ]

    key_packets = [item["data"] for item in result["exchange_transcript"]]
    assert all(set(item) == {"ciphertext", "nonce", "tag"} for item in key_packets)
    assert all(
        item["session_id"] == key_session for item in result["exchange_transcript"]
    )
    assert len({item["nonce"] for item in key_packets}) == 2

    alice_private, alice_public, bob_private, bob_public = _long_term_keys()
    alice_long_shared = dh_shared(alice_private, bob_public)
    bob_long_shared = dh_shared(bob_private, alice_public)
    assert alice_long_shared == bob_long_shared
    generated_session_keys = [
        int(log["detail"].split("=", 1)[1])
        for log in result["logs"]
        if log["kind"] == "generate_session_key"
    ]
    decrypted_session_keys = []
    for item in key_packets:
        assert item["tag"] == authenticated_tag(
            item["ciphertext"], alice_long_shared, item["nonce"], key_session
        )
        decrypted_session_keys.append(
            int(decrypt(item["ciphertext"], alice_long_shared, item["nonce"]))
        )
    assert decrypted_session_keys == generated_session_keys
    assert all(2 <= public_key <= P - 2 for public_key in decrypted_session_keys)

    assert packet(result, 0) == packet(result, 1)


def test_normal_unauthenticated_flow_exposes_plain_dh_and_preserves_message():
    result = run("hello", "none", False)
    communication_id = result["session_ids"]["communication"]

    assert result["defense"] is False
    assert result["received"] == "hello"
    assert result["integrity"] is True
    assert result["sessions"] == [
        {
            "session_id": communication_id,
            "type": "communication",
            "label": "普通通信",
        }
    ]
    assert len(result["exchange_transcript"]) == 2
    assert all(
        set(item["data"]) == {"public_key"} for item in result["exchange_transcript"]
    )
    assert all(
        2 <= item["data"]["public_key"] <= P - 2
        for item in result["exchange_transcript"]
    )
    assert all("session_id" not in item for item in result["exchange_transcript"])
    assert packet(result, 0) == packet(result, 1)
    assert log_kinds(result) == [
        "generate_session_key",
        "generate_session_key",
        "send_session_key",
        "forward_alice_key",
        "receive_session_key",
        "send_session_key",
        "forward_bob_key",
        "receive_session_key",
        "session_ready",
        "send_message",
        "forward_message",
        "receive_message",
    ]


def test_key_replacement_without_defense_uses_two_real_shared_keys(monkeypatch):
    pairs = [dh_keypair() for _ in range(4)]
    pair_queue = iter(pairs)
    monkeypatch.setattr(simulation, "dh_keypair", lambda: next(pair_queue))

    result = simulation.run("secret", "key_replace", False)

    assert result["received"] == "secret"
    assert result["integrity"] is True
    assert result["replay_detected"] is False
    assert log_kinds(result) == [
        "generate_session_key",
        "generate_session_key",
        "send_session_key",
        "replace_alice_session_key",
        "receive_session_key",
        "send_session_key",
        "replace_bob_session_key",
        "receive_session_key",
        "send_message",
        "decrypt_forward_message",
        "receive_message",
    ]
    assert "session_ready" not in log_kinds(result)
    assert any(log["kind"] == "decrypt_forward_message" for log in result["logs"])
    assert not any(log["kind"].startswith("reject_") for log in result["logs"])

    original = packet(result, 0)
    forwarded = packet(result, 1)
    assert original["nonce"] == forwarded["nonce"]
    assert original["ciphertext"] != forwarded["ciphertext"]
    assert original["tag"] != forwarded["tag"]
    alice_private, alice_public = pairs[0]
    bob_private, bob_public = pairs[1]
    evil_left_private, evil_left_public = pairs[2]
    evil_right_private, evil_right_public = pairs[3]
    alice_to_evil = dh_shared(alice_private, evil_right_public)
    evil_to_bob = dh_shared(evil_left_private, bob_public)
    assert alice_to_evil == dh_shared(evil_right_private, alice_public)
    assert evil_to_bob == dh_shared(bob_private, evil_left_public)
    assert decrypt(original["ciphertext"], alice_to_evil, original["nonce"]) == "secret"
    assert decrypt(forwarded["ciphertext"], evil_to_bob, forwarded["nonce"]) == "secret"
    assert original["tag"] == authenticated_tag(
        original["ciphertext"],
        alice_to_evil,
        original["nonce"],
        result["session_ids"]["communication"],
    )
    assert forwarded["tag"] == authenticated_tag(
        forwarded["ciphertext"],
        evil_to_bob,
        forwarded["nonce"],
        result["session_ids"]["communication"],
    )
    assert all(
        item["session_id"] == result["session_ids"]["communication"]
        for item in result["transcript"]
    )


def test_key_replacement_with_defense_cannot_replace_authenticated_session_keys():
    result = run("secret", "key_replace", True)
    key_session = result["session_ids"]["key_exchange"]
    key_kinds = [
        log["kind"] for log in result["logs"] if log.get("session_id") == key_session
    ]

    assert result["received"] == "secret"
    assert result["integrity"] is True
    assert key_kinds.count("observe_alice_key") == 1
    assert key_kinds.count("observe_bob_key") == 1
    assert "replace_alice_session_key" not in key_kinds
    assert "replace_bob_session_key" not in key_kinds
    assert not any(log["kind"] == "decrypt_forward_message" for log in result["logs"])
    assert packet(result, 0) == packet(result, 1)


def test_authenticated_session_public_key_rejects_modified_ciphertext_or_tag():
    alice_private, _, _, bob_public = _long_term_keys()
    shared = dh_shared(alice_private, bob_public)
    session_id = "key-session"
    original = _encrypted_value(123456, shared, session_id)

    tampered_ciphertext = dict(original)
    tampered_ciphertext["ciphertext"] = (
        "00" if original["ciphertext"][:2] != "00" else "ff"
    ) + original["ciphertext"][2:]
    with pytest.raises(ValueError, match="authenticated session public key"):
        _open_value(tampered_ciphertext, shared, session_id)

    tampered_tag = dict(original)
    tampered_tag["tag"] = "0" * len(original["tag"])
    with pytest.raises(ValueError, match="authenticated session public key"):
        _open_value(tampered_tag, shared, session_id)


def test_tampering_keeps_stale_tag_and_is_rejected_only_with_defense():
    attack = run("hello", "tamper", False)
    defended = run("hello", "tamper", True)

    assert attack["integrity"] is False
    assert attack["received"] != "hello"
    assert packet(attack, 0)["tag"] == packet(attack, 1)["tag"]
    assert packet(attack, 0)["ciphertext"] != packet(attack, 1)["ciphertext"]
    assert "reject_integrity" not in log_kinds(attack)

    assert defended["received"] == "[Rejected]"
    assert defended["integrity"] is False
    assert "reject_integrity" in log_kinds(defended)
    assert "receive_message" not in log_kinds(defended)


def test_replay_is_delivered_twice_without_defense():
    result = run("hello", "replay", False)

    assert result["replay_detected"] is True
    assert result["received"] == "hello"
    assert result["integrity"] is True
    assert len(result["transcript"]) == 3
    assert packet(result, 1) == packet(result, 2)
    assert log_kinds(result).count("receive_message") == 2
    assert "reject_replay" not in log_kinds(result)


def test_replay_is_accepted_once_and_rejected_on_second_delivery_with_defense():
    result = run("hello", "replay", True)

    assert result["replay_detected"] is True
    assert result["received"] == "[Replay rejected]"
    assert result["integrity"] is True
    assert len(result["transcript"]) == 3
    assert packet(result, 1) == packet(result, 2)
    assert log_kinds(result).count("receive_message") == 1
    assert log_kinds(result).count("reject_replay") == 1
    assert log_kinds(result)[-2:] == ["replay_message", "reject_replay"]


def test_nonce_cache_requires_session_and_is_scoped_to_session():
    cache = NonceReplayCache()
    assert cache.accept("same", "session-a") is True
    assert cache.accept("same", "session-b") is True
    assert cache.accept("same", "session-a") is False
    with pytest.raises(ValueError, match="session_id is required"):
        cache.accept("same", "")


def test_unknown_attack_is_rejected():
    with pytest.raises(ValueError):
        run("hello", "unknown", False)
