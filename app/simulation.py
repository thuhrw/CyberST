"""Protocol-level simulation for the interactive MITM lab."""

import secrets

from .core import (
    constant_time_equal,
    crypt,
    decrypt,
    dh_keypair,
    dh_shared,
    tag,
)
from .replay import NonceReplayCache


# These public keys model values provisioned out of band. They are initialized
# lazily because the unauthenticated experiment must not use the defense-only
# long-term key layer. Ephemeral keys are generated for every run.
_LONG_TERM_KEYS = None


def _long_term_keys():
    global _LONG_TERM_KEYS
    if _LONG_TERM_KEYS is None:
        _LONG_TERM_KEYS = (*dh_keypair(), *dh_keypair())
    return _LONG_TERM_KEYS


def _new_session_id() -> str:
    return secrets.token_hex(12)


def _encrypted_value(value: int, shared: int, session_id: str, sequence: int) -> dict:
    nonce = secrets.token_hex(12)
    ciphertext = crypt(str(value), shared, nonce)
    return {
        "ciphertext": ciphertext,
        "nonce": nonce,
        "tag": tag(ciphertext, shared, nonce, sequence, session_id),
    }


def _open_value(packet: dict, shared: int, session_id: str, sequence: int) -> int:
    valid = constant_time_equal(
        packet.get("tag", ""),
        tag(packet["ciphertext"], shared, packet["nonce"], sequence, session_id),
    )
    if not valid:
        raise ValueError("invalid authenticated session public key")
    return int(decrypt(packet["ciphertext"], shared, packet["nonce"]))


def run(message, attack="none", defense=False):
    if attack not in {"none", "key_replace", "tamper", "replay"}:
        raise ValueError("unknown attack scenario")

    logs = []
    key_session_id = _new_session_id() if defense else ""
    communication_session_id = _new_session_id() if defense else ""

    def log(actor, action, detail, session_id, kind):
        entry = {
            "actor": actor,
            "action": action,
            "detail": detail,
            "kind": kind,
        }
        if session_id:
            entry["session_id"] = session_id
        logs.append(entry)

    def packet_event(source, target, data, session_id):
        event = {"from": source, "to": target, "data": dict(data)}
        if session_id:
            event["session_id"] = session_id
        return event

    # The long-term key exists only in the defended protocol. It is provisioned
    # outside the network, so Evil cannot replace it during this experiment.
    long_shared = None
    if defense:
        alice_private, alice_public, bob_private, bob_public = _long_term_keys()
        long_shared = dh_shared(alice_private, bob_public)
        bob_long_shared = dh_shared(bob_private, alice_public)
        if long_shared != bob_long_shared:
            raise RuntimeError("long-term DH agreement failed")
        log("Alice/Bob", "建立长期 K", "线下交换完成，长期共享密钥仅用于保护会话公钥", key_session_id, "long_term")

    # Ephemeral key pairs are exchanged in the key_exchange session. The
    # receiver always uses Alice's session_id and does not create a new one.
    alice_session_private, alice_session_public = dh_keypair()
    bob_session_private, bob_session_public = dh_keypair()
    public_key_label = "会话 public key" if defense else "public key"
    log("Alice", f"生成 {public_key_label}", f"public key={alice_session_public}", key_session_id, "generate_session_key")
    log("Bob", f"生成 {public_key_label}", f"public key={bob_session_public}", key_session_id, "generate_session_key")
    if defense:
        log("Alice", "生成 session_id", f"session_id={key_session_id}", key_session_id, "generate_session_id")

    exchange_transcript = []
    key_replay_cache = NonceReplayCache()
    if defense:
        alice_packet = _encrypted_value(alice_session_public, long_shared, key_session_id, 1)
        log("Alice", "发送加密会话 public key", f"session_id={key_session_id}，密文={alice_packet['ciphertext']}", key_session_id, "send_session_key")
        exchange_transcript.append(packet_event("Alice", "Evil", alice_packet, key_session_id))
        if attack == "key_replace":
            log("Evil", "发现这是密文", "放弃替换", key_session_id, "observe_alice_key")
        else:
            log("Evil", "转发加密会话 public key", "保持密文不变", key_session_id, "forward_alice_key")
        if not key_replay_cache.accept(alice_packet["nonce"], key_session_id):
            raise ValueError("replayed key exchange packet")
        received_alice = _open_value(alice_packet, long_shared, key_session_id, 1)
        log("Bob", "接收会话 public key", f"session_id={key_session_id}，public key={received_alice}", key_session_id, "receive_session_key")

        bob_packet = _encrypted_value(bob_session_public, long_shared, key_session_id, 2)
        log("Bob", "发送加密会话 public key", f"session_id={key_session_id}，密文={bob_packet['ciphertext']}", key_session_id, "send_session_key")
        exchange_transcript.append(packet_event("Bob", "Evil", bob_packet, key_session_id))
        if attack == "key_replace":
            log("Evil", "发现这是密文", "放弃替换", key_session_id, "observe_bob_key")
        else:
            log("Evil", "转发加密会话 public key", "保持密文不变", key_session_id, "forward_bob_key")
        if not key_replay_cache.accept(bob_packet["nonce"], key_session_id):
            raise ValueError("replayed key exchange packet")
        received_bob = _open_value(bob_packet, long_shared, key_session_id, 2)
        log("Alice", "接收会话 public key", f"session_id={key_session_id}，public key={received_bob}", key_session_id, "receive_session_key")
        evil_left = evil_right = None
    else:
        log("Alice", "发送 public key", f"public key={alice_session_public}", key_session_id, "send_session_key")
        exchange_transcript.append(packet_event("Alice", "Evil", {"public_key": alice_session_public}, key_session_id))
        if attack == "key_replace":
            evil_left_private, evil_left_public = dh_keypair()
            evil_right_private, evil_right_public = dh_keypair()
            received_alice = evil_left_public
            log("Evil", "替换 Alice 的 public key", f"转发 public key={evil_left_public} 给 Bob", key_session_id, "replace_alice_session_key")
        else:
            received_alice = alice_session_public
            log("Evil", "转发 public key", "保持 public key 不变", key_session_id, "forward_alice_key")
        log("Bob", "接收 public key", f"public key={received_alice}", key_session_id, "receive_session_key")

        log("Bob", "发送 public key", f"public key={bob_session_public}", key_session_id, "send_session_key")
        exchange_transcript.append(packet_event("Bob", "Evil", {"public_key": bob_session_public}, key_session_id))
        if attack == "key_replace":
            received_bob = evil_right_public
            log("Evil", "替换 Bob 的 public key", f"转发 public key={evil_right_public} 给 Alice", key_session_id, "replace_bob_session_key")
            # Alice received Evil's right-hand public key; Bob received the
            # left-hand one. Evil therefore has one shared key per direction.
            evil_alice = dh_shared(evil_right_private, alice_session_public)
            evil_bob = dh_shared(evil_left_private, bob_session_public)
        else:
            received_bob = bob_session_public
            log("Evil", "转发 public key", "保持 public key 不变", key_session_id, "forward_bob_key")
        log("Alice", "接收 public key", f"public key={received_bob}", key_session_id, "receive_session_key")

    alice_shared = dh_shared(alice_session_private, received_bob)
    bob_shared = dh_shared(bob_session_private, received_alice)
    if alice_shared == bob_shared:
        if defense:
            log("Alice/Bob", "完成会话密钥协商", f"session_id={key_session_id}，双方得到同一个 session K，进入新的通信 session", key_session_id, "session_ready")
        else:
            log("Alice/Bob", "完成密钥协商", "双方得到同一个共享 K", "", "session_ready")

    nonce = secrets.token_hex(12)
    ciphertext = crypt(message, alice_shared, nonce)
    communication_packet = {
        "ciphertext": ciphertext,
        "nonce": nonce,
        "tag": tag(ciphertext, alice_shared, nonce, 1, communication_session_id),
    }
    if defense:
        log("Alice", "生成 session_id", f"session_id={communication_session_id}", communication_session_id, "generate_session_id")
    log("Alice", "发送消息", f"密文={ciphertext}，nonce={nonce}，标签={communication_packet['tag']}", communication_session_id, "send_message")
    transcript = [packet_event("Alice", "Evil", communication_packet, communication_session_id)]

    if attack == "tamper":
        communication_packet["ciphertext"] = (
            "00" if communication_packet["ciphertext"][:2] != "00" else "ff"
        ) + communication_packet["ciphertext"][2:]
        log("Evil", "篡改消息", f"密文→{communication_packet['ciphertext']}", communication_session_id, "tamper_message")
    elif attack == "key_replace" and not defense:
        plaintext = decrypt(communication_packet["ciphertext"], evil_alice, communication_packet["nonce"])
        communication_packet["ciphertext"] = crypt(plaintext + " [intercepted]", evil_bob, communication_packet["nonce"])
        communication_packet["tag"] = tag(communication_packet["ciphertext"], evil_bob, communication_packet["nonce"], 1, communication_session_id)
        log("Evil", "解密并转发消息", f"截获明文：{plaintext}", communication_session_id, "decrypt_forward_message")
    elif attack == "key_replace" and defense:
        log("Evil", "转发消息", "保持密文不变", communication_session_id, "forward_message")
    else:
        log("Evil", "转发消息", "保持密文不变", communication_session_id, "forward_message")

    transcript.append(packet_event("Evil", "Bob", communication_packet, communication_session_id))
    replay_cache = NonceReplayCache()

    def deliver(current_packet, packet_session_id):
        current_nonce = current_packet["nonce"]
        valid = constant_time_equal(
            current_packet["tag"],
            tag(current_packet["ciphertext"], bob_shared, current_nonce, 1, packet_session_id),
        )
        if defense and not valid:
            log("Bob", "拒绝消息", "完整性校验失败", packet_session_id, "reject_integrity")
            return "[Rejected]", False
        if defense and not replay_cache.accept(current_nonce, packet_session_id):
            log("Bob", "拒绝消息", "检测到重放：该 session 的 nonce 已使用", packet_session_id, "reject_replay")
            return "[Replay rejected]", True
        try:
            received = decrypt(current_packet["ciphertext"], bob_shared, current_nonce, errors="replace")
        except ValueError:
            received = "[无法解密]"
        log("Bob", "接收消息", f"明文：{received}", packet_session_id, "receive_message")
        return received, valid

    received, integrity = deliver(communication_packet, transcript[-1].get("session_id", ""))
    replay_detected = False
    if attack == "replay":
        replay_detected = True
        log("Evil", "重放消息", "重新发送已截获的报文", communication_session_id, "replay_message")
        transcript.append(packet_event("Evil", "Bob", communication_packet, communication_session_id))
        received, integrity = deliver(communication_packet, transcript[-1].get("session_id", ""))

    return {
        "success": True,
        "message": "重放已检测并拒绝" if replay_detected and defense else "通信完成",
        "logs": logs,
        "sessions": (
            [
                {"session_id": key_session_id, "type": "key_exchange", "label": "会话公钥交换"},
                {"session_id": communication_session_id, "type": "communication", "label": "加密通信"},
            ]
            if defense
            else [{"type": "communication", "label": "普通通信"}]
        ),
        "session_ids": (
            {"key_exchange": key_session_id, "communication": communication_session_id}
            if defense
            else {}
        ),
        "exchange_transcript": exchange_transcript,
        "transcript": transcript,
        "received": received,
        "integrity": integrity,
        "replay_detected": replay_detected,
        "defense": defense,
    }
