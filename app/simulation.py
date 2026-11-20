"""Protocol-level simulation for the interactive MITM lab."""

import secrets
from dataclasses import dataclass, field

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


@dataclass
class Party:
    """State held by an honest endpoint in one simulated protocol run."""

    name: str
    replay_cache: NonceReplayCache = field(default_factory=NonceReplayCache)
    long_private: int | None = None
    long_public: int | None = None
    long_shared: int | None = None
    session_private: int | None = None
    session_public: int | None = None
    session_shared: int | None = None

    def provision_long_term(self, private: int, public: int) -> None:
        self.long_private = private
        self.long_public = public

    def establish_long_shared(self, peer_public: int) -> None:
        if self.long_private is None:
            raise RuntimeError(f"{self.name} has no long-term private key")
        self.long_shared = dh_shared(self.long_private, peer_public)

    def generate_session_keypair(self) -> None:
        self.session_private, self.session_public = dh_keypair()

    def encrypt_session_public_key(self, session_id: str) -> dict:
        """Encrypt this party's ephemeral public key for its peer."""
        if self.long_shared is None:
            raise RuntimeError(f"{self.name} has no long-term shared key")
        if self.session_public is None:
            raise RuntimeError(f"{self.name} has no session public key")
        nonce = secrets.token_hex(12)
        ciphertext = crypt(str(self.session_public), self.long_shared, nonce)
        return {
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": tag(ciphertext, self.long_shared, nonce, session_id),
        }

    def open_session_public_key(self, packet: dict, session_id: str) -> int:
        """Verify and decrypt a peer's ephemeral public key."""
        if self.long_shared is None:
            raise RuntimeError(f"{self.name} has no long-term shared key")
        valid = constant_time_equal(
            packet.get("tag", ""),
            tag(
                packet["ciphertext"],
                self.long_shared,
                packet["nonce"],
                session_id,
            ),
        )
        if not valid:
            raise ValueError("invalid authenticated session public key")
        return int(decrypt(packet["ciphertext"], self.long_shared, packet["nonce"]))

    def establish_session_shared(self, peer_public: int) -> None:
        if self.session_private is None:
            raise RuntimeError(f"{self.name} has no session private key")
        self.session_shared = dh_shared(self.session_private, peer_public)

    def encrypt_message(self, message: str, session_id: str) -> dict:
        if self.session_shared is None:
            raise RuntimeError(f"{self.name} has no session shared key")
        nonce = secrets.token_hex(12)
        ciphertext = crypt(message, self.session_shared, nonce)
        return {
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": tag(ciphertext, self.session_shared, nonce, session_id),
        }

    def verify_message(self, packet: dict, session_id: str) -> bool:
        if self.session_shared is None:
            raise RuntimeError(f"{self.name} has no session shared key")
        return constant_time_equal(
            packet.get("tag", ""),
            tag(
                packet["ciphertext"],
                self.session_shared,
                packet["nonce"],
                session_id,
            ),
        )

    def decrypt_message(self, packet: dict) -> str:
        if self.session_shared is None:
            raise RuntimeError(f"{self.name} has no session shared key")
        return decrypt(
            packet["ciphertext"],
            self.session_shared,
            packet["nonce"],
            errors="replace",
        )


@dataclass
class Evil:
    """Ephemeral state created only when an unauthenticated MITM is run."""

    left_private: int | None = None
    left_public: int | None = None
    right_private: int | None = None
    right_public: int | None = None
    alice_shared: int | None = None
    bob_shared: int | None = None

    def prepare_key_replacement(self, alice_public: int, bob_public: int) -> None:
        self.left_private, self.left_public = dh_keypair()
        self.right_private, self.right_public = dh_keypair()
        self.alice_shared = dh_shared(self.right_private, alice_public)
        self.bob_shared = dh_shared(self.left_private, bob_public)

    def tamper_message(self, packet: dict) -> None:
        """Modify ciphertext without knowing the authentication key."""
        packet["ciphertext"] = (
            "00" if packet["ciphertext"][:2] != "00" else "ff"
        ) + packet["ciphertext"][2:]

    def decrypt_and_reencrypt(self, packet: dict, session_id: str) -> str:
        """Decrypt on the Alice side and authenticate a fresh Bob-side packet."""
        if self.alice_shared is None or self.bob_shared is None:
            raise RuntimeError("Evil has no MITM session keys")
        plaintext = decrypt(packet["ciphertext"], self.alice_shared, packet["nonce"])
        packet["ciphertext"] = crypt(plaintext, self.bob_shared, packet["nonce"])
        packet["tag"] = tag(
            packet["ciphertext"], self.bob_shared, packet["nonce"], session_id
        )
        return plaintext

    def replay_message(self, packet: dict) -> dict:
        """Return a separate copy of a captured packet for retransmission."""
        return dict(packet)


def _long_term_keys():
    global _LONG_TERM_KEYS
    if _LONG_TERM_KEYS is None:
        _LONG_TERM_KEYS = (*dh_keypair(), *dh_keypair())
    return _LONG_TERM_KEYS


def _new_session_id() -> str:
    return secrets.token_hex(12)


def run(message, attack="none", defense=False):
    if attack not in {"none", "key_replace", "tamper", "replay"}:
        raise ValueError("unknown attack scenario")

    logs = []
    key_session_id = _new_session_id() if defense else ""
    communication_session_id = _new_session_id()
    alice = Party("Alice")
    bob = Party("Bob")
    evil = Evil()

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
    if defense:
        alice_private, alice_public, bob_private, bob_public = _long_term_keys()
        alice.provision_long_term(alice_private, alice_public)
        bob.provision_long_term(bob_private, bob_public)
        alice.establish_long_shared(bob.long_public)
        bob.establish_long_shared(alice.long_public)
        if alice.long_shared != bob.long_shared:
            raise RuntimeError("long-term DH agreement failed")
        log(
            "Alice/Bob",
            "建立长期 K",
            "线下交换完成，长期共享密钥仅用于保护会话公钥",
            key_session_id,
            "long_term",
        )

    # With defense enabled, ephemeral key pairs are exchanged in the
    # key_exchange session. The receiver always uses Alice's session_id and
    # does not create a new one. Without defense, this exchange remains plain
    # DH traffic and has no session metadata.
    alice.generate_session_keypair()
    bob.generate_session_keypair()
    public_key_label = "会话 public key" if defense else "public key"
    log(
        "Alice",
        f"生成 {public_key_label}",
        f"public key={alice.session_public}",
        key_session_id,
        "generate_session_key",
    )
    log(
        "Bob",
        f"生成 {public_key_label}",
        f"public key={bob.session_public}",
        key_session_id,
        "generate_session_key",
    )

    exchange_transcript = []
    if defense:
        alice_packet = alice.encrypt_session_public_key(key_session_id)
        log(
            "Alice",
            "发送加密会话 public key",
            f"session_id={key_session_id}，密文={alice_packet['ciphertext']}，nonce={alice_packet['nonce']}，tag={alice_packet['tag']}",
            key_session_id,
            "send_session_key",
        )
        exchange_transcript.append(
            packet_event("Alice", "Evil", alice_packet, key_session_id)
        )
        if attack == "key_replace":
            log("Evil", "发现这是密文", "放弃替换", key_session_id, "observe_alice_key")
        else:
            log(
                "Evil",
                "转发加密会话 public key",
                "保持密文不变",
                key_session_id,
                "forward_alice_key",
            )
        if not bob.replay_cache.accept(alice_packet["nonce"], key_session_id):
            raise ValueError("replayed key exchange packet")
        received_alice = bob.open_session_public_key(alice_packet, key_session_id)
        log("Bob", "接收会话 public key", "", key_session_id, "receive_session_key")

        bob_packet = bob.encrypt_session_public_key(key_session_id)
        log(
            "Bob",
            "发送加密会话 public key",
            f"session_id={key_session_id}，密文={bob_packet['ciphertext']}，nonce={bob_packet['nonce']}，tag={bob_packet['tag']}",
            key_session_id,
            "send_session_key",
        )
        exchange_transcript.append(
            packet_event("Bob", "Evil", bob_packet, key_session_id)
        )
        if attack == "key_replace":
            log("Evil", "发现这是密文", "放弃替换", key_session_id, "observe_bob_key")
        else:
            log(
                "Evil",
                "转发加密会话 public key",
                "保持密文不变",
                key_session_id,
                "forward_bob_key",
            )
        if not alice.replay_cache.accept(bob_packet["nonce"], key_session_id):
            raise ValueError("replayed key exchange packet")
        received_bob = alice.open_session_public_key(bob_packet, key_session_id)
        log("Alice", "接收会话 public key", "", key_session_id, "receive_session_key")
    else:
        log(
            "Alice",
            "发送 public key",
            f"public key={alice.session_public}",
            key_session_id,
            "send_session_key",
        )
        exchange_transcript.append(
            packet_event(
                "Alice", "Evil", {"public_key": alice.session_public}, key_session_id
            )
        )
        if attack == "key_replace":
            evil.prepare_key_replacement(alice.session_public, bob.session_public)
            received_alice = evil.left_public
            log(
                "Evil",
                "替换 Alice 的 public key",
                f"转发 public key={evil.left_public} 给 Bob",
                key_session_id,
                "replace_alice_session_key",
            )
        else:
            received_alice = alice.session_public
            log(
                "Evil",
                "转发 public key",
                "保持 public key 不变",
                key_session_id,
                "forward_alice_key",
            )
        log("Bob", "接收 public key", "", key_session_id, "receive_session_key")

        log(
            "Bob",
            "发送 public key",
            f"public key={bob.session_public}",
            key_session_id,
            "send_session_key",
        )
        exchange_transcript.append(
            packet_event(
                "Bob", "Evil", {"public_key": bob.session_public}, key_session_id
            )
        )
        if attack == "key_replace":
            received_bob = evil.right_public
            log(
                "Evil",
                "替换 Bob 的 public key",
                f"转发 public key={evil.right_public} 给 Alice",
                key_session_id,
                "replace_bob_session_key",
            )
        else:
            received_bob = bob.session_public
            log(
                "Evil",
                "转发 public key",
                "保持 public key 不变",
                key_session_id,
                "forward_bob_key",
            )
        log("Alice", "接收 public key", "", key_session_id, "receive_session_key")

    alice.establish_session_shared(received_bob)
    bob.establish_session_shared(received_alice)
    if alice.session_shared == bob.session_shared:
        if defense:
            log(
                "Alice/Bob",
                "完成会话密钥协商",
                "双方得到同一个 session K，进入新的通信 session",
                key_session_id,
                "session_ready",
            )
        else:
            log(
                "Alice/Bob", "完成密钥协商", "双方得到同一个共享 K", "", "session_ready"
            )

    communication_packet = alice.encrypt_message(message, communication_session_id)
    message_prefix = (
        f"session_id={communication_session_id}，" if communication_session_id else ""
    )
    log(
        "Alice",
        "发送消息",
        f"{message_prefix}密文={communication_packet['ciphertext']}，nonce={communication_packet['nonce']}，tag={communication_packet['tag']}",
        communication_session_id,
        "send_message",
    )
    transcript = [
        packet_event("Alice", "Evil", communication_packet, communication_session_id)
    ]

    if attack == "tamper":
        evil.tamper_message(communication_packet)
        log(
            "Evil",
            "篡改消息",
            f"密文→{communication_packet['ciphertext']}",
            communication_session_id,
            "tamper_message",
        )
    elif attack == "key_replace" and not defense:
        plaintext = evil.decrypt_and_reencrypt(
            communication_packet, communication_session_id
        )
        log(
            "Evil",
            "解密并重新加密消息",
            f"截获明文：{plaintext}",
            communication_session_id,
            "decrypt_forward_message",
        )
    elif attack == "key_replace" and defense:
        log(
            "Evil",
            "转发消息",
            "保持密文不变",
            communication_session_id,
            "forward_message",
        )
    else:
        log(
            "Evil",
            "转发消息",
            "保持密文不变",
            communication_session_id,
            "forward_message",
        )

    transcript.append(
        packet_event("Evil", "Bob", communication_packet, communication_session_id)
    )

    def deliver(current_packet, packet_session_id):
        current_nonce = current_packet["nonce"]
        valid = bob.verify_message(current_packet, packet_session_id)
        if defense and not valid:
            log(
                "Bob",
                "拒绝消息",
                "完整性校验失败",
                packet_session_id,
                "reject_integrity",
            )
            return "[Rejected]", False
        if defense and not bob.replay_cache.accept(current_nonce, packet_session_id):
            log(
                "Bob",
                "拒绝消息",
                "检测到重放：该 session 的 nonce 已使用",
                packet_session_id,
                "reject_replay",
            )
            return "[Replay rejected]", True
        received = bob.decrypt_message(current_packet)
        log(
            "Bob", "接收消息", f"明文：{received}", packet_session_id, "receive_message"
        )
        return received, valid

    received, integrity = deliver(
        communication_packet, transcript[-1].get("session_id", "")
    )
    replay_detected = False
    if attack == "replay":
        replay_detected = True
        log(
            "Evil",
            "重放消息",
            "重新发送已截获的报文",
            communication_session_id,
            "replay_message",
        )
        replayed_packet = evil.replay_message(communication_packet)
        transcript.append(
            packet_event(
                "Evil",
                "Bob",
                replayed_packet,
                communication_session_id,
            )
        )
        received, integrity = deliver(
            replayed_packet, transcript[-1].get("session_id", "")
        )

    return {
        "success": True,
        "message": "重放已检测并拒绝" if replay_detected and defense else "通信完成",
        "logs": logs,
        "sessions": (
            [
                {
                    "session_id": key_session_id,
                    "type": "key_exchange",
                    "label": "会话公钥交换",
                },
                {
                    "session_id": communication_session_id,
                    "type": "communication",
                    "label": "加密通信",
                },
            ]
            if defense
            else [
                {
                    "session_id": communication_session_id,
                    "type": "communication",
                    "label": "普通通信",
                }
            ]
        ),
        "session_ids": (
            {"key_exchange": key_session_id, "communication": communication_session_id}
            if defense
            else {"communication": communication_session_id}
        ),
        "exchange_transcript": exchange_transcript,
        "transcript": transcript,
        "received": received,
        "integrity": integrity,
        "replay_detected": replay_detected,
        "defense": defense,
    }
