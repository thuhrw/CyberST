import secrets

from .core import (
    constant_time_equal,
    crypt,
    decrypt,
    dh_keypair,
    dh_shared,
    sha256,
    tag,
)

# The lab keeps an out-of-band trust store for the lifetime of the process.
# In a deployed protocol these fingerprints would be provisioned externally.
_ALICE_PRIVATE, _ALICE_PUBLIC = dh_keypair()
_BOB_PRIVATE, _BOB_PUBLIC = dh_keypair()


def run(message, attack="none", defense=False):
    if attack not in {"none", "key_replace", "tamper"}:
        raise ValueError("unknown attack scenario")
    logs = []
    L = lambda a, x, d: logs.append({"actor": a, "action": x, "detail": d})
    ap, AP = _ALICE_PRIVATE, _ALICE_PUBLIC
    bp, BP = _BOB_PRIVATE, _BOB_PUBLIC
    L("Alice", "Generate keys", f"A={AP}")
    L("Bob", "Generate keys", f"B={BP}")
    trusted_bob = sha256(str(BP).encode()).hex()
    trusted_alice = sha256(str(AP).encode()).hex()
    L("Alice", "Send public key", f"A={AP} to Evil")
    if attack == "key_replace":
        e1, E1 = dh_keypair()
        e2, E2 = dh_keypair()
        L("Evil", "Replace Alice key", f"Forward E1={E1} to Bob")
        received_bob_key = E1
        L("Bob", "Send public key", f"B={BP} to Evil")
        L("Evil", "Replace Bob key", f"Forward E2={E2} to Alice")
        received_alice_key = E2
        el, er = dh_shared(e1, AP), dh_shared(e2, BP)
    else:
        L("Evil", "Forward public key", f"A={AP} to Bob")
        L("Bob", "Send public key", f"B={BP} to Evil")
        L("Evil", "Forward public key", f"B={BP} to Alice")
        received_bob_key, received_alice_key = BP, AP
        el = er = None
    if defense:
        bob_fp = sha256(str(received_bob_key).encode()).hex()
        alice_fp = sha256(str(received_alice_key).encode()).hex()
        alice_ok = bob_fp == trusted_bob
        bob_ok = alice_fp == trusted_alice
        L(
            "Alice",
            "Verify Bob",
            f"fingerprint {bob_fp[:16]}，result={'passed' if alice_ok else 'failed'}",
        )
        L(
            "Bob",
            "Verify Alice",
            f"fingerprint {alice_fp[:16]}，result={'passed' if bob_ok else 'failed'}",
        )
        if not (alice_ok and bob_ok):
            L(
                "Alice/Bob",
                "Terminate session",
                "Identity verification failed; no shared key established",
            )
            return {
                "success": False,
                "message": "Connection blocked by defense",
                "logs": logs,
                "transcript": [],
            }
    ash = dh_shared(ap, received_bob_key)
    bsh = dh_shared(bp, received_alice_key)
    n = secrets.token_hex(6)
    c = crypt(message, ash, n)
    mac = tag(c, ash, n)
    packet = {"ciphertext": c, "nonce": n, "tag": mac}
    L("Alice", "Send", f"ciphertext {c}，nonce {n}，tag {mac}")
    tr = [{"from": "Alice", "to": "Evil", "data": dict(packet)}]
    if attack == "tamper":
        packet["ciphertext"] = (
            "00" if packet["ciphertext"][:2] != "00" else "ff"
        ) + packet["ciphertext"][2:]
        L("Evil", "Tamper message", f"ciphertext→{packet['ciphertext']}")
    elif attack == "key_replace":
        plain = decrypt(packet["ciphertext"], el, packet["nonce"])
        packet["ciphertext"] = crypt(plain + " [intercepted]", er, packet["nonce"])
        packet["tag"] = tag(packet["ciphertext"], er, packet["nonce"])
        L("Evil", "Decrypt and forward", f"Intercepted plaintext:{plain}")
    else:
        L("Evil", "Forward message", "Forward ciphertext without changes")
    tr.append({"from": "Evil", "to": "Bob", "data": dict(packet)})
    valid = constant_time_equal(
        packet["tag"], tag(packet["ciphertext"], bsh, packet["nonce"])
    )
    try:
        r = decrypt(packet["ciphertext"], bsh, packet["nonce"])
    except (ValueError, UnicodeDecodeError):
        r = "[Unable to decrypt]"
    if defense and not valid:
        L("Bob", "Reject message", "Integrity check failed")
        r = "[Rejected]"
    else:
        L("Bob", "Receive", f"plaintext:{r}")
    return {
        "success": True,
        "message": "Communication complete",
        "logs": logs,
        "transcript": tr,
        "received": r,
        "integrity": valid,
    }
