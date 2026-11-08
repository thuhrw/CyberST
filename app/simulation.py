import hashlib
import hmac
import secrets

from .core import *


def run(message, attack="none", defense=False):
    logs = []
    L = lambda a, x, d: logs.append({"actor": a, "action": x, "detail": d})
    ap, AP = dh_keypair()
    bp, BP = dh_keypair()
    L("Alice", "Generate keys", f"A={AP}")
    L("Bob", "Generate keys", f"B={BP}")
    L("Alice", "Send public key", f"A={AP} to Evil")
    L("Evil", "Forward public key", f"A={AP} to Bob")
    L("Bob", "Send public key", f"B={BP} to Evil")
    L("Evil", "Forward public key", f"B={BP} to Alice")
    trusted_bob = hashlib.sha256(str(BP).encode()).hexdigest()[:16]
    trusted_alice = hashlib.sha256(str(AP).encode()).hexdigest()[:16]
    if attack == "key_replace":
        e1, E1 = dh_keypair()
        e2, E2 = dh_keypair()
        L("Evil", "Replace keys", f"A→{E1}, B→{E2}")
        received_bob_key, received_alice_key = E1, E2
        el, er = dh_shared(e1, AP), dh_shared(e2, BP)
    else:
        received_bob_key, received_alice_key = BP, AP
        el = er = None
    if defense:
        bob_fp = hashlib.sha256(str(received_bob_key).encode()).hexdigest()[:16]
        alice_fp = hashlib.sha256(str(received_alice_key).encode()).hexdigest()[:16]
        alice_ok = bob_fp == trusted_bob
        bob_ok = alice_fp == trusted_alice
        L(
            "Alice",
            "Verify Bob",
            f"fingerprint {bob_fp}，result={'passed' if alice_ok else 'failed'}",
        )
        L(
            "Bob",
            "Verify Alice",
            f"fingerprint {alice_fp}，result={'passed' if bob_ok else 'failed'}",
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
    L("Alice", "Send", f"ciphertext {c}，tag {mac}")
    tr = [{"from": "Alice", "to": "Evil", "data": c}]
    if attack == "tamper":
        c = ("00" if c[:2] != "00" else "ff") + c[2:]
        L("Evil", "Tamper message", f"ciphertext→{c}")
    elif attack == "key_replace":
        plain = decrypt(c, el, n)
        c = crypt(plain + " [intercepted]", er, n)
        L("Evil", "Decrypt and forward", f"Intercepted plaintext:{plain}")
    else:
        L("Evil", "Forward message", "Forward ciphertext without changes")
    tr.append({"from": "Evil", "to": "Bob", "data": c})
    valid = hmac.compare_digest(mac, tag(c, bsh, n))
    try:
        r = decrypt(c, bsh, n)
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
