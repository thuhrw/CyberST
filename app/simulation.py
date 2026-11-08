import hashlib
import hmac
import secrets

from .core import *


def run(message, attack="none", defense=False):
    logs = []
    L = lambda a, x, d: logs.append({"actor": a, "action": x, "detail": d})
    ap, AP = dh_keypair()
    bp, BP = dh_keypair()
    L("Alice", "生成密钥", f"A={AP}")
    L("Bob", "生成密钥", f"B={BP}")
    trusted_bob = hashlib.sha256(str(BP).encode()).hexdigest()[:16]
    trusted_alice = hashlib.sha256(str(AP).encode()).hexdigest()[:16]
    if attack == "key_replace":
        e1, E1 = dh_keypair()
        e2, E2 = dh_keypair()
        L("Evil", "替换密钥", f"A→{E1}, B→{E2}")
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
        L("Alice", "验证 Bob", f"指纹 {bob_fp}，结果={'通过' if alice_ok else '失败'}")
        L("Bob", "验证 Alice", f"指纹 {alice_fp}，结果={'通过' if bob_ok else '失败'}")
        if not (alice_ok and bob_ok):
            L("Alice/Bob", "终止会话", "身份验证失败，未建立共享密钥")
            return {
                "success": False,
                "message": "连接被防御阻断",
                "logs": logs,
                "transcript": [],
            }
    ash = dh_shared(ap, received_bob_key)
    bsh = dh_shared(bp, received_alice_key)
    n = secrets.token_hex(6)
    c = crypt(message, ash, n)
    mac = tag(c, ash, n)
    L("Alice", "发送", f"密文 {c}，标签 {mac}")
    tr = [{"from": "Alice", "to": "Evil", "data": c}]
    if attack == "tamper":
        c = ("00" if c[:2] != "00" else "ff") + c[2:]
        L("Evil", "篡改消息", f"密文→{c}")
    elif attack == "key_replace":
        plain = decrypt(c, el, n)
        c = crypt(plain + " [已窃听]", er, n)
        L("Evil", "解密并转发", f"窃听内容：{plain}")
    tr.append({"from": "Evil", "to": "Bob", "data": c})
    valid = hmac.compare_digest(mac, tag(c, bsh, n))
    try:
        r = decrypt(c, bsh, n)
    except (ValueError, UnicodeDecodeError):
        r = "[无法解密]"
    if defense and not valid:
        L("Bob", "拒绝消息", "完整性校验失败")
        r = "[已拒绝]"
    else:
        L("Bob", "接收", f"明文：{r}")
    return {
        "success": True,
        "message": "通信完成",
        "logs": logs,
        "transcript": tr,
        "received": r,
        "integrity": valid,
    }
