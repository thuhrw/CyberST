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
    if attack == "key_replace":
        e1, E1 = dh_keypair()
        e2, E2 = dh_keypair()
        L("Evil", "替换密钥", f"A→{E1}, B→{E2}")
        if defense:
            L("Alice/Bob", "验证失败", "公开值指纹不匹配，拒绝会话")
            return {
                "success": False,
                "message": "连接被防御阻断",
                "logs": logs,
                "transcript": [],
            }
        ash = dh_shared(ap, E1)
        bsh = dh_shared(bp, E2)
        el = dh_shared(e1, AP)
        er = dh_shared(e2, BP)
    else:
        ash = dh_shared(ap, BP)
        bsh = dh_shared(bp, AP)
        el = er = None
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
