# 中间人攻击与防御实验器

安装依赖并启动：

```bash
uv sync
uv run uvicorn app.main:app --reload
```

打开 http://127.0.0.1:8000；测试运行 `uv run pytest`。

Alice/Bob 用自实现模幂 Diffie-Hellman 协商密钥、自实现 SHA-256 和 HMAC，并用 SHA-256 密钥流 XOR 加密。关闭防御时，DH public key 在普通通信流程中明文交换，Evil 可以替换它们并分别解密、重加密消息。

开启防御后，Alice/Bob 预先在线下交换长期 public key 并得到长期 K。每次实验先建立一个 `key_exchange` session：Alice 产生 `session_id`，双方的会话 public key 使用长期 K 加密并通过 HMAC 验证；Evil 只能看到密文，无法完成替换。交换完成后进入新的 `communication` session，Alice 再产生一个新的 `session_id`，双方使用会话共享密钥保护消息。nonce 缓存按 session 隔离，重复报文会被拒绝。

界面中的“下一步”可逐步查看通信日志，每个 session 单独占一列。
