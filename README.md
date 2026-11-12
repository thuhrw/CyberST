# 中间人攻击与防御实验器

安装依赖并启动：

```bash
uv sync
uv run uvicorn app.main:app --reload
```

打开 http://127.0.0.1:8000；测试运行 `uv run pytest`。

Alice/Bob 用自实现模幂 Diffie-Hellman 协商密钥、自实现 SHA-256 和 HMAC，并用 SHA-256 密钥流 XOR 加密。每条通信报文包含会话 ID、递增 `sequence`、随机 `nonce`、`ciphertext` 和 `tag`；标签覆盖这些字段，防止攻击者修改序列号。Evil 可密钥替换窃听、篡改密文或重放已截获报文；启用防御后通过公开值指纹验证阻断替换、完整性校验拒绝篡改，并通过 64 位滑动窗口防止重复、过旧和超出序号范围的报文。界面中的 “Next step” 可逐步查看通信日志。
