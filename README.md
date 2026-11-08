# 中间人攻击与防御实验器

`uv sync && uv run uvicorn app.main:app --reload`，打开 http://127.0.0.1:8000；测试运行 `uv run pytest`。

Alice/Bob 用自实现模幂 Diffie-Hellman 协商密钥，自实现 SHA-256 密钥流 XOR 加密与 HMAC 完整性标签。Evil 可密钥替换窃听或篡改密文；启用防御后通过公开值指纹验证阻断替换、完整性校验拒绝篡改。
