# 中间人攻击与防御实验器

一个用于演示 Diffie-Hellman 密钥协商、中间人攻击（MITM）以及完整性和重放防御的交互式 Web 实验项目。

项目通过 Alice、Evil、Bob 三个角色还原通信过程。前端以拓扑图和分步日志展示每个动作，后端则实际执行密钥生成、共享密钥计算、加密、解密、HMAC 校验和 nonce 重放检测，而不是只根据条件输出预设日志。

> 这是密码学教学模拟器。项目中的密码组件用于展示算法流程，不应替代生产环境中的 TLS、AES-GCM 或 ChaCha20-Poly1305 实现。

## 功能亮点

- **真实的 DH 密钥协商**：使用自实现快速模幂计算生成公钥和共享密钥。
- **真实的报文处理**：消息会根据共享密钥和 nonce 生成密文，并在接收端解密。
- **完整性保护**：使用自实现 SHA-256 和 HMAC-SHA256 为密文、nonce、session ID 生成认证标签。
- **可观测的 MITM**：未启用防御时，Evil 可以替换双方的 DH 公钥，并分别解密、重新加密和转发消息。
- **会话级防御**：启用防御后，临时会话公钥通过长期共享密钥加密并认证，通信和密钥交换使用不同的 session。
- **篡改和重放检测**：认证失败的报文会被拒绝；同一 session 中重复使用的 nonce 会被拒绝。
- **分步交互界面**：点击“下一步”查看 Alice、Evil、Bob 的通信动作和每个 session 的日志。

## 快速开始

### 环境要求

- Python 3.11 或更高版本
- uv

### 安装依赖

```bash
git clone <repository-url>
cd mitm-lab
uv sync
```

### 启动 Web 服务

```bash
uv run uvicorn app.main:app --reload
```

打开 <http://127.0.0.1:8000>，在页面中选择消息、攻击场景和是否启用防御，然后运行实验。

### 运行测试

```bash
uv run pytest
```

测试覆盖自实现密码算法与 Python 标准库/独立参考实现的结果一致性，以及完整的攻防流程。当前测试包括 DH、SHA-256、HMAC、密钥流加密、密钥替换、消息篡改、重放和 nonce session 隔离。

## 实验流程

### 未启用防御

1. Alice 和 Bob 明文交换临时 DH public key。
2. Evil 可以替换两侧 public key，建立两个不同的共享密钥。
3. Alice 使用 Alice-Evil 共享密钥加密消息。
4. Evil 解密消息，再使用 Evil-Bob 共享密钥重新加密并生成新的认证标签。
5. Bob 使用 Evil-Bob 共享密钥解密，因此无法发现消息曾经过 Evil。

在正常通信中，Alice 和 Bob 的 public key 不被替换，双方直接得到同一个共享密钥。

### 启用防御

1. Alice 和 Bob 使用线下预置的长期 DH public key 得到长期共享密钥。
2. 每次实验创建独立的 `key_exchange` session。
3. 双方的临时 session public key 使用长期共享密钥加密，并用 HMAC 绑定密文、nonce 和 session ID。
4. Evil 只能转发经过认证的密文，不能直接替换其中的 session public key。
5. 密钥交换完成后创建新的 `communication` session，使用临时会话共享密钥保护消息。
6. Bob 先验证 HMAC，再检查当前 session 的 nonce 是否已经使用过，最后才解密消息。

## 攻击场景

| 场景 | 未启用防御 | 启用防御 |
| --- | --- | --- |
| `none` | 正常通信 | 正常通信，使用加密的会话公钥交换 |
| `key_replace` | Evil 替换 DH public key，解密并重新加密消息 | Evil 只能看到密文并放弃替换 |
| `tamper` | Evil 修改密文；Bob 仍会尝试接收，完整性标记失败 | Bob 在解密前拒绝报文 |
| `replay` | 同一报文可以被 Bob 重复接收 | 第二次使用相同 nonce 的报文被拒绝 |

攻击场景通过 API 的 `attack` 字段选择：`none`、`key_replace`、`tamper` 或 `replay`。

## 密码学实现

核心实现位于 [`app/core.py`](app/core.py)：

- `modexp()`：快速模幂，用于 DH 公钥和共享密钥计算。
- `sha256()`：本地实现的 SHA-256，测试中与 `hashlib.sha256` 对照。
- `hmac_sha256()`：本地实现的 HMAC-SHA256，测试中与 `hmac.new` 对照。
- `crypt()` / `decrypt()`：基于 SHA-256 密钥流和 XOR 的教学加密封装。
- `tag()`：对 `session_id`、`nonce` 和密文计算认证标签。
- `constant_time_equal()`：用于标签比较的常量时间比较函数。

`crypt()` 是项目自定义的教学构造，并不是 AES 或 ChaCha20。测试会用独立的 `hashlib` 参考实现验证其计算结果，但结果一致不代表该构造适合生产环境。

## HTTP API

服务提供以下接口：

```text
GET  /
POST /api/simulate
```

请求示例：

```bash
curl -X POST http://127.0.0.1:8000/api/simulate \
  -H 'Content-Type: application/json' \
  -d '{
    "message": "Meet at 10:00",
    "attack": "key_replace",
    "defense": false
  }'
```

请求字段：

| 字段 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `message` | string | `Meet at 10:00` | Alice 要发送的消息 |
| `attack` | string | `none` | `none`、`key_replace`、`tamper` 或 `replay` |
| `defense` | boolean | `false` | 是否启用认证会话和重放防御 |

响应包含：

- `logs`：按执行顺序排列的角色动作；
- `exchange_transcript`：DH 公钥或认证加密会话公钥的网络报文；
- `transcript`：消息发送、转发和重放报文；
- `sessions` / `session_ids`：密钥交换和通信 session；
- `received`：Bob 最终收到的内容或拒绝结果；
- `integrity`：最终报文的完整性校验结果；
- `replay_detected`：是否执行了重放场景。

## 项目结构

```text
mitm-lab/
├── app/
│   ├── core.py          # DH、SHA-256、HMAC、加密和认证标签
│   ├── replay.py        # 按 session 管理 nonce 的重放缓存
│   ├── simulation.py    # Alice/Evil/Bob 协议和攻击模拟
│   └── main.py          # FastAPI 应用和 HTTP 接口
├── static/
│   ├── index.html       # 交互式实验界面
│   └── project-background.webp
├── tests/
│   ├── test_core.py     # 算法与标准库参考结果对照
│   └── test_simulation.py # 端到端攻防流程测试
├── pyproject.toml
└── uv.lock
```
