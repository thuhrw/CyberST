# 中间人攻击与防御实验器

一个用于演示 Diffie-Hellman 密钥协商、中间人攻击（MITM）以及完整性和重放防御的交互式 Web 实验项目。

项目通过 Alice、Evil、Bob 三个角色还原通信过程。前端以拓扑图和分步日志展示每个动作，后端则实际执行密钥生成、共享密钥计算、加密、解密、HMAC 校验和 nonce 重放检测。


## 快速开始

### 环境要求

- Python 3.11 或更高版本
- uv

### 安装依赖

```bash
uv sync
```

### 启动 Web 服务

```bash
uv run uvicorn app.main:app --reload
```

打开 <http://127.0.0.1:8000>，在页面中选择消息、攻击场景和是否启用防御，然后运行实验。

### 运行测试

```bash
uv run pytest -q
```

测试覆盖自实现密码算法与 Python 标准库/独立参考实现的结果一致性，以及完整的攻防流程。当前测试包括 DH、SHA-256、HMAC、密钥流加密、密钥替换、消息篡改、重放和 nonce session 隔离。

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
- `sha256()`：本地实现的 SHA-256。
- `hmac_sha256()`：本地实现的 HMAC-SHA256。
- `crypt()` / `decrypt()`：基于 SHA-256 密钥流和 XOR 的加密封装。
- `tag()`：对 `session_id`、`nonce` 和密文计算认证标签。
- `constant_time_equal()`：用于标签比较的常量时间比较函数。


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
- `success`：模拟流程是否成功执行；
- `message`：本次实验的结果说明；
- `defense`：本次实验是否启用防御。

## 项目结构

```text
./
├── app/
│   ├── core.py          # DH、SHA-256、HMAC、加密和认证标签
│   ├── replay.py        # 按 session 管理 nonce 的重放缓存
│   ├── simulation.py    # Alice/Evil/Bob 协议和攻击模拟
│   └── main.py          # FastAPI 应用和 HTTP 接口
├── static/
│   └── index.html       # 交互式实验界面
├── tests/
│   ├── test_core.py     # 算法与标准库参考结果对照
│   └── test_simulation.py # 端到端攻防流程测试
├── pyproject.toml
└── uv.lock
```
