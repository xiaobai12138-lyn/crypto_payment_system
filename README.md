# 基于密码学的移动支付终端

完整的移动支付安全体系演示，覆盖**网络攻击 / 数据泄露 / 身份冒用**三大威胁面：

- **传输安全**：ECDH-P256 协商 → HKDF-SHA256 派生 → AES-256-GCM 端到端加密 + Nonce 一次性 + Rate-limit
- **数据落库**：登录/支付密码 PBKDF2-SHA256 双 hash；手机号 / TOTP secret 以 AES-256-GCM 字段级加密 (KEK 文件保护)
- **身份与抗抵赖**：服务端 ECDSA-P256 签发 ES256 JWT；客户端长期 ECDSA-P256 密钥对(localStorage)对每笔交易签名；TOTP RFC 6238 二次验证；设备指纹绑定
- **审计**：HMAC-SHA256 哈希链，单行被改后续全断

> 算法工作原理 / 参数 / 密钥管理详见 [`CRYPTO_DESIGN.md`](./CRYPTO_DESIGN.md)。

## 技术栈

| 层 | 技术 |
| --- | --- |
| 后端 | Python 3.13、Flask 3.1、PyMySQL 1.1、pycryptodome 3.23、cryptography 48、PyJWT 2.12、pyotp 2.9、Werkzeug 3.1 |
| 前端 | 单页 HTML + Tailwind CDN + Font Awesome + Web Crypto API |
| 数据库 | MySQL 8.4 (`secure_pay_db`) |
| 密码学 | ECDH-P256 / HKDF-SHA256 / AES-256-GCM / ECDSA-P256(ES256) / HMAC-SHA256 / PBKDF2-SHA256 / TOTP (HOTP-SHA1) |

## 项目结构

```
payment_system/
├── app.py                       # Flask 后端：路由 / 鉴权 / 加密 / 限流 / 审计链
├── crypto_utils.py              # 密码学工具层 (KEK / JWT / HMAC / TOTP / 限流 / 验签)
├── templates/
│   └── index.html               # 单页 UI: 登录/注册 / 首页 / 收付款 / 转账 / 2FA绑定 / 安全中心
├── migrations/
│   ├── init_schema.sql                       # 从零建库一键脚本 (幂等, 含 direction 字段)
│   ├── 2026-05-14_security_upgrade.sql       # v1 → v2 增量升级 (加密/JWT/TOTP/设备指纹)
│   └── 2026-05-17_transfer_double_entry.sql  # v2 → v3 增量升级 (transactions.direction)
├── secure_storage/              # 服务端长期密钥 (0600)
│   ├── kek_v1.bin               # 32B AES-256 KEK (字段加密)
│   ├── server_ecc_private.pem   # P-256 ECDH 私钥 (报文协商)
│   ├── server_ecc_public.pem    # P-256 ECDH 公钥
│   ├── jwt_ecdsa_private.pem    # P-256 ECDSA 私钥 (签 JWT)
│   ├── jwt_ecdsa_public.pem     # P-256 ECDSA 公钥
│   └── audit_hmac.key           # 32B HMAC key (审计链)
├── CRYPTO_DESIGN.md             # 密码学算法详解 (原理/参数/密钥管理)
├── DATABASE.md                  # 数据库部署指南 (建库/重置/备份/字段说明)
├── MANUAL.md                    # 用户操作手册 (功能总览/界面/逐步操作/攻击解读/FAQ)
├── README.md
└── .venv/
```

> 遗留物 `keys/server_private.pem`、`database.db`、`secure_storage/server_{private,public}.pem` 是早期 RSA 方案的残留，可清理。

## 数据库 Schema

库名 `secure_pay_db`，6 张表 (5 张原表 + `user_devices`)：

- **users** — `id PK, username UNI, password_hash, payment_pwd_hash, phone_ciphertext/iv/tag, totp_ciphertext/iv/tag, totp_enabled, signing_pub_key, kek_version, balance DECIMAL(12,2), created_at`
- **transactions** — `id PK, txn_id UNI, user_id FK, amount, receiver, direction ENUM('OUTGOING','INCOMING'), status, risk_score, client_signature, digest_sha256, device_fp, created_at` (转账时发款方和收款方各落一行,前端按 direction 显示 ±)
- **audit_logs** — `id PK, event_type, user_id, severity, description, ip_address, operation_hash CHAR(64), prev_hash CHAR(64), created_at` (哈希链)
- **used_nonces** — `nonce PK, used_at NULL, created_at`
- **user_devices** — `id PK, user_id FK, device_fp, ua_summary, trusted, first_seen, last_seen, UNIQUE(user_id, device_fp)`
- **rate_limit_log** — `id PK, bucket_key, action, created_at` (预留落库审计)

DB 连接配置在 `app.py:DATABASE_CONFIG` (优先读环境变量 `DB_PASSWORD`)。

## API 接口

| 方法 | 路径 | 鉴权 | 说明 |
| --- | --- | --- | --- |
| GET  | `/` | — | 渲染单页 UI |
| GET  | `/api/dashboard` | JWT 可选 (允许 demo) | 余额 / 最近 10 笔交易 / 统计 / 最近 50 条审计日志 |
| GET  | `/api/keys/server` | — | 一次性下发 ECDH 公钥 + JWT 验证公钥 |
| GET  | `/api/get_token` | — | 下发 nonce + ECDH 公钥 (5 min 过期) |
| POST | `/api/register` | — | 注册：用户名 / 登录密码 / 支付密码 / 手机号(可选, AES-GCM 落库) |
| POST | `/api/login` | — | 验证 + (若开 2FA) TOTP → 返回 ES256 JWT |
| POST | `/api/logout` | — | 清 session |
| POST | `/api/totp/setup` | JWT | 返回 base32 secret + otpauth URI |
| POST | `/api/totp/verify` | JWT | 校验 code 后启用 2FA (secret AES-GCM 加密落库) |
| POST | `/api/device/register` | JWT | 登记客户端 ECDSA-P256 长期公钥 + 设备指纹 |
| POST | `/api/pay` | JWT 可选 | 旧版加密支付 (¥38 demo) |
| POST | `/api/transfer` | JWT | 全流程：ECDH+AES-GCM 包裹的 (amount, receiver, 支付密码, TOTP) + 客户端 ECDSA 签名 + 设备指纹 → 服务端 7 重校验后**双账本扣加**(发款方 -amount、收款方 +amount,各写一条 transactions),返还服务端签名 JWT 回执。收款方必须是已注册用户名;余额不足时返回 FAILED 并附带当前余额与所需金额 |
| POST | `/api/topup` | JWT | 银行卡充值:ECDH+AES-GCM 包裹的 (amount, card_number, card_holder, expiry, cvv, 支付密码, TOTP) + 客户端 ECDSA 签名(摘要含 last4 不含完整卡号) → 服务端做 Luhn 算法 + 有效期 + CVV 校验, 通过 6 重凭证校验后 `balance += amount`, 写一条 INCOMING transactions(receiver=`银行卡 ****<last4>`)。**卡号 / CVV / 有效期 零持久化**, 仅审计日志保留 last4 |
| GET  | `/api/admin/logs` | JWT (user_id=1) | 50 条审计日志 |

### `/api/transfer` 请求体

```json
{
  "nonce":              "N + 16hex (来自 get_token)",
  "client_ecc_pub_key": "客户端临时 ECDH-P256 公钥 (PEM/SPKI)",
  "iv":                 "base64(12B AES-GCM IV)",
  "tag":                "base64(16B GCM tag)",
  "payload":            "base64(AES-256-GCM 密文)  明文: {amount, receiver, payment_password, totp_code}",
  "client_signature":   "base64(ECDSA-P256/SHA-256 over transaction_digest, DER)",
  "device_fp":          "<sha256 hex (浏览器侧 UA+canvas+屏幕+时区)>"
}
```

### 服务端 7 重校验顺序

1. JWT(ES256) 解码 → user_id
2. Rate-limit (IP+用户, token bucket)
3. Nonce 一次性消费 (`SELECT ... FOR UPDATE`)
4. ECDH 协商 + HKDF + AES-GCM 解密 (失败即拦截 MITM/篡改)
5. 收款方存在性 + 禁止自我转账; 支付密码 PBKDF2 hash 校验 + (若启用) TOTP 校验
6. 设备指纹必须在 `user_devices.trusted=1` 范围内
7. 用 `users.signing_pub_key` 验证客户端 ECDSA 签名 (抗抵赖)

通过全部 7 重 → **按 id 升序加锁双方** → 发款方 `-amount`、收款方 `+amount` → 写两条 `transactions` (`OUTGOING` + `INCOMING`,后者 txn_id 加 `-R` 后缀) → 写审计哈希链 → 服务端签发 ES256 JWT 回执。

## 快速启动

前置:MySQL 已起在 `localhost:3306`,密码 `lxb12138`(或环境变量 `DB_PASSWORD`)。

**全新机器**(从零建库):
```bash
cd /root/payment_system
mysql -uroot -p < migrations/init_schema.sql      # 建 secure_pay_db + 6 张表 (幂等)
.venv/bin/python app.py
```

**旧库升级**(已有 4 张表的早期版本):
```bash
mysql -uroot -p secure_pay_db < migrations/2026-05-14_security_upgrade.sql
.venv/bin/python app.py
```

> 数据库的详细部署 / 重置 / 备份 / 字段说明见 [`DATABASE.md`](./DATABASE.md)。

浏览器打开 [http://127.0.0.1:5000](http://127.0.0.1:5000)。未登录会进入登录/注册页；首次注册需填用户名 / 登录密码(≥8位) / 支付密码(≥6位) / 手机号(可选)。

**端口被占？**

```bash
fuser -k 5000/tcp        # 或 lsof -ti:5000 | xargs -r kill
```

## 安全特性矩阵

| 威胁 | 措施 |
| --- | --- |
| MITM / 嗅探 | 应用层 ECDH-P256 + AES-256-GCM(AEAD)；HSTS / nosniff / DENY / CSP 响应头 |
| 重放 | `used_nonces` 一次性 + `SELECT FOR UPDATE` |
| 拖库 | 登录/支付密码 PBKDF2-SHA256；手机号 / TOTP secret AES-GCM 字段级加密 (KEK 文件外保管) |
| 撞库 / 暴破 | PBKDF2(60 万轮) + Rate-limit (login 10/min, register 5/min, transfer 10/min, pay 20/min) |
| Cookie 劫持 | 主要鉴权改为 ES256 JWT (Authorization Bearer) |
| 单因子被绕过 | 支付密码 + TOTP RFC 6238 + 客户端 ECDSA 签名 + 设备指纹 (4 因子) |
| 否认交易 | 客户端长期 ECDSA 私钥签名落库 (`transactions.client_signature`)；服务端回执也带 ES256 |
| 篡改审计 | `audit_logs.operation_hash = HMAC-SHA256(prev_hash ‖ payload)` 哈希链 |
| 并发超卖 | 扣款前 `SELECT ... FOR UPDATE` |
| 越权 | `auth_required(allow_demo)` 装饰器；admin 接口要 user_id=1 (演示用) |

⚠️ 仍未做、生产前必须补：HTTPS 终结、HSM/KMS 托管密钥、JWT 黑名单/refresh token、地理风险评分、Passkey/WebAuthn 替代 localStorage 私钥。

## 已知遗留物

- `keys/server_private.pem`（空）、`database.db`（空 SQLite 残留）、`secure_storage/server_{private,public}.pem`（旧 RSA 方案密钥）—— 都可删除，保留不影响运行。

## 变更历史

- **2026-05-13** — 修复前端加密协议不匹配：`templates/index.html` 原用 RSA-OAEP + AES-CBC，与后端 ECDH + AES-GCM 不兼容，导致 `/api/pay` 永久失败。改写 `encryptPaymentPayload` 使用 Web Crypto 的 ECDH(P-256) → HKDF-SHA256 → AES-256-GCM，并按 `client_ecc_pub_key/iv/tag/payload` 协议字段发送。
- **2026-05-14** — 完整移动支付安全体系升级：新增 `crypto_utils.py` 密码学工具层、`migrations/2026-05-14_security_upgrade.sql` schema 升级 (users/transactions/audit_logs 增列, 新建 user_devices/rate_limit_log)；后端引入 ECDSA-P256(ES256) JWT、独立支付密码、TOTP(RFC 6238) 2FA、字段级 AES-GCM 加密 (KEK)、客户端 ECDSA-P256 抗抵赖签名、设备指纹绑定、内存 token-bucket Rate-limit、安全响应头 (HSTS/CSP/nosniff/DENY)、HMAC-SHA256 审计哈希链、`/api/transfer` 7 重校验；前端重写 `index.html` 加入登录/注册/2FA绑定/转账/安全中心五个页面与本机长期签名密钥对(localStorage)；新增 `CRYPTO_DESIGN.md` 详细论述各算法的工作原理、参数与密钥管理。
- **2026-05-17** — 新增 `migrations/init_schema.sql` 从零建库一键脚本(幂等,使用 `CREATE TABLE IF NOT EXISTS` 不破坏已有数据)、新增 `DATABASE.md` 数据库部署指南(覆盖建库/字段说明/重置/备份/FAQ);README 把"快速启动"拆成"新机器从零"与"旧库升级"两条路径。
- **2026-05-17** — 转账改造为双账本:`transactions` 加 `direction` ENUM('OUTGOING','INCOMING') 字段(`migrations/2026-05-17_transfer_double_entry.sql` 幂等迁移),`/api/transfer` 现在校验收款方必须是已注册用户、禁止向自己转账、按 id 升序加锁双方避死锁、发款方-amount/收款方+amount 同一事务内完成、各写一条 transactions(收款方那条 txn_id 衍生为 `<txn_id>-R`);余额不足返回的 FAILED 消息含当前余额与所需金额。前端 `apiPost` 把 `FAILED` 视为业务错误抛出(保留 `TOTP_REQUIRED` 例外),手机端转账失败/超额提示终于可见;`renderTransactions` 按 `direction` 用 `-¥`(灰) / `+¥`(绿) 分色显示,收款流水显示"来自 <对方>"。`init_schema.sql` 同步加上 direction 列。
- **2026-05-17** — 新增 `/api/topup` 银行卡充值能力:服务端 Luhn(MOD-10) + 有效期 + CVV 格式校验 + 单笔 5 万上限,通过整套安全管线(ECDH+AES-GCM+Nonce+支付密码+TOTP+ECDSA客户端签名+设备指纹)入账;**卡号/CVV/有效期零持久化**,只把 `银行卡 ****<last4>` 写入 transactions 与审计日志,完整卡号永不出现在数据库/日志/响应中。前端首页"充值"按钮启用(替原 2FA 入口),2FA 入口移到安全中心;新增 page-topup 含卡号自动空格分组、有效期自动补斜杠、本地 Luhn 即时校验。
- **2026-05-17** — 新增 `MANUAL.md` 用户操作手册:覆盖功能模块总览、界面布局、5 分钟快速上手、注册/登录/2FA/转账/充值/支付/安全中心 8 类操作的逐步流程、管理后台与审计日志阅读指南、8 类典型攻击的日志解读、故障排查 FAQ。面向"演示者/使用者/课程评审"读者,与 README(开发者)/DATABASE(DBA)/CRYPTO_DESIGN(算法层) 分工。
- **2026-05-18** — 修复"支付按钮卡在'加密信道协商中'"`templates/index.html`:根因是 JWT 30 分钟过期后,前端 localStorage 仍带旧 token 请求 `/api/pay`,服务端返回 401;原 `handleSecurePay` 的 catch 只弹 alert 没还原按钮文字/样式,造成视觉卡死。新增 `handleUnauthorized()` 工具方法,`apiGet`/`apiPost` 收到 401 时自动 `clearAuth()` 并 `switchPage('page-auth')`,抛出"登录已失效,请重新登录"统一文案;`handleSecurePay` 的 catch 补齐 `btn.innerHTML = original` + 移除 `opacity-75/cursor-not-allowed`,与 `handleTransfer`/`handleTopup` 已有的还原逻辑保持一致。未改后端、未改 JWT 有效期。
=======
# crypto_payment_system