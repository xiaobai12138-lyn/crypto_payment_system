# 移动支付安全体系 — 密码学算法应用说明

> 本文档配套 `/root/payment_system/`，说明该项目用到的全部密码学原语：算法工作原理、参数选择、密钥生成与管理，以及它们如何串成端到端的"用户注册 → 登录 → 交易发起 → 数据传输 → 服务端处理"流程。

## 0. 安全目标与威胁模型

| 威胁类别 | 典型场景 | 本系统的应对 |
| --- | --- | --- |
| 网络攻击 | 中间人嗅探、篡改、重放 | TLS *(部署层)* + 应用层 ECDH-P256 协商 + AES-256-GCM(AEAD) + Nonce 一次性 |
| 数据泄露 | 数据库被拖、备份外泄 | 登录密码 PBKDF2-SHA256 单向 hash；手机号 / TOTP secret 字段级 AES-256-GCM 加密(KEK 在文件系统外保管，0600) |
| 身份冒用 | 撞库、Cookie 劫持、设备克隆、否认交易 | 独立支付密码 + TOTP(RFC 6238) 二次验证 + ECDSA-P256 签发 JWT(ES256) + 客户端长期 ECDSA-P256 签名抗抵赖 + 设备指纹绑定 |
| 内部审计 | 篡改审计日志 | 每条审计日志写入 `HMAC-SHA256(prev_hash ‖ payload)`，构成哈希链；任何一行被改后续全断 |

整套系统刻意采用 **多算法、多通道** 设计：传输保密(AEAD) ↔ 身份认证(JWT) ↔ 抗抵赖签名(ECDSA) ↔ 二次验证(TOTP) 分别用不同密钥，互不复用，单点泄露不致整体崩盘。

---

## 1. ECDH-P256 — 一次性会话密钥协商

### 1.1 工作原理

椭圆曲线 Diffie-Hellman 在曲线 `secp256r1 (NIST P-256)` 上工作：

- 曲线：`y² = x³ - 3x + b (mod p)`，其中 `p = 2²⁵⁶ - 2²²⁴ + 2¹⁹² + 2⁹⁶ - 1`，基点 `G` 阶 `n ≈ 2²⁵⁶`。
- 客户端选随机 `d_c ∈ [1, n-1]`，公钥 `Q_c = d_c · G`；服务端同理 `d_s, Q_s`。
- 双方算 `K = d_c · Q_s = d_s · Q_c`，取 `K.x`(32 字节) 作为共享秘密。
- 安全性依赖 ECDLP：已知 `Q, G` 求 `d` 在 P-256 上需 ~2¹²⁸ 次群运算。

### 1.2 参数与本项目实现

| 项 | 取值 | 出处 |
| --- | --- | --- |
| 曲线 | P-256 | `crypto_utils.py` / 前端 `crypto.subtle.generateKey({namedCurve:'P-256'})` |
| 公钥编码 | SubjectPublicKeyInfo (SPKI) PEM | `serialization.PublicFormat.SubjectPublicKeyInfo` |
| 服务端长期 ECDH 私钥 | `secure_storage/server_ecc_private.pem`，启动时自动生成 | `app.py:load_server_ecc_key` |
| 客户端密钥生命周期 | **一次性** — 每笔交易由 `crypto.subtle.generateKey` 重新生成 | `templates/index.html:encryptPaymentPayload` |

### 1.3 密钥管理

- 服务端 ECDH 私钥落地 `secure_storage/server_ecc_private.pem`，权限 0600；轮换策略：替换文件即可，旧密文交易已经解密入库不受影响。
- 客户端私钥**不落地**，仅存在内存里直到 `deriveBits` 完毕后随页面 GC 释放，最小化暴露面。
- ECDH 不直接做对称密钥(出于"原始 DH 共享秘密分布不均匀"的考虑) — 必须经 HKDF 拉伸(§3)。

---

## 2. AES-256-GCM — 报文 AEAD 加密

### 2.1 工作原理

AES (Rijndael) 的 256 位密钥版本：14 轮 SubBytes/ShiftRows/MixColumns/AddRoundKey。本系统用 GCM 模式 (Galois/Counter Mode)：

- **C** = AES-CTR(K, IV‖counter, P)
- **T** = GHASH(H, AAD, C) ⊕ AES_K(IV‖0x00000001)，其中 `H = AES_K(0¹²⁸)`
- 输出 `(C, T)`；解密时若 T 不匹配则抛 `InvalidTag`。

GCM 同时提供**保密性(IND-CPA)** 与**完整性(INT-CTXT)**，篡改任何字节都会导致 tag 不通过。

### 2.2 参数

| 项 | 取值 | 说明 |
| --- | --- | --- |
| 密钥长度 | 256 bit | 由 §3 HKDF 输出 |
| IV 长度 | 12 字节 (96 bit) | GCM 推荐值；每次随机生成、严禁重用 |
| Tag 长度 | 16 字节 (128 bit) | 最高强度档 |
| AAD | 当次 `nonce` | 把 nonce 钉进 GCM 校验范围，篡改 nonce 也会失败 |
| IV 唯一性策略 | `crypto.getRandomValues(12)` 每报文新值 + nonce 一次性 | 双重保证 |

### 2.3 在两个流程中的不同载荷

- **支付报文加密** (`/api/pay`, `/api/transfer`)：明文为 `{amount, receiver, [payment_password], [totp_code]}` 的 JSON UTF-8。
- **字段级加密** (`crypto_utils.encrypt_field`)：用 **KEK** 加密手机号 / TOTP secret 入库，AAD 绑定 `username`，防止"密文挪用攻击"(把 A 的密文拷给 B 那一行)。

### 2.4 密钥管理

| 密钥 | 来源 | 存储 | 轮换 |
| --- | --- | --- | --- |
| 会话密钥 (报文加密) | HKDF 派生，每次新生成 | 仅内存 | 自动一次性 |
| KEK (字段加密) | `secret_token_bytes(32)` 初次启动生成 | `secure_storage/kek_v1.bin`，权限 0600 | 表 `users.kek_version` 预留版本号，未来可读旧密文+用旧 KEK 解密+用新 KEK 重写 |

---

## 3. HKDF-SHA256 — 密钥派生

### 3.1 工作原理 (RFC 5869)

```
PRK = HMAC-SHA256(salt, ikm)         # extract
OKM = T(1) ‖ T(2) ‖ ...               # expand
T(i) = HMAC-SHA256(PRK, T(i-1) ‖ info ‖ byte(i))
```

把"分布不均的 ikm" 压缩成"均匀分布的 PRK"，再展开成所需长度，输出与随机串不可区分。

### 3.2 本项目参数

| 字段 | 值 | 备注 |
| --- | --- | --- |
| `ikm` | ECDH 共享秘密 `K.x` (32 字节) | §1 结果 |
| `salt` | 当次 `nonce` 的 UTF-8 字节 | 保证不同交易派生出不同密钥 |
| `info` | `b"secure-pay-ecc-v1"` | 协议版本绑定，未来升级不冲突 |
| 输出 | 32 字节 → AES-256 密钥 | 一一对应 |

### 3.3 密钥管理

无独立"HKDF 密钥"，PRK 只活在调用栈一次性变量中；只要 `ikm/salt/info` 不被攻击者完全控制，输出就安全。

---

## 4. ECDSA-P256 / ES256 — JWT 与抗抵赖签名

### 4.1 工作原理

ECDSA 在 P-256 上：

- 私钥 `d`、公钥 `Q = d·G`。签消息 `m`：
  - `e = SHA-256(m)`，取前 256 bit
  - 随机 `k`，`(x₁,_) = k·G`，`r = x₁ mod n`
  - `s = k⁻¹(e + d·r) mod n`，签名 `(r, s)`(DER 编码 ~70 字节)
- 验签：`u₁ = e·s⁻¹, u₂ = r·s⁻¹`，`(x',_) = u₁·G + u₂·Q`，`r ≡ x' mod n` 则通过。

> 本系统采用 `pyca/cryptography` 与 Web Crypto，两端均默认使用**确定性或安全随机** `k`，避免 PS3-Sony 那种 k 复用导致的私钥泄露。

### 4.2 两个独立用途

| 用途 | 密钥 | 签什么 | 谁验证 |
| --- | --- | --- | --- |
| **服务端 JWT (ES256)** | `secure_storage/jwt_ecdsa_private.pem` | JWT header+payload | 任意 API（也可下发公钥让外部系统验证），保证 token 不可伪造 |
| **客户端交易抗抵赖** | 浏览器端 ECDSA-P256，导出 JWK 存 localStorage(demo) | `SHA-256("v1|user_id||amount|receiver|nonce|device_fp")` | 服务端用用户预先登记的 `signing_pub_key` 验签，事后用户无法否认 |

### 4.3 JWT (ES256) 详细参数

```json
header  : { "alg": "ES256", "typ": "JWT" }
payload : { "iss":"secure-pay", "sub":"<user_id>", "iat":..., "nbf":...,
            "exp": iat+1800, "jti":"<uuid>", "name":"<username>" }
```

- `alg=ES256` ⇒ ECDSA-P256 + SHA-256；签名为 `BASE64URL(r ‖ s)` (64 字节)。
- `exp` 强制 30 分钟，`jti` 唯一 (后续可接黑名单实现"主动登出 JWT")。
- 服务端要求 `Authorization: Bearer <jwt>`，在 `auth_required` 装饰器里调用 `jwt_verify`。

### 4.4 客户端长期签名密钥的管理

- **生成**：首次进入页面时 `crypto.subtle.generateKey({name:'ECDSA', namedCurve:'P-256'}, true, ['sign','verify'])`。
- **持久化**：导出为 JWK，base64 后写 `localStorage.secpay.signing.jwk`；**仅供 demo**，生产应改用 IndexedDB 储存非可导出的 CryptoKey 对象。
- **登记**：通过 `/api/device/register` 把 SPKI/PEM 公钥与设备指纹一起绑定到 `users.signing_pub_key`。
- **轮换**：清掉 localStorage 即可触发重新生成；服务端在 `signing_pub_key` 改变时应发邮件/短信告警(本项目仅落审计日志 `DEVICE_BIND`)。
- **抗抵赖意义**：服务端只持有公钥，无法伪造用户签名；用户事后否认"我没下单"时可出示 `transactions.client_signature` + `digest_sha256` 给第三方校验。

### 4.5 摘要规范化

服务端 `transaction_digest` 与前端 `signTransactionDigest` 用同一字符串拼法：

```
"v1" | str(user_id) | ""  | amount(规整为 'X.XX') | receiver | nonce | device_fp
        └─ "" 是预留位，留给未来加 txn_id 时无需破坏旧客户端
```

变更任一字段都会让签名失效；选择"字符串规范化 + SHA-256"而不是直接签 JSON，是因为 JSON 在不同实现下空白、键顺序不一致，会导致签名不可复现。

---

## 5. HMAC-SHA256 — 审计哈希链 & 请求级 MAC

### 5.1 工作原理

```
HMAC_K(m) = SHA256( (K ⊕ opad) ‖ SHA256( (K ⊕ ipad) ‖ m ) )
```

PRF 与 MAC，存在性可证安全；抗长度扩展。

### 5.2 用法

- **审计哈希链** (`crypto_utils.audit_chain_hash`)：每条 `audit_log` 写库前查"上一条" `operation_hash`，再算 `H = HMAC_K(prev_hash | event_type | user_id | desc | ip | ts)` 一并写入 `audit_logs.operation_hash`。
  - 由于 K 只在服务端，攻击者即便能改库也无法重算正确 H ⇒ 任一行被改动，后续链断；离线巡检脚本能秒级定位。
- **请求级 MAC 工具** (`canonical_request_bytes`)：预留给将来对内部服务-服务调用做 HMAC 签名头，公开 API 未启用。

### 5.3 密钥管理

`secure_storage/audit_hmac.key`，启动时一次性生成 32 字节随机 → 0600；轮换会让"过去链"无法验证(需要把旧 hash 链也重算)，因此实操中是**只生成一次，永不轮换**，必要时整库重置。

---

## 6. PBKDF2-SHA256 — 口令哈希

### 6.1 工作原理

```
DK = T_1 ‖ T_2 ‖ ... ‖ T_l
T_i = U_1 ⊕ U_2 ⊕ ... ⊕ U_c
U_1 = HMAC_pwd(salt ‖ i),  U_j = HMAC_pwd(U_{j-1})
```

通过 `c` 次重复迭代，让单次哈希耗时显著增加 → 减缓暴力撞库。

### 6.2 参数

`werkzeug.security.generate_password_hash` 默认用 `pbkdf2:sha256:600000` (60 万轮)、16 字节随机 salt，输出 hash 形如 `pbkdf2:sha256:600000$<salt>$<hex>`。

- 登录密码 hash：列 `users.password_hash`
- **支付密码 hash**：列 `users.payment_pwd_hash`，与登录密码**独立** — 即便登录会话被劫，发起转账仍要再输支付密码。

### 6.3 密钥管理

无独立密钥；salt 随机内嵌；迭代次数升级策略：登录成功且仍用旧轮数时，可静默升级为新轮数 hash(本项目未实现)。

---

## 7. TOTP / HOTP — 二次验证

### 7.1 工作原理 (RFC 6238 / RFC 4226)

```
T = floor((time_now - T0) / X)         # X = 30s, T0 = 0
HOTP(K, T) = truncate( HMAC-SHA1(K, T) ) mod 10^6
```

`K` 是用户专属的 base32 secret(160 bit)，输出 6 位十进制码。服务端允许 ±1 个时间窗口的偏差 (`valid_window=1`)，应对时钟漂移。

### 7.2 参数与绑定流程

| 项 | 取值 |
| --- | --- |
| 算法 | HOTP based on HMAC-SHA1 |
| Secret 长度 | 160 bit base32 |
| 步长 | 30 秒 |
| 数字位数 | 6 |
| 容忍窗口 | ±30 秒 |

绑定：`/api/totp/setup` 生成 secret 并写入 session(`pending_totp_secret`)、返回 `otpauth://totp/SecurePay:<username>?secret=...` URI；用户在 Authenticator 中扫描后输入 6 位 code，命中 `/api/totp/verify` 才把 secret 写入 `users.totp_*`(经 §2 KEK 加密) 并置 `totp_enabled=1`。

### 7.3 密钥管理

- secret 永不出现在响应里(除首次设置)；落库时以 AES-256-GCM 字段加密，AAD 绑定 username。
- 用户重置 2FA 时应让其重新发起 `setup` 流程 — 旧 secret 直接覆盖。
- 服务端时钟必须与可信 NTP 同步，否则会拒掉合法 code。

---

## 8. SHA-256 与设备指纹

`hashlib.sha256` 在系统中无独立"密钥"，但出现在多处：

- 交易摘要规范化
- 设备指纹熵源(UA + 语言 + 屏幕 + 时区 + canvas) → 一次哈希 → 64 hex 入库
- 审计哈希链 (经 HMAC 包裹)
- 操作日志的原始 `operation_hash`

P-256 + SHA-256 是 NSA Suite B 推荐的"配套"：曲线 256 bit ↔ 哈希 256 bit ↔ AES-256，整体在同一安全等级 (128-bit 安全余量)。

---

## 9. 端到端流程串讲

```
┌─────────────────────────── 用户注册 ───────────────────────────┐
│ register {username, password, payment_password, phone}        │
│   ├ password         → PBKDF2-SHA256(c=600k, 16B salt)          │
│   ├ payment_password → PBKDF2-SHA256                            │
│   └ phone            → AES-256-GCM(KEK, AAD=username) → 入库     │
└────────────────────────────────────────────────────────────────┘
┌─────────────────────────── 登录 ───────────────────────────────┐
│ login {username, password} → 验证 hash                          │
│   ├ 若 totp_enabled=1 ⇒ 解密 secret(KEK) → TOTP.verify(code)    │
│   └ 通过 → 服务端 ECDSA-P256 签发 ES256 JWT (exp=30min)         │
│ 客户端首登录 → 生成 ECDSA-P256 长期密钥对(本机)                 │
│              → /api/device/register 登记公钥 + device_fp(指纹) │
└────────────────────────────────────────────────────────────────┘
┌─────────────────────────── 交易发起 ───────────────────────────┐
│ GET /api/get_token → 服务端发 nonce(一次性) + ECDH 公钥          │
│ 客户端：                                                         │
│   ├ 生成临时 ECDH 密钥 → 协商 K.x                                │
│   ├ HKDF-SHA256(salt=nonce, info='secure-pay-ecc-v1') → AES key │
│   ├ AES-256-GCM(IV=12B, AAD=nonce) 加密 JSON(amount,...)         │
│   └ ECDSA-P256(SHA-256) 对 transaction_digest 签名 (用长期私钥) │
└────────────────────────────────────────────────────────────────┘
┌─────────────────────────── 数据传输 ───────────────────────────┐
│ POST /api/transfer Authorization: Bearer <JWT>                  │
│ Body: {nonce, client_ecc_pub_key, iv, tag, payload,              │
│        client_signature, device_fp}                              │
│ TLS 在传输层保护；应用层 GCM 提供端到端机密性+完整性               │
└────────────────────────────────────────────────────────────────┘
┌─────────────────────────── 服务端处理 ─────────────────────────┐
│ 1) jwt_verify(JWT) → user_id (ES256 公钥验签)                   │
│ 2) Rate-limit (IP+user, token bucket)                            │
│ 3) Nonce → SELECT ... FOR UPDATE → 标记 used (防重放)            │
│ 4) ECDH 协商出同样 K → HKDF → AES-GCM decrypt_and_verify         │
│ 5) 校验 payment_pwd hash + (可选) TOTP                          │
│ 6) 校验 device_fp ∈ trusted user_devices                         │
│ 7) ECDSA 公钥验签 client_signature (抗抵赖)                      │
│ 8) 余额加锁扣款 + 写 transactions(签名/摘要/指纹)               │
│ 9) audit_log → HMAC-SHA256 哈希链                                │
│ 10) 服务端再签发一份 ES256 JWT 作交易回执                        │
└────────────────────────────────────────────────────────────────┘
```

---

## 10. 密钥清单（速查）

| 文件 / 列 | 内容 | 用途 | 谁可看 |
| --- | --- | --- | --- |
| `secure_storage/kek_v1.bin` | 32B 随机 (AES-256 KEK) | 字段加密 | 仅服务端 |
| `secure_storage/server_ecc_private.pem` | P-256 ECDH 私钥 | 报文加密协商 | 仅服务端 |
| `secure_storage/server_ecc_public.pem`  | P-256 ECDH 公钥 | 下发给客户端 | 公开 |
| `secure_storage/jwt_ecdsa_private.pem` | P-256 ECDSA 私钥 | 签发 JWT | 仅服务端 |
| `secure_storage/jwt_ecdsa_public.pem`  | P-256 ECDSA 公钥 | 验证 JWT(可对外公布) | 公开 |
| `secure_storage/audit_hmac.key` | 32B 随机 HMAC 密钥 | 审计哈希链 | 仅服务端 |
| `users.password_hash` | PBKDF2 摘要 | 登录密码 | DBA |
| `users.payment_pwd_hash` | PBKDF2 摘要 | 支付密码 | DBA |
| `users.phone_ciphertext/iv/tag` | AES-256-GCM 密文 | 手机号 | DBA(看到密文，无法解密) |
| `users.totp_ciphertext/iv/tag` | AES-256-GCM 密文 | TOTP secret | DBA |
| `users.signing_pub_key` | PEM | 客户端长期签名公钥 | 公开 |
| `localStorage.secpay.signing.jwk` (浏览器) | ECDSA 长期密钥对 | 交易签名 | 仅本机 |

> **DBA 拖库场景**：拿到 DB 不能解密手机号 / TOTP（需要 KEK 文件），不能伪造 JWT（需要 JWT 私钥），不能伪造交易（需要用户浏览器的私钥）。**只有把服务器与该用户浏览器一同拿下，才能完全冒名**。

---

## 11. 未实施但推荐的强化

1. **HSM / KMS** 托管 KEK 与 JWT 私钥（当前是文件 0600）。
2. **JWT 刷新机制**：access token 15 min + refresh token 7 day，且 refresh token 单设备绑定。
3. **Webauthn / Passkey** 替代 TOTP 与 localStorage 私钥，私钥真正离用户进入安全芯片。
4. **风险评分**：把 device_fp 异常、地理跳变、金额突增接入 `transactions.risk_score`，触发短信复核。
5. **审计签名上链**：把每天结束的哈希链根 (`H_last`) 公示或上 Merkle 树，做法律证据级抗抵赖。
6. **后量子迁移**：把 ECDH/ECDSA 换 Kyber/Dilithium 作为长期路线。
