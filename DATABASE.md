# 数据库部署指南

如果你拿到这份代码、想在自己的机器上**从零**建出与开发环境完全一致的 `secure_pay_db`,跟着这份文档走即可。本文覆盖:建库、表结构详解、应用密码学密钥的初始化、验证、重置、备份。

> 一键脚本: [`migrations/init_schema.sql`](./migrations/init_schema.sql)(幂等、不破坏已有数据)。
> 表与字段背后的算法解释看 [`CRYPTO_DESIGN.md`](./CRYPTO_DESIGN.md)。

---

## 1. 前置条件

| 项 | 要求 |
| --- | --- |
| MySQL | 8.0 或更高 |
| 字符集 | `utf8mb4` |
| 排序规则 | `utf8mb4_unicode_ci`(本项目统一使用) |
| 权限 | 拥有 `CREATE`、`ALTER`、`INDEX`、`REFERENCES`、`INSERT`、`UPDATE`、`DELETE`、`SELECT` |
| 引擎 | 默认 InnoDB(本项目必需,外键 + 行锁要用) |

确认版本:
```bash
mysql -uroot -p -e "SELECT VERSION();"
```

---

## 2. 一键建库(推荐)

```bash
cd /root/payment_system
mysql -uroot -p < migrations/init_schema.sql
```

脚本会:

1. `CREATE DATABASE IF NOT EXISTS secure_pay_db` (utf8mb4 / utf8mb4_unicode_ci)
2. `USE secure_pay_db`
3. 依次 `CREATE TABLE IF NOT EXISTS` 出 **6 张表** —— `users`、`transactions`、`audit_logs`、`used_nonces`、`user_devices`、`rate_limit_log`
4. 最后输出 `secure_pay_db init complete`

整个脚本**只用 `IF NOT EXISTS`,不会删除任何已存在的表**,可放心重复执行。

> 如果你已经按旧版本(只有 4 张表的 v1/v2 schema)建过库、想升级到当前版本,**不要**用 `init_schema.sql`,改跑增量迁移:`mysql -u… secure_pay_db < migrations/2026-05-14_security_upgrade.sql`,它用存储过程实现 "ADD COLUMN IF NOT EXISTS"。

---

## 3. 表结构一览

```
secure_pay_db
├── users           账户主表(11 个安全相关列)
├── transactions    交易流水(含客户端 ECDSA 签名)
├── audit_logs      审计日志(HMAC-SHA256 哈希链)
├── used_nonces     防重放 Nonce 一次性池
├── user_devices    受信设备指纹白名单
└── rate_limit_log  频次审计落库(在线限流走内存桶,此表保留供离线分析)
```

### 3.1 `users` —— 账户主表

| 字段 | 类型 | 默认/约束 | 用途 |
| --- | --- | --- | --- |
| `id`               | INT AI         | PK                  | 用户主键 |
| `username`         | VARCHAR(80)    | UNIQUE, NOT NULL    | 登录名 |
| `password_hash`    | VARCHAR(255)   | NOT NULL            | **登录密码** PBKDF2-SHA256 摘要(`werkzeug.security`,60 万轮 + 16B salt) |
| `payment_pwd_hash` | VARCHAR(255)   | NULL                | **支付密码** PBKDF2 摘要(独立于登录密码) |
| `balance`          | DECIMAL(12,2)  | DEFAULT 0.00        | 账户余额。扣款时配合 `SELECT ... FOR UPDATE` 防并发超卖 |
| `phone_ciphertext` | VARBINARY(255) | NULL                | 手机号 **AES-256-GCM 密文** |
| `phone_iv`         | VARBINARY(12)  | NULL                | GCM IV(12B) |
| `phone_tag`        | VARBINARY(16)  | NULL                | GCM 认证 tag(16B) |
| `totp_ciphertext`  | VARBINARY(255) | NULL                | **TOTP secret** 的 AES-256-GCM 密文(AAD=username) |
| `totp_iv`          | VARBINARY(12)  | NULL                | TOTP GCM IV |
| `totp_tag`         | VARBINARY(16)  | NULL                | TOTP GCM tag |
| `totp_enabled`     | TINYINT(1)     | DEFAULT 0           | 是否启用 2FA |
| `signing_pub_key`  | TEXT           | NULL                | 客户端**长期 ECDSA-P256 公钥**(PEM/SPKI),用于交易抗抵赖验签 |
| `kek_version`      | INT            | DEFAULT 1           | 字段加密用的 KEK 版本号,留作密钥轮换 |
| `created_at`       | TIMESTAMP      | DEFAULT NOW         | 注册时间 |

**为什么手机号要加密?** 手机号是高价值 PII,即便拖库,攻击者拿到的只是密文,需要同时拿到磁盘上的 `secure_storage/kek_v1.bin` 才能解密。

**为什么 TOTP secret 要加密?** secret 本身就是"凭证",任何人拿到就能算出验证码。`AAD=username` 防止"密文挪用攻击" —— 把 A 的密文拷给 B 那一行不会解密成功。

### 3.2 `transactions` —— 交易流水

| 字段 | 类型 | 用途 |
| --- | --- | --- |
| `id`               | INT AI PK            | |
| `txn_id`           | VARCHAR(64) UNIQUE   | `TXN` + 12 hex。**收款方那条用衍生 `<txn_id>-R`**,保证全表唯一 |
| `user_id`          | INT FK → users(id)   | 本行所属的用户(发款方 / 收款方各一行,各自看到自己的视角) |
| `amount`           | DECIMAL(12,2)        | 正数;前端按 direction 决定显示 `-` 还是 `+` |
| `receiver`         | VARCHAR(255)         | 字段名沿用旧 schema;**语义=对方姓名**:发款方那行填收款方,收款方那行填发款方 |
| `direction`        | ENUM('OUTGOING','INCOMING') NOT NULL | `OUTGOING`=发款方视角,`INCOMING`=收款方视角 |
| `status`           | VARCHAR(32)          | `SUCCESS`/`FAILED`/… |
| `risk_score`       | INT DEFAULT 0        | 预留风险评分位 |
| `client_signature` | VARBINARY(96)        | 客户端 **ECDSA-P256 DER** 签名(仅 OUTGOING 行有,收款方那行为 NULL) |
| `digest_sha256`    | CHAR(64)             | 被签消息的 SHA-256 摘要 hex |
| `device_fp`        | CHAR(64)             | 发起设备指纹(同上,只 OUTGOING 有) |
| `created_at`       | TIMESTAMP            | |

**双账本写入逻辑(`/api/transfer`):**

```text
事务内 (按 user id 升序加锁防死锁):
  UPDATE users SET balance = balance - amount WHERE id = sender_id
  UPDATE users SET balance = balance + amount WHERE id = receiver_id
  INSERT transactions (..., direction='OUTGOING', txn_id='TXN…')        -- 发款方视角
  INSERT transactions (..., direction='INCOMING', txn_id='TXN…-R')      -- 收款方视角
```

**银行卡充值的单边账本(`/api/topup`):**

```text
事务内:
  UPDATE users SET balance = balance + amount WHERE id = user_id
  INSERT transactions (..., direction='INCOMING',
                       receiver='银行卡 ****<last4>',
                       txn_id='TOP…',
                       client_signature/digest/device_fp 全部保留)
```

充值没有"对方用户"概念,只写一条 INCOMING。`receiver` 字段存掩码字符串,**完整卡号、CVV、有效期不入任何表/索引/日志/审计/响应**,服务端校验完即丢。

发款方和收款方各从 `WHERE user_id = ?` 取出自己的视角,前端按 `direction` 决定显示 `-¥` (红/灰) 或 `+¥` (绿)。

**为什么要把签名和摘要落库?** 用户事后否认"我没发起这笔",可拿出 `client_signature` 配合 `users.signing_pub_key` 由第三方验证;由于私钥只在用户浏览器,客户无法抵赖。收款方那条不携带签名,因为它不是用户主动发起的动作。

### 3.3 `audit_logs` —— 审计日志(哈希链)

| 字段 | 类型 | 用途 |
| --- | --- | --- |
| `id`             | INT AI PK    | |
| `event_type`     | VARCHAR(64)  | `USER_REGISTER`/`LOGIN_SUCCESS`/`REPLAY_ATTACK`/… |
| `user_id`        | INT NULL     | 涉及的用户(可空) |
| `severity`       | VARCHAR(32)  | `INFO`/`WARN`/`CRITICAL` |
| `description`    | TEXT         | 人读消息 |
| `ip_address`     | VARCHAR(45)  | 支持 IPv6 |
| `operation_hash` | CHAR(64)     | 本行 `HMAC-SHA256(prev_hash ‖ payload)`,hex |
| `prev_hash`      | CHAR(64) NULL| 上一条 `operation_hash`,首行为 NULL |
| `created_at`     | TIMESTAMP    | |

**哈希链的意义:** HMAC 密钥(`secure_storage/audit_hmac.key`)只在应用服务器上,DBA 拖库后即使能 UPDATE 也无法重算正确的 `operation_hash`,任一行被改动后续整链都对不上,巡检脚本能秒级定位篡改位置。

### 3.4 `used_nonces` —— 防重放 Nonce

| 字段 | 类型 | 用途 |
| --- | --- | --- |
| `nonce`      | VARCHAR(64) PK    | `N` + 16 hex |
| `used_at`    | TIMESTAMP NULL    | NULL = 已发未用; 非 NULL = 已消费 |
| `created_at` | TIMESTAMP         | |

**用法:** `/api/get_token` 时插入(NULL);`/api/pay`、`/api/transfer` 时 `SELECT ... FOR UPDATE`,若 `used_at IS NOT NULL` 即认定重放并拒绝。

### 3.5 `user_devices` —— 受信设备

| 字段 | 类型 | 用途 |
| --- | --- | --- |
| `id`         | INT AI PK                          | |
| `user_id`    | INT FK → users (ON DELETE CASCADE) | |
| `device_fp`  | CHAR(64)                           | SHA-256(UA + canvas + 屏幕 + 时区 + 语言) hex |
| `ua_summary` | VARCHAR(255) NULL                  | 显示用 UA 截断 |
| `first_seen` | TIMESTAMP                          | |
| `last_seen`  | TIMESTAMP ON UPDATE CURRENT        | |
| `trusted`    | TINYINT(1) DEFAULT 0               | 是否受信。本项目首登即置 1 |
| UNIQUE       | `(user_id, device_fp)`             | |

转账接口在第 6 步用 `WHERE user_id=? AND device_fp=? AND trusted=1` 检索,未命中即拒。

### 3.6 `rate_limit_log` —— 频次审计

| 字段 | 类型 | 用途 |
| --- | --- | --- |
| `id`         | BIGINT AI PK | |
| `bucket_key` | VARCHAR(128) | `<ip>\|<user>` |
| `action`     | VARCHAR(64)  | `login`/`pay`/`transfer`/… |
| `created_at` | TIMESTAMP    | |
| INDEX        | `(bucket_key, created_at)` | |

**说明:** 在线限流走应用进程内 token bucket(见 `crypto_utils.TokenBucket`),此表是预留的离线分析口子,目前项目未主动写入,可留作扩展。

---

## 4. 应用密码学密钥的初始化

数据库建好之后,**还需要应用层的一组密钥** —— 它们由 `app.py` 启动时自动生成,文件落在 `secure_storage/`,权限 `0600`:

| 文件 | 内容 | 触发生成 |
| --- | --- | --- |
| `secure_storage/kek_v1.bin`            | 32B 随机 AES-256 KEK(用来加 phone / TOTP) | 首次 `import crypto_utils` |
| `secure_storage/server_ecc_private.pem` | P-256 ECDH 私钥(报文协商)         | 首次 `/api/get_token` |
| `secure_storage/server_ecc_public.pem`  | 对应公钥                          | 同上 |
| `secure_storage/jwt_ecdsa_private.pem`  | P-256 ECDSA 私钥(签 ES256 JWT)    | 首次 `import crypto_utils` |
| `secure_storage/jwt_ecdsa_public.pem`   | 对应公钥                          | 同上 |
| `secure_storage/audit_hmac.key`         | 32B 随机 HMAC 密钥(审计链)         | 同上 |

**你不需要手动生成这些** —— `python app.py` 启动时若发现文件缺失就会自动创建。如果你想把生产环境密钥搬到新机器,直接复制整个 `secure_storage/` 目录(权限保持 0600)。

---

## 5. 验证部署成功

```bash
mysql -uroot -p secure_pay_db -e "SHOW TABLES;"
```

应该看到 6 张表:
```
audit_logs
rate_limit_log
transactions
used_nonces
user_devices
users
```

启动应用并跑端到端测试(`requests`、`pyotp`、`cryptography` 在 `.venv` 已经装好):
```bash
.venv/bin/python app.py &        # 默认 0.0.0.0:5000
.venv/bin/python /tmp/e2e.py     # 见 README "快速启动"
```

期望输出末尾包含 `=== ALL OK ===` 即说明 schema、密钥、应用三层都正常。

---

## 6. 重置 / 重建 数据库

> ⚠️ **destructive**:以下命令会删除全部业务数据。仅用于本地开发重置。

### 6.1 仅清空数据、保留表结构
```sql
USE secure_pay_db;
SET FOREIGN_KEY_CHECKS = 0;
TRUNCATE TABLE transactions;
TRUNCATE TABLE used_nonces;
TRUNCATE TABLE user_devices;
TRUNCATE TABLE audit_logs;
TRUNCATE TABLE rate_limit_log;
DELETE FROM users;             -- 有 FK 引用,不能 TRUNCATE
ALTER TABLE users AUTO_INCREMENT = 1;
SET FOREIGN_KEY_CHECKS = 1;
```

### 6.2 完全重建(drop + 重跑 init)
```bash
mysql -uroot -p -e "DROP DATABASE secure_pay_db;"
mysql -uroot -p < migrations/init_schema.sql
```

重建后旧的应用密钥仍然可用,**但**审计哈希链会从头开始 —— 旧的 HMAC 链已经没有上下文了。如果要彻底重置成"出厂",也同步删 `secure_storage/`:

```bash
rm -rf secure_storage/    # 谨慎: 旧密文(若有)将永远无法解密!
```

---

## 7. 备份与恢复

**结构 + 数据**:
```bash
mysqldump -uroot -p --single-transaction --routines --triggers secure_pay_db > backup.sql
```

**只导结构**(便于查 diff):
```bash
mysqldump -uroot -p --no-data secure_pay_db > schema_only.sql
```

**恢复到新库**:
```bash
mysql -uroot -p -e "CREATE DATABASE secure_pay_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -uroot -p secure_pay_db < backup.sql
```

> 别忘了同步备份 `secure_storage/`,否则 phone/TOTP/审计 hash 都无法解读。

---

## 8. 应用配置中的 DB 凭据

`app.py:DATABASE_CONFIG` 默认连 `localhost:3306`,密码读自环境变量 `DB_PASSWORD`,缺省回落到代码里的 `lxb12138`。生产请走环境变量,**不要**把真实密码留在代码里:

```bash
export DB_PASSWORD="your-strong-password"
.venv/bin/python app.py
```

---

## 9. FAQ

**Q: 跑过旧版 schema(只有 `users/transactions/audit_logs/used_nonces` 4 张表)需要升级,该用哪个脚本?**
A: 按顺序跑两个增量迁移:
  1. `migrations/2026-05-14_security_upgrade.sql` —— 补齐 users/transactions/audit_logs 增列、建 user_devices/rate_limit_log。
  2. `migrations/2026-05-17_transfer_double_entry.sql` —— 给 transactions 加 `direction` 列。

两个脚本都是幂等的(用存储过程模拟"ADD COLUMN IF NOT EXISTS")。

**Q: 我能不能直接用 `init_schema.sql` 把旧库升级上来?**
A: 不行。`init_schema.sql` 用的是 `CREATE TABLE IF NOT EXISTS` —— 若旧表已经存在,它**不会**改动旧表结构。先跑 `2026-05-14_security_upgrade.sql` 把列补齐,再跑 `init_schema.sql` 把缺的表(`user_devices`、`rate_limit_log`)创出来,最终也一致。

**Q: 我希望表前缀加 `sp_` 之类的,可以吗?**
A: 改 `init_schema.sql` 里的表名 + `app.py` 里所有 SQL 的引用即可。本项目没有 ORM 抽象,改起来直接 grep 替换。

**Q: 哪些字段会被 KEK 加密、哪些不会?**
A: `users.phone_*`、`users.totp_*` 由 KEK 加密。其它字段(余额、用户名、交易金额/收款方等)**明文存**,因为它们是业务必查字段,加密后查询代价过高。

**Q: 转账时收款方为什么会多出一条记录?**
A: `/api/transfer` 是"双账本"实现 —— 发款方和收款方各落一条 `transactions`,通过 `direction` 字段区分(OUTGOING / INCOMING),便于双方都能在自己的账单里看到这笔交易。两条记录共享同一笔业务,但 `txn_id` 不同(收款方那条衍生为 `<txn_id>-R`),避免 UNIQUE 冲突。

**Q: 银行卡充值会把卡号存到数据库吗?**
A: 不会。`/api/topup` 设计为**零持久化敏感卡数据**:卡号 / CVV / 有效期 仅在请求生命周期内存活(通过 ECDH+AES-GCM 加密上送 → 服务端校验 Luhn / 有效期 / CVV 格式 → 用完即弃)。落库的 `transactions` 行只保留 `银行卡 ****<last4>` 这种掩码字符串,`direction='INCOMING'`,`txn_id` 形如 `TOPxxxxxxxx`。审计日志同样只记 last4。即便整库被拖,也无法还原任何完整卡号。
