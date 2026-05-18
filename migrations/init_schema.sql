-- =====================================================================
-- secure_pay_db — 完整初始化脚本 (从零创建)
-- 版本: 2026-05-17
-- 适用: MySQL 8.x
--
-- 用途: 在一台干净的 MySQL 上一次性建库 + 建表，得到与开发环境一致的结构。
--
-- 安全特性:
--   - CREATE DATABASE / CREATE TABLE 均使用 IF NOT EXISTS, 不会破坏已存在的表;
--   - 不含 DROP TABLE / DROP DATABASE, 重复执行无副作用;
--   - 若你确实需要重置/重建, 见 DATABASE.md 的"重置" 章节, 必须手动 DROP。
--
-- 与 2026-05-14_security_upgrade.sql 的关系:
--   - 后者是"已有库 + 已有 4 张表(早期版本)"上的增量 ALTER (幂等);
--   - 本文件是面向"全新环境"的完整 CREATE;
--   - 两者最终落地的 schema 完全一致。
-- =====================================================================

CREATE DATABASE IF NOT EXISTS `secure_pay_db`
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE `secure_pay_db`;

SET NAMES utf8mb4;

-- ---------------------------------------------------------------------
-- 1. users — 账户主表
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `users` (
    `id`                INT            NOT NULL AUTO_INCREMENT,
    `username`          VARCHAR(80)    NOT NULL,
    `password_hash`     VARCHAR(255)   NOT NULL                COMMENT '登录密码 PBKDF2-SHA256 hash',
    `balance`           DECIMAL(12,2)  NOT NULL DEFAULT 0.00,
    `created_at`        TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `phone_ciphertext`  VARBINARY(255) NULL                    COMMENT '手机号 AES-256-GCM 密文',
    `phone_iv`          VARBINARY(12)  NULL                    COMMENT '手机号 GCM IV',
    `phone_tag`         VARBINARY(16)  NULL                    COMMENT '手机号 GCM tag',
    `payment_pwd_hash`  VARCHAR(255)   NULL                    COMMENT '支付密码 PBKDF2 hash (与登录密码独立)',
    `totp_ciphertext`   VARBINARY(255) NULL                    COMMENT 'TOTP secret AES-256-GCM 密文',
    `totp_iv`           VARBINARY(12)  NULL,
    `totp_tag`          VARBINARY(16)  NULL,
    `totp_enabled`      TINYINT(1)     NOT NULL DEFAULT 0,
    `signing_pub_key`   TEXT           NULL                    COMMENT '客户端长期 ECDSA-P256 公钥(PEM/SPKI)',
    `kek_version`       INT            NOT NULL DEFAULT 1      COMMENT '所用 KEK 版本，便于轮换',
    PRIMARY KEY (`id`),
    UNIQUE KEY `uniq_username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 2. transactions — 交易流水
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `transactions` (
    `id`                INT            NOT NULL AUTO_INCREMENT,
    `txn_id`            VARCHAR(64)    NOT NULL,
    `user_id`           INT            NOT NULL,
    `amount`            DECIMAL(12,2)  NOT NULL,
    `receiver`          VARCHAR(255)   NOT NULL,
    `status`            VARCHAR(32)    NOT NULL,
    `risk_score`        INT            NOT NULL DEFAULT 0,
    `created_at`        TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `client_signature`  VARBINARY(96)  NULL                    COMMENT '客户端 ECDSA-P256 对交易摘要的签名 (DER, 仅 OUTGOING)',
    `digest_sha256`     CHAR(64)       NULL                    COMMENT '交易摘要 (hex)',
    `device_fp`         CHAR(64)       NULL                    COMMENT '设备指纹 (SHA-256 hex)',
    `direction`         ENUM('OUTGOING','INCOMING') NOT NULL DEFAULT 'OUTGOING'
                                                               COMMENT '本行视角: OUTGOING=发出 / INCOMING=收到',
    PRIMARY KEY (`id`),
    UNIQUE KEY `uniq_txn_id` (`txn_id`),
    KEY `idx_transactions_user_id` (`user_id`),
    CONSTRAINT `fk_transactions_user`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 3. audit_logs — 审计日志 (HMAC-SHA256 哈希链)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `audit_logs` (
    `id`             INT          NOT NULL AUTO_INCREMENT,
    `event_type`     VARCHAR(64)  NOT NULL,
    `user_id`        INT          NULL,
    `severity`       VARCHAR(32)  NOT NULL,
    `description`    TEXT         NOT NULL,
    `ip_address`     VARCHAR(45)  NULL,
    `operation_hash` CHAR(64)     NOT NULL                  COMMENT '当前行 HMAC-SHA256(prev_hash || payload)',
    `created_at`     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `prev_hash`      CHAR(64)     NULL                      COMMENT '上一条 operation_hash，组成哈希链',
    PRIMARY KEY (`id`),
    KEY `idx_audit_logs_created_at` (`created_at`),
    KEY `idx_audit_logs_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 4. used_nonces — 防重放 Nonce 池
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `used_nonces` (
    `nonce`      VARCHAR(64) NOT NULL,
    `used_at`    TIMESTAMP   NULL DEFAULT NULL                COMMENT '为 NULL 表示已发未用；非 NULL 表示已消费',
    `created_at` TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`nonce`),
    KEY `idx_used_nonces_used_at` (`used_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 5. user_devices — 受信设备 / 指纹白名单
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `user_devices` (
    `id`         INT          NOT NULL AUTO_INCREMENT,
    `user_id`    INT          NOT NULL,
    `device_fp`  CHAR(64)     NOT NULL                                       COMMENT 'SHA-256 hex(浏览器指纹熵源)',
    `ua_summary` VARCHAR(255) NULL,
    `first_seen` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `last_seen`  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
                                       ON UPDATE CURRENT_TIMESTAMP,
    `trusted`    TINYINT(1)   NOT NULL DEFAULT 0,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uniq_user_device` (`user_id`, `device_fp`),
    CONSTRAINT `fk_user_devices_user`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- 6. rate_limit_log — 频次审计落库表 (在线限流走内存桶)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `rate_limit_log` (
    `id`         BIGINT       NOT NULL AUTO_INCREMENT,
    `bucket_key` VARCHAR(128) NOT NULL,
    `action`     VARCHAR(64)  NOT NULL,
    `created_at` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_bucket_time` (`bucket_key`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SELECT 'secure_pay_db init complete' AS status;

