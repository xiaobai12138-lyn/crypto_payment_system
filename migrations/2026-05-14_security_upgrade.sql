-- =====================================================================
-- secure_pay_db schema 升级 (2026-05-14)
-- 目标：支撑 JWT(ECDSA) / TOTP 2FA / 字段级 AES-GCM 加密 / 客户端 ECDSA
-- 抗抵赖签名 / 设备指纹绑定 / 审计哈希链。
-- 使用方式：
--   mysql -uroot -p secure_pay_db < migrations/2026-05-14_security_upgrade.sql
-- 幂等：用一个临时存储过程做 "ADD COLUMN IF NOT EXISTS" 的等价行为。
-- =====================================================================

DELIMITER //
DROP PROCEDURE IF EXISTS _add_col_if_missing //
CREATE PROCEDURE _add_col_if_missing(IN tbl VARCHAR(64), IN col VARCHAR(64), IN ddl TEXT)
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = tbl AND COLUMN_NAME = col
    ) THEN
        SET @s = CONCAT('ALTER TABLE `', tbl, '` ADD COLUMN `', col, '` ', ddl);
        PREPARE stmt FROM @s;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END //
DELIMITER ;

-- ---------- users 表 ----------
CALL _add_col_if_missing('users', 'phone_ciphertext',  'VARBINARY(255) NULL COMMENT "手机号 AES-256-GCM 密文"');
CALL _add_col_if_missing('users', 'phone_iv',          'VARBINARY(12) NULL  COMMENT "手机号 GCM IV"');
CALL _add_col_if_missing('users', 'phone_tag',         'VARBINARY(16) NULL  COMMENT "手机号 GCM tag"');
CALL _add_col_if_missing('users', 'payment_pwd_hash',  'VARCHAR(255) NULL   COMMENT "支付密码 PBKDF2 hash (与登录密码独立)"');
CALL _add_col_if_missing('users', 'totp_ciphertext',   'VARBINARY(255) NULL COMMENT "TOTP secret AES-256-GCM 密文"');
CALL _add_col_if_missing('users', 'totp_iv',           'VARBINARY(12) NULL');
CALL _add_col_if_missing('users', 'totp_tag',          'VARBINARY(16) NULL');
CALL _add_col_if_missing('users', 'totp_enabled',      'TINYINT(1) NOT NULL DEFAULT 0');
CALL _add_col_if_missing('users', 'signing_pub_key',   'TEXT NULL COMMENT "客户端长期 ECDSA-P256 公钥(PEM/SPKI)"');
CALL _add_col_if_missing('users', 'kek_version',       'INT NOT NULL DEFAULT 1 COMMENT "所用 KEK 版本，便于轮换"');

-- ---------- transactions 表 ----------
CALL _add_col_if_missing('transactions', 'client_signature', 'VARBINARY(96) NULL COMMENT "客户端 ECDSA-P256 对交易摘要的签名 (DER)"');
CALL _add_col_if_missing('transactions', 'digest_sha256',    'CHAR(64) NULL      COMMENT "交易摘要 (hex)"');
CALL _add_col_if_missing('transactions', 'device_fp',        'CHAR(64) NULL      COMMENT "设备指纹 (SHA-256 hex)"');

-- ---------- audit_logs 表 ----------
CALL _add_col_if_missing('audit_logs', 'prev_hash', 'CHAR(64) NULL COMMENT "上一条 operation_hash，组成哈希链"');

DROP PROCEDURE _add_col_if_missing;

-- ---------- 新表 ----------
CREATE TABLE IF NOT EXISTS user_devices (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    user_id         INT NOT NULL,
    device_fp       CHAR(64) NOT NULL COMMENT 'SHA-256 hex(指纹熵源)',
    ua_summary      VARCHAR(255) NULL,
    first_seen      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    trusted         TINYINT(1) NOT NULL DEFAULT 0,
    UNIQUE KEY uniq_user_device (user_id, device_fp),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS rate_limit_log (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    bucket_key  VARCHAR(128) NOT NULL,
    action      VARCHAR(64)  NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_bucket_time (bucket_key, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SELECT 'Migration 2026-05-14 applied' AS status;
