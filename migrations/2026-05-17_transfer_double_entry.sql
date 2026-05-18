-- =====================================================================
-- 2026-05-17_transfer_double_entry.sql
-- 目的: 让转账成为"双账本" — 发款方 / 收款方各写一条 transactions 记录,
--      方向用 direction 字段区分,前端可正确显示 ±金额。
-- 幂等: 用临时存储过程实现 "ADD COLUMN IF NOT EXISTS"。
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

CALL _add_col_if_missing(
    'transactions',
    'direction',
    "ENUM('OUTGOING','INCOMING') NOT NULL DEFAULT 'OUTGOING' COMMENT '本行视角: OUTGOING=发出 / INCOMING=收到'"
);

DROP PROCEDURE _add_col_if_missing;

SELECT 'Migration 2026-05-17 applied: transactions.direction added' AS status;
