"""
TOTP 实时演示工具
- 从数据库读取 totp_enabled=1 的用户列表
- 用 KEK 解密 totp_ciphertext，拿到 base32 secret
- 实时显示当前 6 位动态码与下次刷新倒计时

用法：
    .venv/bin/python demo_totp.py            # 交互式选用户
    .venv/bin/python demo_totp.py alice      # 直接指定用户名
按 Ctrl+C 退出。
"""
import os
import sys
import time
import pymysql
import pyotp

import crypto_utils as cu

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": os.environ.get("DB_PASSWORD", "lxb12138"),
    "database": "secure_pay_db",
    "charset": "utf8mb4",
    "cursorclass": pymysql.cursors.DictCursor,
    "autocommit": True,
}


def list_enabled_users(cursor) -> list[dict]:
    cursor.execute(
        "SELECT id, username, totp_iv, totp_ciphertext, totp_tag "
        "FROM users WHERE totp_enabled=1 ORDER BY id"
    )
    return list(cursor.fetchall())


def pick_user(users: list[dict], wanted: str | None) -> dict:
    if not users:
        print("数据库里没有任何已绑定 2FA 的用户。请先在网页上完成 TOTP 绑定。")
        sys.exit(1)
    if wanted:
        for u in users:
            if u["username"] == wanted:
                return u
        print(f"未找到用户 {wanted!r}，或该用户未启用 2FA。")
        sys.exit(1)
    if len(users) == 1:
        return users[0]
    print("已绑定 2FA 的用户：")
    for i, u in enumerate(users, 1):
        print(f"  [{i}] {u['username']} (id={u['id']})")
    while True:
        choice = input("选择编号: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(users):
            return users[int(choice) - 1]
        print("无效输入，请重新选择。")


def decrypt_secret(user: dict) -> str:
    secret = cu.decrypt_field(
        user["totp_iv"], user["totp_ciphertext"], user["totp_tag"],
        aad=user["username"].encode("utf-8"),
    )
    if not secret:
        print("解密失败：totp 字段为空或 KEK 不匹配。")
        sys.exit(1)
    return secret


def render_loop(username: str, secret: str) -> None:
    totp = pyotp.TOTP(secret)
    bar_width = 30
    print("\n" + "=" * 56)
    print(f"  SecurePay TOTP Live Viewer  —  user: {username}")
    print("=" * 56)
    print(f"  Secret (base32): {secret}")
    print(f"  Algorithm:       HMAC-SHA1, 6 digits, 30s window (RFC 6238)")
    print(f"  服务器接受窗口:  ±30s (valid_window=1)")
    print("=" * 56)
    print("  Ctrl+C 退出\n")

    try:
        while True:
            now = time.time()
            remaining = 30 - (int(now) % 30)
            code = totp.now()
            filled = bar_width - int(bar_width * remaining / 30)
            bar = "█" * filled + "░" * (bar_width - filled)
            sys.stdout.write(
                f"\r  当前码: \033[1;32m{code[:3]} {code[3:]}\033[0m   "
                f"刷新倒计时: [{bar}] {remaining:2d}s "
            )
            sys.stdout.flush()
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  已退出。")


def main() -> None:
    wanted = sys.argv[1] if len(sys.argv) > 1 else None
    conn = pymysql.connect(**DB_CONFIG)
    try:
        with conn.cursor() as cursor:
            users = list_enabled_users(cursor)
    finally:
        conn.close()
    user = pick_user(users, wanted)
    secret = decrypt_secret(user)
    render_loop(user["username"], secret)


if __name__ == "__main__":
    main()
