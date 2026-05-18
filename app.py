"""
文件名：app.py
版本：3.0 — 完整移动支付安全体系
- 网络攻击：ECDH-P256 + AES-256-GCM 端到端加密、Nonce 防重放、Rate-limit、安全响应头
- 数据泄露：手机号/TOTP secret 字段级 AES-256-GCM 加密(KEK 落地保护)、PBKDF2 密码哈希
- 身份冒用：ECDSA-P256 签发 JWT(ES256)、独立支付密码、TOTP 2FA、客户端长期 ECDSA 签名(抗抵赖)、设备指纹
"""
import os, time, uuid, json, base64, hashlib, pymysql
from decimal import Decimal, InvalidOperation
from functools import wraps
from flask import Flask, request, jsonify, render_template, session, g
from flask_cors import CORS
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from werkzeug.security import generate_password_hash, check_password_hash

import crypto_utils as cu

app = Flask(__name__)
# secret_key 必须固定以保证 session 跨重启可用；生产请改环境变量
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret-please-change")
CORS(app, supports_credentials=True)

DATABASE_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': os.environ.get("DB_PASSWORD", 'lxb12138'),
    'database': 'secure_pay_db',
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor,
    'autocommit': False
}

KEYS_DIR = "secure_storage"
os.makedirs(KEYS_DIR, exist_ok=True)


def get_db():
    if 'db' not in g:
        g.db = pymysql.connect(**DATABASE_CONFIG)
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()


# --- 安全响应头 ---
@app.after_request
def apply_security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # 模板使用 Tailwind/FA CDN，CSP 放宽到 cdn.tailwindcss.com / cdnjs
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "style-src  'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "font-src   https://cdnjs.cloudflare.com data:; "
        "img-src    'self' data:; "
        "connect-src 'self'"
    )
    return resp


# --- 审计日志：HMAC-SHA256 哈希链 ---
def audit_log(event_type, user_id, severity, description, ip):
    db = get_db()
    try:
        with db.cursor() as cursor:
            cursor.execute("SELECT operation_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            prev_hash = row['operation_hash'] if row else None
            ts = time.time()
            chain_hash = cu.audit_chain_hash(prev_hash, event_type, user_id, description, ip or '', ts)
            sql = """INSERT INTO audit_logs
                     (event_type, user_id, severity, description, ip_address, operation_hash, prev_hash)
                     VALUES (%s, %s, %s, %s, %s, %s, %s)"""
            cursor.execute(sql, (event_type, user_id, severity, description, ip, chain_hash, prev_hash))
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"[ERROR] 审计日志写入失败: {e}")


def money_value(value):
    if value is None:
        return 0.0
    if isinstance(value, Decimal):
        return float(value)
    return value


def parse_amount(value):
    try:
        amount = Decimal(str(value)).quantize(Decimal('0.01'))
    except (InvalidOperation, TypeError, ValueError):
        raise ValueError("金额格式错误")
    if amount <= 0:
        raise ValueError("金额必须大于 0")
    return amount


def b64decode_field(data, field):
    try:
        return base64.b64decode(data[field], validate=True)
    except Exception as exc:
        raise ValueError(f"{field} 编码无效") from exc


def format_time(value):
    if not value:
        return None
    return value.strftime('%Y-%m-%d %H:%M:%S')


# --- JWT 鉴权装饰器 ---
def auth_required(allow_demo=False):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user_id = None
            token = None
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header[7:].strip()
            if token:
                try:
                    claims = cu.jwt_verify(token)
                    user_id = int(claims['sub'])
                except Exception as exc:
                    audit_log('AUTH_FAIL', None, 'WARN', f'JWT 校验失败: {exc}', request.remote_addr)
                    return jsonify({"status": "ERROR", "msg": "认证失败，请重新登录"}), 401
            elif allow_demo:
                user_id = ensure_demo_user()
            else:
                return jsonify({"status": "ERROR", "msg": "缺少认证 token"}), 401
            g.user_id = user_id
            return fn(*args, **kwargs)
        return wrapper
    return deco


def ensure_demo_user():
    """未登录访客自动绑定 demo_user，方便首屏 dashboard 不空。"""
    if session.get('user_id'):
        return session['user_id']
    db = get_db()
    with db.cursor() as cursor:
        cursor.execute("SELECT id FROM users WHERE username = %s", ('demo_user',))
        user = cursor.fetchone()
        if user:
            user_id = user['id']
        else:
            cursor.execute(
                "INSERT INTO users (username, password_hash, balance) VALUES (%s, %s, %s)",
                ('demo_user', generate_password_hash('demo123456'), 10000.00)
            )
            user_id = cursor.lastrowid
    db.commit()
    session['user_id'] = user_id
    return user_id


# --- ECC 临时密钥 (会话级 ECDH 协商) ---
def load_server_ecc_key():
    priv_path = f"{KEYS_DIR}/server_ecc_private.pem"
    pub_path = f"{KEYS_DIR}/server_ecc_public.pem"
    if not (os.path.exists(priv_path) and os.path.exists(pub_path)):
        key = ECC.generate(curve='P-256')
        with open(priv_path, "wt", encoding="utf-8") as f:
            f.write(key.export_key(format='PEM'))
        with open(pub_path, "wt", encoding="utf-8") as f:
            f.write(key.public_key().export_key(format='PEM'))
    with open(priv_path, "rt", encoding="utf-8") as f:
        return ECC.import_key(f.read())


def derive_ecc_session_key(client_public_pem, nonce):
    server_key = load_server_ecc_key()
    client_public_key = ECC.import_key(client_public_pem)
    shared_point = client_public_key.pointQ * int(server_key.d)
    shared_secret = int(shared_point.x).to_bytes(32, 'big')
    return HKDF(
        shared_secret, 32, nonce.encode('utf-8'), SHA256,
        context=b'secure-pay-ecc-v1'
    )


# =========================== Rate-limit helper ===============================
def rate_limit(action, capacity, refill_sec):
    """简短装饰器；按 IP+用户 限流。"""
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            key = request.headers.get('X-Forwarded-For') or request.remote_addr or 'unknown'
            uid = getattr(g, 'user_id', None) or session.get('user_id') or 'anon'
            bucket_key = f"{key}|{uid}"
            if not cu.limiter.allow(bucket_key, action, capacity, refill_sec):
                audit_log('RATE_LIMIT', uid if isinstance(uid, int) else None, 'WARN',
                          f'触发限流: {action}', request.remote_addr)
                return jsonify({"status": "ERROR", "msg": "请求过于频繁，请稍后再试"}), 429
            return fn(*args, **kwargs)
        return wrapper
    return deco


# ================================ 路由 =======================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/dashboard')
@auth_required(allow_demo=True)
def dashboard():
    user_id = g.user_id
    db = get_db()
    try:
        with db.cursor() as cursor:
            cursor.execute("SELECT id, username, balance, totp_enabled FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            cursor.execute("""
                SELECT txn_id, amount, receiver, status, direction, risk_score, created_at
                FROM transactions WHERE user_id = %s
                ORDER BY created_at DESC LIMIT 10
            """, (user_id,))
            transactions = cursor.fetchall()
            cursor.execute("""
                SELECT
                    COALESCE(SUM(CASE WHEN DATE(created_at) = CURRENT_DATE AND status = 'SUCCESS' THEN amount ELSE 0 END), 0) AS today_amount,
                    COUNT(DISTINCT user_id) AS active_users
                FROM transactions
            """)
            stats = cursor.fetchone()
            cursor.execute("SELECT COUNT(*) AS total FROM audit_logs WHERE event_type = 'REPLAY_ATTACK'")
            replay = cursor.fetchone()
            cursor.execute("""
                SELECT event_type, severity, description, created_at
                FROM audit_logs ORDER BY created_at DESC LIMIT 50
            """)
            logs = cursor.fetchall()
        return jsonify({
            "status": "SUCCESS",
            "user": {
                "id": user['id'], "username": user['username'],
                "balance": money_value(user['balance']),
                "totp_enabled": bool(user['totp_enabled'])
            },
            "transactions": [{
                "txn_id": tx['txn_id'], "amount": money_value(tx['amount']),
                "receiver": tx['receiver'], "status": tx['status'],
                "direction": tx['direction'],
                "risk_score": tx['risk_score'], "created_at": format_time(tx['created_at'])
            } for tx in transactions],
            "stats": {
                "today_amount": money_value(stats['today_amount']),
                "active_users": stats['active_users'],
                "replay_blocks": replay['total']
            },
            "logs": [{
                "event_type": log['event_type'], "severity": log['severity'],
                "description": log['description'], "created_at": format_time(log['created_at'])
            } for log in logs]
        })
    except Exception as e:
        return jsonify({"status": "ERROR", "msg": str(e)}), 500


# --- 注册 / 登录 ---
@app.route('/api/register', methods=['POST'])
@rate_limit('register', capacity=5, refill_sec=60)
def register():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password')
    payment_password = data.get('payment_password')
    phone = (data.get('phone') or '').strip() or None

    if not username or not password or not payment_password:
        return jsonify({"status": "ERROR", "msg": "用户名/登录密码/支付密码均不能为空"}), 400
    if len(password) < 8 or len(payment_password) < 6:
        return jsonify({"status": "ERROR", "msg": "登录密码 ≥8 位、支付密码 ≥6 位"}), 400

    db = get_db()
    try:
        with db.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                return jsonify({"status": "ERROR", "msg": "用户名已存在"}), 409

            login_hash = generate_password_hash(password)
            pay_hash = generate_password_hash(payment_password)
            phone_iv = phone_ct = phone_tag = None
            if phone:
                # AAD 绑定到用户名以防止跨账户密文挪用
                phone_iv, phone_ct, phone_tag = cu.encrypt_field(phone, aad=username.encode('utf-8'))

            cursor.execute("""
                INSERT INTO users
                    (username, password_hash, payment_pwd_hash,
                     phone_ciphertext, phone_iv, phone_tag, balance, kek_version)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (username, login_hash, pay_hash,
                  phone_ct, phone_iv, phone_tag, 10000.00, 1))
            user_id = cursor.lastrowid
        db.commit()
        audit_log('USER_REGISTER', user_id, 'INFO', f'用户 {username} 注册成功', request.remote_addr)
        return jsonify({"status": "SUCCESS", "user_id": user_id})
    except Exception as e:
        db.rollback()
        audit_log('REGISTER_FAIL', None, 'WARN', str(e), request.remote_addr)
        return jsonify({"status": "ERROR", "msg": "注册失败"}), 500


@app.route('/api/login', methods=['POST'])
@rate_limit('login', capacity=10, refill_sec=60)
def login():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    totp_code = (data.get('totp_code') or '').strip()

    db = get_db()
    try:
        with db.cursor() as cursor:
            cursor.execute("""
                SELECT id, username, password_hash, totp_enabled,
                       totp_ciphertext, totp_iv, totp_tag
                FROM users WHERE username = %s
            """, (username,))
            user = cursor.fetchone()
        if not user or not check_password_hash(user['password_hash'], password):
            audit_log('LOGIN_FAIL', None, 'WARN', f'登录失败: {username}', request.remote_addr)
            return jsonify({"status": "ERROR", "msg": "用户名或密码错误"}), 401

        # 若已绑定 TOTP，必须二次校验
        if user['totp_enabled']:
            if not totp_code:
                return jsonify({"status": "TOTP_REQUIRED", "msg": "请输入动态验证码"}), 200
            try:
                secret = cu.decrypt_field(user['totp_iv'], user['totp_ciphertext'], user['totp_tag'],
                                          aad=user['username'].encode('utf-8'))
            except Exception:
                audit_log('TOTP_DECRYPT_FAIL', user['id'], 'CRITICAL', 'TOTP secret 解密失败', request.remote_addr)
                return jsonify({"status": "ERROR", "msg": "二次验证不可用"}), 500
            if not cu.totp_verify(secret, totp_code):
                audit_log('TOTP_FAIL', user['id'], 'WARN', '动态码错误', request.remote_addr)
                return jsonify({"status": "ERROR", "msg": "动态码错误"}), 401

        session['user_id'] = user['id']
        token = cu.jwt_issue(user['id'], extras={"name": user['username']})
        audit_log('LOGIN_SUCCESS', user['id'], 'INFO', '用户登录', request.remote_addr)
        return jsonify({
            "status": "SUCCESS", "user_id": user['id'], "username": user['username'],
            "token": token, "totp_enabled": bool(user['totp_enabled'])
        })
    except Exception as e:
        return jsonify({"status": "ERROR", "msg": str(e)}), 500


@app.route('/api/logout', methods=['POST'])
def logout():
    uid = session.pop('user_id', None)
    if uid:
        audit_log('LOGOUT', uid, 'INFO', '用户登出', request.remote_addr)
    return jsonify({"status": "SUCCESS"})


# --- TOTP 2FA 绑定 / 关闭 ---
@app.route('/api/totp/setup', methods=['POST'])
@auth_required()
def totp_setup():
    """返回 otpauth URI，用户用 Authy/Google Authenticator 扫码或手填。
    secret 暂存到 session 直至 /verify 通过才写库（加密落地）。"""
    secret = cu.generate_totp_secret()
    session['pending_totp_secret'] = secret
    db = get_db()
    with db.cursor() as cursor:
        cursor.execute("SELECT username FROM users WHERE id = %s", (g.user_id,))
        u = cursor.fetchone()
    uri = cu.totp_provisioning_uri(secret, account=u['username'])
    audit_log('TOTP_SETUP_INIT', g.user_id, 'INFO', '发起 TOTP 绑定', request.remote_addr)
    return jsonify({"status": "SUCCESS", "secret": secret, "otpauth_uri": uri})


@app.route('/api/totp/verify', methods=['POST'])
@auth_required()
def totp_verify():
    data = request.get_json() or {}
    code = (data.get('code') or '').strip()
    secret = session.get('pending_totp_secret')
    if not secret:
        return jsonify({"status": "ERROR", "msg": "请先调用 /api/totp/setup"}), 400
    if not cu.totp_verify(secret, code):
        return jsonify({"status": "ERROR", "msg": "动态码错误"}), 401

    db = get_db()
    try:
        with db.cursor() as cursor:
            cursor.execute("SELECT username FROM users WHERE id = %s", (g.user_id,))
            u = cursor.fetchone()
            iv, ct, tag = cu.encrypt_field(secret, aad=u['username'].encode('utf-8'))
            cursor.execute("""
                UPDATE users
                SET totp_ciphertext=%s, totp_iv=%s, totp_tag=%s, totp_enabled=1
                WHERE id=%s
            """, (ct, iv, tag, g.user_id))
        db.commit()
        session.pop('pending_totp_secret', None)
        audit_log('TOTP_ENABLE', g.user_id, 'INFO', '2FA 绑定成功', request.remote_addr)
        return jsonify({"status": "SUCCESS"})
    except Exception as e:
        db.rollback()
        return jsonify({"status": "ERROR", "msg": str(e)}), 500


# --- 客户端长期签名公钥登记（用于交易抗抵赖） ---
@app.route('/api/device/register', methods=['POST'])
@auth_required()
def device_register():
    data = request.get_json() or {}
    pub_pem = (data.get('signing_pub_key') or '').strip()
    device_fp = (data.get('device_fp') or '').strip()
    ua = request.headers.get('User-Agent', '')[:255]
    if not pub_pem or not device_fp:
        return jsonify({"status": "ERROR", "msg": "缺少签名公钥或设备指纹"}), 400
    if 'BEGIN PUBLIC KEY' not in pub_pem:
        return jsonify({"status": "ERROR", "msg": "公钥格式错误，应为 PEM/SPKI"}), 400

    db = get_db()
    try:
        with db.cursor() as cursor:
            cursor.execute("UPDATE users SET signing_pub_key=%s WHERE id=%s", (pub_pem, g.user_id))
            cursor.execute("""
                INSERT INTO user_devices (user_id, device_fp, ua_summary, trusted)
                VALUES (%s, %s, %s, 1)
                ON DUPLICATE KEY UPDATE last_seen=CURRENT_TIMESTAMP, trusted=1
            """, (g.user_id, device_fp, ua))
        db.commit()
        audit_log('DEVICE_BIND', g.user_id, 'INFO', f'绑定设备指纹 {device_fp[:12]}…', request.remote_addr)
        return jsonify({"status": "SUCCESS"})
    except Exception as e:
        db.rollback()
        return jsonify({"status": "ERROR", "msg": str(e)}), 500


# --- 服务端公钥披露（JWT 验证 + ECDH 协商均会用） ---
@app.route('/api/keys/server', methods=['GET'])
def server_keys():
    load_server_ecc_key()
    pub_ecdh = open(f"{KEYS_DIR}/server_ecc_public.pem", encoding="utf-8").read().strip()
    return jsonify({
        "ecdh_pub_key": pub_ecdh,        # 报文加密协商
        "jwt_pub_key": cu.jwt_public_pem(),  # ES256 JWT 验证
    })


# --- 兼容 v2：单次支付的 nonce + ECDH 公钥下发 ---
@app.route('/api/get_token', methods=['GET'])
@rate_limit('get_token', capacity=30, refill_sec=60)
def get_token():
    load_server_ecc_key()
    pub_key = open(f"{KEYS_DIR}/server_ecc_public.pem", encoding="utf-8").read().strip()
    nonce = "N" + uuid.uuid4().hex[:16].upper()
    db = get_db()
    try:
        with db.cursor() as cursor:
            cursor.execute("""
                DELETE FROM used_nonces
                WHERE created_at < NOW() - INTERVAL 10 MINUTE
                   OR used_at < NOW() - INTERVAL 10 MINUTE
            """)
            cursor.execute("INSERT INTO used_nonces (nonce) VALUES (%s)", (nonce,))
        db.commit()
    except Exception:
        db.rollback()
    return jsonify({
        "crypto": "ECDH-P256-HKDF-SHA256-AES-256-GCM",
        "server_ecc_pub_key": pub_key, "nonce": nonce, "expires_in": 300
    })


def _consume_nonce(cursor, nonce):
    """SELECT FOR UPDATE → 标记 used_at；若被用过/不存在则抛 ReplayError。"""
    cursor.execute("SELECT used_at FROM used_nonces WHERE nonce = %s FOR UPDATE", (nonce,))
    row = cursor.fetchone()
    if not row or row['used_at'] is not None:
        raise ReplayError(nonce)
    cursor.execute("UPDATE used_nonces SET used_at = NOW() WHERE nonce = %s", (nonce,))


class ReplayError(Exception):
    pass


def _decrypt_payload(data):
    """ECDH 协商 → AES-GCM 解密，返回明文 JSON dict。"""
    aes_key = derive_ecc_session_key(data['client_ecc_pub_key'], data['nonce'])
    iv = b64decode_field(data, 'iv')
    tag = b64decode_field(data, 'tag')
    ciphertext = b64decode_field(data, 'payload')
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    cipher_aes.update(data['nonce'].encode('utf-8'))
    return json.loads(cipher_aes.decrypt_and_verify(ciphertext, tag).decode('utf-8'))


# --- 支付（保留兼容） ---
@app.route('/api/pay', methods=['POST'])
@auth_required(allow_demo=True)
@rate_limit('pay', capacity=20, refill_sec=60)
def process_payment():
    user_id = g.user_id
    data = request.get_json() or {}
    client_ip = request.remote_addr
    required = ['nonce', 'client_ecc_pub_key', 'iv', 'tag', 'payload']
    if not all(k in data for k in required):
        audit_log('PAY_FAIL', user_id, 'WARN', '参数缺失', client_ip)
        return jsonify({"status": "ERROR", "msg": "参数错误"}), 400

    db = get_db()
    try:
        with db.cursor() as cursor:
            try:
                _consume_nonce(cursor, data['nonce'])
            except ReplayError:
                audit_log('REPLAY_ATTACK', user_id, 'CRITICAL', f'拦截重放: {data["nonce"]}', client_ip)
                return jsonify({"status": "FAILED", "msg": "请求非法，请刷新重试"}), 403

        try:
            txn_data = _decrypt_payload(data)
            amount = parse_amount(txn_data['amount'])
            receiver = txn_data['receiver']
        except Exception as e:
            audit_log('PAY_FAIL', user_id, 'CRITICAL', f'解密失败: {e}', client_ip)
            return jsonify({"status": "ERROR", "msg": "数据解密失败"}), 400

        with db.cursor() as cursor:
            cursor.execute("SELECT balance FROM users WHERE id = %s FOR UPDATE", (user_id,))
            user = cursor.fetchone()
            if not user or user['balance'] < amount:
                audit_log('PAY_FAIL', user_id, 'WARN', f'余额不足: 需{amount} 余{user["balance"]}', client_ip)
                return jsonify({"status": "FAILED", "msg": "余额不足"}), 200
            txn_id = "TXN" + uuid.uuid4().hex[:12].upper()
            cursor.execute("UPDATE users SET balance = balance - %s WHERE id = %s", (amount, user_id))
            cursor.execute("""INSERT INTO transactions
                (txn_id, user_id, amount, receiver, status, risk_score, direction)
                VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (txn_id, user_id, amount, receiver, 'SUCCESS', 10, 'OUTGOING'))
        db.commit()
        audit_log('PAY_SUCCESS', user_id, 'INFO', f'支付成功: {txn_id} 金额: {amount}', client_ip)
        return jsonify({"status": "SUCCESS", "txn_id": txn_id,
                        "new_balance": money_value(user['balance'] - amount), "msg": "支付成功"})
    except Exception as e:
        db.rollback()
        audit_log('SYSTEM_ERROR', user_id, 'CRITICAL', f'系统异常: {e}', client_ip)
        return jsonify({"status": "ERROR", "msg": "系统繁忙"}), 500


# --- 转账：完整安全管线 ---
@app.route('/api/transfer', methods=['POST'])
@auth_required()
@rate_limit('transfer', capacity=10, refill_sec=60)
def transfer():
    """请求体：
    {
      "nonce", "client_ecc_pub_key", "iv", "tag", "payload",     # ECDH+AES-GCM 包裹的明文 JSON
      "client_signature": base64(ECDSA-P256/SHA-256 over digest),
      "device_fp": "<sha256 hex>"
    }
    密文 payload 解出: { amount, receiver, payment_password, totp_code }
    """
    user_id = g.user_id
    ip = request.remote_addr
    data = request.get_json() or {}
    required = ['nonce', 'client_ecc_pub_key', 'iv', 'tag', 'payload', 'client_signature', 'device_fp']
    if not all(k in data for k in required):
        audit_log('TRANSFER_FAIL', user_id, 'WARN', '参数缺失', ip)
        return jsonify({"status": "ERROR", "msg": "参数错误"}), 400

    db = get_db()
    try:
        # 1) 防重放
        with db.cursor() as cursor:
            try:
                _consume_nonce(cursor, data['nonce'])
            except ReplayError:
                audit_log('REPLAY_ATTACK', user_id, 'CRITICAL', f'转账重放: {data["nonce"]}', ip)
                return jsonify({"status": "FAILED", "msg": "请求非法，请刷新"}), 403

        # 2) 解密
        try:
            inner = _decrypt_payload(data)
            amount = parse_amount(inner['amount'])
            receiver = (inner.get('receiver') or '').strip()
            pay_pwd = inner.get('payment_password') or ''
            totp_code = (inner.get('totp_code') or '').strip()
            if not receiver:
                raise ValueError("收款方为空")
        except Exception as e:
            audit_log('TRANSFER_FAIL', user_id, 'CRITICAL', f'解密失败: {e}', ip)
            return jsonify({"status": "ERROR", "msg": "数据解密失败"}), 400

        # 3) 用户/凭证校验
        with db.cursor() as cursor:
            # 3.1 先验证收款方存在且不是自己 (无锁查询)
            cursor.execute("SELECT id, username FROM users WHERE username = %s", (receiver,))
            receiver_row = cursor.fetchone()
            if not receiver_row:
                audit_log('TRANSFER_FAIL', user_id, 'WARN', f'收款方不存在: {receiver}', ip)
                return jsonify({"status": "FAILED", "msg": f"收款方 {receiver} 不存在"}), 200
            if receiver_row['id'] == user_id:
                audit_log('TRANSFER_FAIL', user_id, 'WARN', '禁止向自己转账', ip)
                return jsonify({"status": "FAILED", "msg": "不能向自己转账"}), 200
            receiver_id = receiver_row['id']
            receiver_name = receiver_row['username']

            # 3.2 按 id 升序加锁双方,避免并发死锁
            lock_order = sorted({user_id, receiver_id})
            locked = {}
            for uid in lock_order:
                cursor.execute("""
                    SELECT id, username, balance, payment_pwd_hash,
                           totp_enabled, totp_ciphertext, totp_iv, totp_tag,
                           signing_pub_key
                    FROM users WHERE id=%s FOR UPDATE
                """, (uid,))
                locked[uid] = cursor.fetchone()
            user = locked[user_id]
            receiver_user = locked[receiver_id]

            if not user or not user['payment_pwd_hash'] or not check_password_hash(user['payment_pwd_hash'], pay_pwd):
                audit_log('TRANSFER_FAIL', user_id, 'WARN', '支付密码错误', ip)
                return jsonify({"status": "FAILED", "msg": "支付密码错误"}), 401

            if user['totp_enabled']:
                secret = cu.decrypt_field(user['totp_iv'], user['totp_ciphertext'], user['totp_tag'],
                                          aad=user['username'].encode('utf-8'))
                if not cu.totp_verify(secret, totp_code):
                    audit_log('TRANSFER_FAIL', user_id, 'WARN', '动态码错误', ip)
                    return jsonify({"status": "FAILED", "msg": "动态码错误"}), 401

            if not user['signing_pub_key']:
                audit_log('TRANSFER_FAIL', user_id, 'WARN', '未登记签名设备', ip)
                return jsonify({"status": "ERROR", "msg": "请先在本设备完成签名密钥登记"}), 400

            # 4) 设备指纹必须可信
            cursor.execute("SELECT id FROM user_devices WHERE user_id=%s AND device_fp=%s AND trusted=1",
                           (user_id, data['device_fp']))
            if not cursor.fetchone():
                audit_log('TRANSFER_FAIL', user_id, 'CRITICAL', f'未受信设备 {data["device_fp"][:12]}…', ip)
                return jsonify({"status": "FAILED", "msg": "设备未受信，请先在本设备登录并绑定"}), 403

            # 5) 客户端 ECDSA 签名验证（抗抵赖）
            txn_id = "TXN" + uuid.uuid4().hex[:12].upper()
            digest = cu.transaction_digest(
                user_id=user_id, txn_id='',
                amount=str(amount), receiver=receiver_name,
                nonce=data['nonce'], device_fp=data['device_fp']
            )
            try:
                sig_der = base64.b64decode(data['client_signature'], validate=True)
            except Exception:
                return jsonify({"status": "ERROR", "msg": "签名编码错误"}), 400
            if not cu.verify_client_signature(user['signing_pub_key'], sig_der, digest):
                audit_log('SIGN_FAIL', user_id, 'CRITICAL', '客户端签名校验失败', ip)
                return jsonify({"status": "FAILED", "msg": "交易签名校验失败"}), 403

            # 6) 余额
            if user['balance'] < amount:
                audit_log('TRANSFER_FAIL', user_id, 'WARN', f'余额不足 需{amount} 余{user["balance"]}', ip)
                return jsonify({"status": "FAILED", "msg": f"余额不足: 当前 ¥{money_value(user['balance']):.2f}, 需要 ¥{float(amount):.2f}"}), 200

            # 7) 双账本: 发款方 -amount, 收款方 +amount, 各写一条流水
            cursor.execute("UPDATE users SET balance = balance - %s WHERE id = %s", (amount, user_id))
            cursor.execute("UPDATE users SET balance = balance + %s WHERE id = %s", (amount, receiver_id))

            # 发款方视角: OUTGOING, receiver 字段记对方姓名
            cursor.execute("""INSERT INTO transactions
                (txn_id, user_id, amount, receiver, status, risk_score,
                 client_signature, digest_sha256, device_fp, direction)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (txn_id, user_id, amount, receiver_name, 'SUCCESS', 5,
                 sig_der, digest.hex(), data['device_fp'], 'OUTGOING'))
            # 收款方视角: INCOMING, receiver 字段记对方(发款方)姓名,txn_id 衍生
            in_txn_id = txn_id + "-R"
            cursor.execute("""INSERT INTO transactions
                (txn_id, user_id, amount, receiver, status, risk_score, direction)
                VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (in_txn_id, receiver_id, amount, user['username'], 'SUCCESS', 0, 'INCOMING'))
        db.commit()
        audit_log('TRANSFER_SUCCESS', user_id, 'INFO',
                  f'转账成功 {txn_id}: {user["username"]} → {receiver_name} 金额 {amount}', ip)
        audit_log('TRANSFER_INCOMING', receiver_id, 'INFO',
                  f'收到转账 {in_txn_id}: {user["username"]} → {receiver_name} 金额 {amount}', ip)
        # 服务端回执 JWT 同样可校验（含 txn_id），实现服务端抗抵赖
        receipt = cu.jwt_issue(user_id, extras={
            "txn_id": txn_id, "amount": str(amount), "receiver": receiver_name,
            "digest": digest.hex()
        })
        return jsonify({"status": "SUCCESS", "txn_id": txn_id,
                        "new_balance": money_value(user['balance'] - amount),
                        "receipt": receipt})
    except Exception as e:
        db.rollback()
        audit_log('SYSTEM_ERROR', user_id, 'CRITICAL', f'转账异常: {e}', ip)
        return jsonify({"status": "ERROR", "msg": "系统繁忙"}), 500


# --- 充值: 从银行卡到 APP ---
def _luhn_check(card_number: str) -> bool:
    """Luhn 算法校验银行卡号(MOD-10)。"""
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) != len(card_number) or not (13 <= len(digits) <= 19):
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _validate_expiry(expiry: str) -> bool:
    """expiry 形如 'MM/YY'(本世纪)。"""
    import re
    m = re.fullmatch(r'(\d{2})/(\d{2})', expiry or '')
    if not m:
        return False
    mm, yy = int(m.group(1)), int(m.group(2))
    if not (1 <= mm <= 12):
        return False
    # 取本月 vs 卡有效期月末
    import datetime as _dt
    now = _dt.date.today()
    exp_year = 2000 + yy
    # 月末 (下一个月 day=1 - 1 day)
    if mm == 12:
        last = _dt.date(exp_year + 1, 1, 1) - _dt.timedelta(days=1)
    else:
        last = _dt.date(exp_year, mm + 1, 1) - _dt.timedelta(days=1)
    return last >= now


@app.route('/api/topup', methods=['POST'])
@auth_required()
@rate_limit('topup', capacity=5, refill_sec=60)
def topup():
    """从银行卡充值。

    请求体跟 /api/transfer 同结构, 明文 payload:
      { amount, card_number, card_holder, expiry("MM/YY"), cvv,
        payment_password, totp_code }
    所有银行卡敏感数据用完即弃, 不入库;只把 `银行卡 ****<last4>` 字符串
    写入 transactions.receiver。
    """
    user_id = g.user_id
    ip = request.remote_addr
    data = request.get_json() or {}
    required = ['nonce', 'client_ecc_pub_key', 'iv', 'tag', 'payload',
                'client_signature', 'device_fp']
    if not all(k in data for k in required):
        audit_log('TOPUP_FAIL', user_id, 'WARN', '参数缺失', ip)
        return jsonify({"status": "ERROR", "msg": "参数错误"}), 400

    db = get_db()
    try:
        # 1) Nonce 一次性
        with db.cursor() as cursor:
            try:
                _consume_nonce(cursor, data['nonce'])
            except ReplayError:
                audit_log('REPLAY_ATTACK', user_id, 'CRITICAL',
                          f'充值重放: {data["nonce"]}', ip)
                return jsonify({"status": "FAILED", "msg": "请求非法，请刷新"}), 403

        # 2) 解密
        try:
            inner = _decrypt_payload(data)
            amount = parse_amount(inner['amount'])
            card_number = (inner.get('card_number') or '').replace(' ', '').strip()
            card_holder = (inner.get('card_holder') or '').strip()
            expiry      = (inner.get('expiry') or '').strip()
            cvv         = (inner.get('cvv') or '').strip()
            pay_pwd     = inner.get('payment_password') or ''
            totp_code   = (inner.get('totp_code') or '').strip()
        except Exception as e:
            audit_log('TOPUP_FAIL', user_id, 'CRITICAL', f'解密失败: {e}', ip)
            return jsonify({"status": "ERROR", "msg": "数据解密失败"}), 400

        # 3) 银行卡格式校验 (Luhn + 长度 + CVV + expiry)
        if not _luhn_check(card_number):
            audit_log('TOPUP_FAIL', user_id, 'WARN', '卡号 Luhn 校验未通过', ip)
            return jsonify({"status": "FAILED", "msg": "卡号无效"}), 200
        if not (cvv.isdigit() and 3 <= len(cvv) <= 4):
            return jsonify({"status": "FAILED", "msg": "CVV 格式错误"}), 200
        if not _validate_expiry(expiry):
            return jsonify({"status": "FAILED", "msg": "有效期错误或已过期"}), 200
        if not card_holder:
            return jsonify({"status": "FAILED", "msg": "持卡人姓名不能为空"}), 200
        if amount > Decimal('50000'):
            audit_log('TOPUP_FAIL', user_id, 'WARN', f'单笔超限: {amount}', ip)
            return jsonify({"status": "FAILED", "msg": "单笔充值上限 ¥50,000"}), 200

        last4 = card_number[-4:]
        receiver_label = f"银行卡 ****{last4}"

        # 4) 凭证 + 2FA + 设备 + ECDSA 校验
        with db.cursor() as cursor:
            cursor.execute("""
                SELECT id, username, balance, payment_pwd_hash,
                       totp_enabled, totp_ciphertext, totp_iv, totp_tag,
                       signing_pub_key
                FROM users WHERE id=%s FOR UPDATE
            """, (user_id,))
            user = cursor.fetchone()

            if not user or not user['payment_pwd_hash'] or not check_password_hash(user['payment_pwd_hash'], pay_pwd):
                audit_log('TOPUP_FAIL', user_id, 'WARN', '支付密码错误', ip)
                return jsonify({"status": "FAILED", "msg": "支付密码错误"}), 401

            if user['totp_enabled']:
                secret = cu.decrypt_field(user['totp_iv'], user['totp_ciphertext'], user['totp_tag'],
                                          aad=user['username'].encode('utf-8'))
                if not cu.totp_verify(secret, totp_code):
                    audit_log('TOPUP_FAIL', user_id, 'WARN', '动态码错误', ip)
                    return jsonify({"status": "FAILED", "msg": "动态码错误"}), 401

            if not user['signing_pub_key']:
                return jsonify({"status": "ERROR", "msg": "请先在本设备完成签名密钥登记"}), 400

            cursor.execute("SELECT id FROM user_devices WHERE user_id=%s AND device_fp=%s AND trusted=1",
                           (user_id, data['device_fp']))
            if not cursor.fetchone():
                audit_log('TOPUP_FAIL', user_id, 'CRITICAL',
                          f'未受信设备 {data["device_fp"][:12]}…', ip)
                return jsonify({"status": "FAILED", "msg": "设备未受信"}), 403

            # 5) 客户端 ECDSA 签名 — 摘要里只含 last4 (整张卡号不上链不入摘要)
            digest = cu.transaction_digest(
                user_id=user_id, txn_id='',
                amount=str(amount), receiver=receiver_label,
                nonce=data['nonce'], device_fp=data['device_fp']
            )
            try:
                sig_der = base64.b64decode(data['client_signature'], validate=True)
            except Exception:
                return jsonify({"status": "ERROR", "msg": "签名编码错误"}), 400
            if not cu.verify_client_signature(user['signing_pub_key'], sig_der, digest):
                audit_log('SIGN_FAIL', user_id, 'CRITICAL', '充值签名校验失败', ip)
                return jsonify({"status": "FAILED", "msg": "交易签名校验失败"}), 403

            # 6) 入账
            txn_id = "TOP" + uuid.uuid4().hex[:12].upper()
            cursor.execute("UPDATE users SET balance = balance + %s WHERE id = %s",
                           (amount, user_id))
            cursor.execute("""INSERT INTO transactions
                (txn_id, user_id, amount, receiver, status, risk_score,
                 client_signature, digest_sha256, device_fp, direction)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (txn_id, user_id, amount, receiver_label, 'SUCCESS', 0,
                 sig_der, digest.hex(), data['device_fp'], 'INCOMING'))

        db.commit()
        # 在审计日志只记 last4, 完整卡号永远不留痕
        audit_log('TOPUP_SUCCESS', user_id, 'INFO',
                  f'充值成功 {txn_id}: {receiver_label} → 金额 {amount}', ip)
        receipt = cu.jwt_issue(user_id, extras={
            "txn_id": txn_id, "amount": str(amount),
            "receiver": receiver_label, "digest": digest.hex()
        })
        # 卡号、CVV、expiry 此刻已超出作用域, GC 即可回收;不返回回响应
        return jsonify({"status": "SUCCESS", "txn_id": txn_id,
                        "new_balance": money_value(user['balance'] + amount),
                        "receipt": receipt})
    except Exception as e:
        db.rollback()
        audit_log('SYSTEM_ERROR', user_id, 'CRITICAL', f'充值异常: {e}', ip)
        return jsonify({"status": "ERROR", "msg": "系统繁忙"}), 500


@app.route('/api/admin/logs')
@auth_required()
def admin_logs():
    if g.user_id != 1:
        return jsonify({"status": "ERROR", "msg": "权限不足"}), 403
    db = get_db()
    try:
        with db.cursor() as cursor:
            cursor.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 50")
            logs = cursor.fetchall()
            for log in logs:
                log['created_at'] = log['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        return jsonify(logs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=False, port=5000)
