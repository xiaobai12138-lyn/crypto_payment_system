"""crypto_utils.py — 移动支付安全体系的密码学工具层。

模块覆盖：
- 字段级 AES-256-GCM 加解密 (KEK 由文件落地，可按 kek_version 轮换)
- ECDSA-P256 服务器签名密钥 (签 JWT、签业务流水)
- JWT 签发/验证 (ES256 = ECDSA-P256 + SHA-256)
- HMAC-SHA256 (审计哈希链、请求级 MAC)
- TOTP secret 生成 (pyotp / RFC 6238)
- 内存级 token-bucket rate limiter (按 IP+动作)
- ECDSA-P256 客户端签名验证 (抗抵赖)

约定：所有 GCM IV 12 字节，tag 16 字节。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import uuid
from typing import Any

import jwt as pyjwt
import pyotp
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.exceptions import InvalidSignature
from Crypto.Cipher import AES

KEYS_DIR = os.path.join(os.path.dirname(__file__), "secure_storage")
os.makedirs(KEYS_DIR, exist_ok=True)

KEK_PATH = os.path.join(KEYS_DIR, "kek_v1.bin")
JWT_PRIV_PATH = os.path.join(KEYS_DIR, "jwt_ecdsa_private.pem")
JWT_PUB_PATH = os.path.join(KEYS_DIR, "jwt_ecdsa_public.pem")
HMAC_KEY_PATH = os.path.join(KEYS_DIR, "audit_hmac.key")

JWT_ALG = "ES256"
JWT_ISSUER = "secure-pay"
JWT_TTL_SECONDS = 30 * 60  # 30 分钟


# =============================================================================
# 1. KEK / 字段级 AES-256-GCM
# =============================================================================
def _load_or_create_kek() -> bytes:
    """加载或生成 256-bit KEK (Key Encryption Key)。

    生产环境应替换为 HSM / KMS；这里用本地文件 + 0600 模拟。
    """
    if not os.path.exists(KEK_PATH):
        kek = secrets.token_bytes(32)
        with open(KEK_PATH, "wb") as f:
            f.write(kek)
        os.chmod(KEK_PATH, 0o600)
        return kek
    with open(KEK_PATH, "rb") as f:
        return f.read()


_KEK = _load_or_create_kek()


def aes_gcm_encrypt(plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes, bytes]:
    """返回 (iv, ciphertext, tag)，全部为 bytes。"""
    iv = secrets.token_bytes(12)
    cipher = AES.new(_KEK, AES.MODE_GCM, nonce=iv)
    if aad:
        cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return iv, ct, tag


def aes_gcm_decrypt(iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    cipher = AES.new(_KEK, AES.MODE_GCM, nonce=iv)
    if aad:
        cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)


def encrypt_field(plaintext: str | None, aad: bytes = b"") -> tuple[bytes, bytes, bytes] | tuple[None, None, None]:
    if plaintext is None:
        return None, None, None
    iv, ct, tag = aes_gcm_encrypt(plaintext.encode("utf-8"), aad=aad)
    return iv, ct, tag


def decrypt_field(iv: bytes | None, ciphertext: bytes | None, tag: bytes | None, aad: bytes = b"") -> str | None:
    if not (iv and ciphertext and tag):
        return None
    return aes_gcm_decrypt(bytes(iv), bytes(ciphertext), bytes(tag), aad=aad).decode("utf-8")


# =============================================================================
# 2. ECDSA-P256 服务器签名密钥 (用于 JWT 与交易回执)
# =============================================================================
def _load_or_create_jwt_keys() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    if not (os.path.exists(JWT_PRIV_PATH) and os.path.exists(JWT_PUB_PATH)):
        priv = ec.generate_private_key(ec.SECP256R1())
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with open(JWT_PRIV_PATH, "wb") as f:
            f.write(priv_pem)
        os.chmod(JWT_PRIV_PATH, 0o600)
        with open(JWT_PUB_PATH, "wb") as f:
            f.write(pub_pem)
    with open(JWT_PRIV_PATH, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    with open(JWT_PUB_PATH, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    return priv, pub


_JWT_PRIV, _JWT_PUB = _load_or_create_jwt_keys()

with open(JWT_PRIV_PATH, "rb") as _f:
    _JWT_PRIV_PEM = _f.read()
with open(JWT_PUB_PATH, "rb") as _f:
    _JWT_PUB_PEM = _f.read()


def jwt_public_pem() -> str:
    return _JWT_PUB_PEM.decode("utf-8")


def jwt_issue(user_id: int, extras: dict[str, Any] | None = None) -> str:
    """ES256 (ECDSA-P256 + SHA-256) JWT。"""
    now = int(time.time())
    payload = {
        "iss": JWT_ISSUER,
        "sub": str(user_id),
        "iat": now,
        "nbf": now,
        "exp": now + JWT_TTL_SECONDS,
        "jti": uuid.uuid4().hex,
    }
    if extras:
        payload.update(extras)
    return pyjwt.encode(payload, _JWT_PRIV_PEM, algorithm=JWT_ALG)


def jwt_verify(token: str) -> dict[str, Any]:
    """校验失败抛异常。"""
    return pyjwt.decode(
        token,
        _JWT_PUB_PEM,
        algorithms=[JWT_ALG],
        issuer=JWT_ISSUER,
        options={"require": ["exp", "iat", "sub"]},
    )


# =============================================================================
# 3. HMAC-SHA256 — 审计哈希链 + 请求级 MAC
# =============================================================================
def _load_or_create_hmac_key() -> bytes:
    if not os.path.exists(HMAC_KEY_PATH):
        key = secrets.token_bytes(32)
        with open(HMAC_KEY_PATH, "wb") as f:
            f.write(key)
        os.chmod(HMAC_KEY_PATH, 0o600)
        return key
    with open(HMAC_KEY_PATH, "rb") as f:
        return f.read()


_HMAC_KEY = _load_or_create_hmac_key()


def hmac_sha256_hex(data: bytes) -> str:
    return hmac.new(_HMAC_KEY, data, hashlib.sha256).hexdigest()


def audit_chain_hash(prev_hash: str | None, event_type: str, user_id: int | None,
                     description: str, ip: str, ts: float) -> str:
    """对 (prev_hash || event || user || desc || ip || ts) 做 HMAC-SHA256。

    若任意一行被篡改/删除，链上所有后续 hash 都对不上。
    """
    msg = "|".join([
        prev_hash or "",
        event_type,
        str(user_id) if user_id is not None else "",
        description,
        ip or "",
        f"{ts:.6f}",
    ]).encode("utf-8")
    return hmac_sha256_hex(msg)


# =============================================================================
# 4. TOTP (RFC 6238) — 2FA
# =============================================================================
def generate_totp_secret() -> str:
    """base32 编码的 160-bit secret。"""
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, account: str, issuer: str = "SecurePay") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name=issuer)


def totp_verify(secret: str, code: str) -> bool:
    if not (secret and code):
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


# =============================================================================
# 5. 客户端 ECDSA-P256 签名验证 (抗抵赖)
# =============================================================================
def verify_client_signature(pub_pem: str, signature_der: bytes, message: bytes) -> bool:
    """客户端长期密钥对的公钥(PEM/SPKI) + DER 编码 ECDSA 签名。"""
    try:
        pub = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            return False
        pub.verify(signature_der, message, ec.ECDSA(crypto_hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def transaction_digest(user_id: int, txn_id: str, amount: str, receiver: str,
                       nonce: str, device_fp: str) -> bytes:
    """规范化字符串 → SHA-256，客户端/服务端必须用同一拼法。"""
    canon = "|".join(["v1", str(user_id), txn_id, amount, receiver, nonce, device_fp])
    return hashlib.sha256(canon.encode("utf-8")).digest()


# =============================================================================
# 6. 内存 token-bucket rate limiter (按 key+action)
# =============================================================================
class TokenBucket:
    """简单 token bucket：capacity 个令牌，每 refill_sec 重置。"""

    def __init__(self) -> None:
        self._buckets: dict[str, dict[str, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, action: str, capacity: int, refill_sec: float) -> bool:
        bk = f"{action}:{key}"
        now = time.time()
        with self._lock:
            b = self._buckets.get(bk)
            if not b:
                self._buckets[bk] = {"tokens": capacity - 1, "ts": now, "cap": capacity, "refill": refill_sec}
                return True
            elapsed = now - b["ts"]
            # 持续补充
            refill_amount = (elapsed / b["refill"]) * b["cap"]
            b["tokens"] = min(b["cap"], b["tokens"] + refill_amount)
            b["ts"] = now
            if b["tokens"] >= 1:
                b["tokens"] -= 1
                return True
            return False


limiter = TokenBucket()


# =============================================================================
# 7. 工具函数
# =============================================================================
def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def canonical_request_bytes(method: str, path: str, body_bytes: bytes, nonce: str, ts: str) -> bytes:
    """请求级 HMAC 的规范化输入。"""
    body_hash = hashlib.sha256(body_bytes or b"").hexdigest()
    return f"{method.upper()}\n{path}\n{body_hash}\n{nonce}\n{ts}".encode("utf-8")
