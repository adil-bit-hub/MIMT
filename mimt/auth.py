"""MIMT 内置认证模块。

统一管理「代理端口」与「Web 面板」的凭据，数据落盘为 data/auth.json：
    {
      "proxy": {"username": "...", "password_hash": "pbkdf2_sha256$...", "enabled": true},
      "panel": {"username": "...", "password_hash": "...", "enabled": true}
    }

密码使用 PBKDF2-HMAC-SHA256 + 随机盐，不存明文。
兼容旧版明文配置（首次加载时自动迁移为哈希）。
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path

# 240000 轮在 2C 云主机上单次要 ~160ms，每个请求都算会让面板明显卡顿。
# 降到 120000 仍远高于 OWASP 最低要求，配合下面的结果缓存，正常使用几乎无感知。
PBKDF2_ROUNDS = 120_000
_ITER_SEP = "$"


def hash_password(password: str, *, rounds: int = PBKDF2_ROUNDS) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return _ITER_SEP.join(["pbkdf2_sha256", str(rounds),
                           salt.hex(), dk.hex()])


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, rounds_s, salt_hex, hash_hex = stored.split(_ITER_SEP)
        if algo != "pbkdf2_sha256":
            return False
        rounds = int(rounds_s)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 bytes.fromhex(salt_hex), rounds)
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


# ── 可逆加密：仅用于拼装「完整代理地址」，不替代校验用的哈希 ──
_KEY_FILE_NAME = "auth.key"


def _load_or_create_key(path) -> bytes:
    from pathlib import Path
    kp = Path(path).parent / _KEY_FILE_NAME
    if kp.exists():
        try:
            data = kp.read_bytes()
            if len(data) >= 32:
                return data[:32]
        except OSError:
            pass
    key = secrets.token_bytes(32)
    try:
        kp.write_bytes(key)
        os.chmod(kp, 0o600)
    except OSError:
        pass
    return key


def _xor_stream(data: bytes, key: bytes) -> bytes:
    """简单流加密（XOR + SHA256 派生），足够防止文件被直接读取。"""
    out = bytearray()
    counter = 0
    while len(out) < len(data):
        block = hashlib.sha256(key + counter.to_bytes(8, "big")).digest()
        out.extend(block)
        counter += 1
    return bytes(a ^ b for a, b in zip(data, out))


def _parse_basic(header_value: str) -> tuple[str, str] | None:
    """解析 'Basic base64(user:pass)'。"""
    if not header_value:
        return None
    parts = header_value.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "basic":
        return None
    try:
        raw = base64.b64decode(parts[1].strip(), validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if ":" not in text:
        return None
    user, _, pw = text.partition(":")
    return user, pw


class AuthStore:
    """代理 / 面板两套凭据的读写与校验。线程安全。"""

    def __init__(self, path: os.PathLike | str | Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._verify_cache: dict[tuple[str, str, str], str] = {}
        self._cache_max = 256
        self._key = _load_or_create_key(self.path)
        self._data: dict[str, dict] = {
            "proxy": {"username": "", "password_hash": "", "enabled": False},
            "panel": {"username": "", "password_hash": "", "enabled": False},
        }
        self.load()

    # ---------------- 持久化 ----------------
    def load(self) -> None:
        with self._lock:
            if not self.path.exists():
                return
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                return
            for scope in ("proxy", "panel"):
                node = raw.get(scope) or {}
                if node:
                    self._data[scope] = {
                        "username": node.get("username", ""),
                        "password_hash": node.get("password_hash", ""),
                        "password_enc": node.get("password_enc", ""),
                        "enabled": bool(node.get("enabled", False)),
                    }

    def save(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data, ensure_ascii=False, indent=2),
                           encoding="utf-8")
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            tmp.replace(self.path)

    # ---------------- 查询 ----------------
    def enabled(self, scope: str) -> bool:
        with self._lock:
            node = self._data.get(scope) or {}
            return bool(node.get("enabled") and node.get("username")
                        and node.get("password_hash"))

    def username(self, scope: str) -> str:
        with self._lock:
            return (self._data.get(scope) or {}).get("username", "")

    def summary(self, scope: str) -> dict:
        with self._lock:
            node = self._data.get(scope) or {}
            return {"enabled": self.enabled(scope),
                    "username": node.get("username", "")}

    def plain_password(self, scope: str) -> str:
        """取出可用的明文密码（用于拼装完整代理地址）。"""
        import base64
        with self._lock:
            node = self._data.get(scope) or {}
            enc = node.get("password_enc") or ""
            if not enc:
                return ""
            try:
                return _xor_stream(base64.b64decode(enc), self._key).decode("utf-8")
            except Exception:
                return ""

    # ---------------- 校验 ----------------
    def check(self, scope: str, username: str, password: str) -> bool:
        with self._lock:
            node = self._data.get(scope) or {}
            if not (node.get("enabled") and node.get("password_hash")):
                return True  # 未启用认证视为放行
            if not hmac.compare_digest(node.get("username", ""), username or ""):
                return False
            stored = node["password_hash"]
            key = (scope, username or "", password or "")
            if self._verify_cache.get(key) == stored:
                return True
            if not verify_password(password or "", stored):
                return False
            if len(self._verify_cache) >= self._cache_max:
                self._verify_cache.clear()
            self._verify_cache[key] = stored
            return True

    def check_basic(self, scope: str, header_value: str | None) -> tuple[bool, str]:
        """返回 (是否通过, 失败原因)。"""
        if not self.enabled(scope):
            return True, ""
        parsed = _parse_basic(header_value or "")
        if not parsed:
            return False, "缺少或格式错误的 Proxy-Authorization / Authorization"
        user, pw = parsed
        if not self.check(scope, user, pw):
            return False, "用户名或密码错误"
        return True, ""

    # ---------------- 修改 ----------------
    def set_credentials(self, scope: str, username: str, password: str,
                        *, enabled: bool = True) -> None:
        with self._lock:
            import base64
            self._data[scope] = {
                "username": (username or "").strip(),
                "password_hash": hash_password(password),
                # 密文仅供「复制完整代理地址」使用，与校验哈希相互独立
                "password_enc": base64.b64encode(
                    _xor_stream(password.encode("utf-8"), self._key)
                ).decode("ascii"),
                "enabled": bool(enabled),
            }
            self._verify_cache.clear()
            self.save()

    def set_enabled(self, scope: str, enabled: bool) -> bool:
        with self._lock:
            node = self._data.get(scope) or {}
            if enabled and not (node.get("username") and node.get("password_hash")):
                return False
            node["enabled"] = bool(enabled)
            self._data[scope] = node
            self.save()
            return True

    def clear(self, scope: str) -> None:
        with self._lock:
            self._data[scope] = {"username": "", "password_hash": "", "enabled": False}
            self._verify_cache.clear()
            self.save()
