"""出口链路（多级中转）：让 MIMT 自己的出站流量再经过中转代理。

默认链路是「客户端 → MIMT → 目标站」，目标侧看到的是本机公网 IP。
开启链路后变成「客户端 → MIMT → 中转1 → 中转2 → … → 目标站」，
目标侧只能看到最后一跳中转的 IP，本机真实 IP 不再出现在目标日志里。

设计要点
- 逐跳串联：第 1 跳直连，其后每一跳都在上一跳的隧道内发起；每跳可以是
  HTTP/HTTPS 正向代理（CONNECT）或 SOCKS5（含用户名/密码认证）；
- 只把域名交给中转，DNS 由中转侧解析，避免本机 DNS 泄漏；
- 链路失败默认「失败即失败」，不静默回落到直连，防止忘了链路已挂时露出真实 IP；
- 配置热更新：面板保存后对后续请求立即生效，无需重启进程；
- 纯 asyncio + 标准库，无第三方依赖。
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import os
import re
import ssl
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

MAX_HEAD = 64 * 1024
SUPPORTED_SCHEMES = ("http", "https", "socks5", "socks5h")
DEFAULT_PORTS = {"http": 8080, "https": 8443, "socks5": 1080, "socks5h": 1080}

# 探测出口 IP 用。多个候选并行探测，第一个拿到 IP 的即为结果；
# 故意混入不同家，避免某一家的线路被中转出口拉黑时整体失败。
PROBE_URLS = (
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
    "https://api.ipify.org?format=json",
    "http://ip-api.com/json/?fields=query",
)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")


class ChainError(RuntimeError):
    """链路建立或探测失败。"""


# --------------------------------------------------------------------------
# 单跳配置
# --------------------------------------------------------------------------
@dataclass
class Hop:
    scheme: str = "http"
    host: str = ""
    port: int = 0
    username: str = ""
    password: str = ""

    # ---------- 构造 / 序列化 ----------
    def __post_init__(self) -> None:
        self.scheme = (self.scheme or "http").strip().lower()
        self.host = (self.host or "").strip()
        if self.scheme not in SUPPORTED_SCHEMES:
            raise ChainError(f"不支持的中转协议 {self.scheme!r}，可用：{', '.join(SUPPORTED_SCHEMES)}")
        if not self.host:
            raise ChainError("中转地址不能为空")
        if self.host.startswith("[") and self.host.endswith("]"):
            self.host = self.host[1:-1]
        try:
            self.port = int(self.port or DEFAULT_PORTS[self.scheme])
        except (TypeError, ValueError):
            raise ChainError(f"中转端口不合法：{self.port!r}")
        if not 1 <= self.port <= 65535:
            raise ChainError(f"中转端口越界：{self.port}")

    @property
    def is_socks(self) -> bool:
        return self.scheme.startswith("socks")

    @property
    def label(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        auth = f"{self.username}@" if self.username else ""
        return f"{self.scheme}://{auth}{host}:{self.port}"

    def to_dict(self, *, mask: bool = True) -> dict[str, Any]:
        return {
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": ("***" if self.password else "") if mask else self.password,
            "has_password": bool(self.password),
        }

    # ---------- 解析 ----------
    @classmethod
    def parse(cls, spec: Any) -> "Hop":
        """支持 "host:port" / "http://user:pass@host:8080" / "socks5h://host:1080" / dict。"""
        if isinstance(spec, Hop):
            return spec
        if isinstance(spec, dict):
            return cls(
                scheme=spec.get("scheme") or spec.get("type") or "http",
                host=spec.get("host") or spec.get("addr") or "",
                port=spec.get("port") or 0,
                username=spec.get("username") or spec.get("user") or "",
                password=spec.get("password") or spec.get("pass") or "",
            )
        text = str(spec or "").strip()
        if not text:
            raise ChainError("中转地址为空")
        if "://" not in text:
            text = "http://" + text
        u = urlsplit(text)
        return cls(
            scheme=u.scheme or "http",
            host=u.hostname or "",
            port=u.port or 0,
            username=u.username or "",
            password=u.password or "",
        )


def split_hops(spec: str | list | tuple) -> list[Hop]:
    """把 "a:1,b:2" 或列表拆成 Hop 列表（保持顺序＝链路顺序）。"""
    if isinstance(spec, str):
        items = [p for p in re.split(r"[,\s]+", spec.strip()) if p]
    else:
        items = list(spec)
    return [Hop.parse(it) for it in items]


# --------------------------------------------------------------------------
# 链路
# --------------------------------------------------------------------------
@dataclass
class ChainConfig:
    enabled: bool = False
    hops: list[Hop] = field(default_factory=list)
    verify: bool = False          # 校验 HTTPS 中转与探测目标的证书
    timeout: float = 20.0         # 单跳建链超时（秒）
    allow_direct: bool = False    # 链路失败时是否允许回落直连（默认禁止）

    def to_dict(self, *, mask: bool = True) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "hops": [h.to_dict(mask=mask) for h in self.hops],
            "verify": self.verify,
            "timeout": self.timeout,
            "allow_direct": self.allow_direct,
        }


class ProxyChain:
    """可热更新的出口链路。线程安全（配置改动与读取分离）。"""

    def __init__(self, config: ChainConfig | None = None, path: Path | str | None = None):
        self._lock = threading.RLock()
        self._cfg = config or ChainConfig()
        self.path = Path(path).expanduser() if path else None
        # 运行统计
        self.hits = 0
        self.failures = 0
        self.last_error = ""
        self.last_error_ts = 0.0
        self.last_probe: dict[str, Any] = {}

    # ---------------- 配置 ----------------
    @property
    def enabled(self) -> bool:
        return self._cfg.enabled

    @property
    def hops(self) -> tuple[Hop, ...]:
        with self._lock:
            return tuple(self._cfg.hops)

    @property
    def allow_direct(self) -> bool:
        return self._cfg.allow_direct

    @property
    def timeout(self) -> float:
        with self._lock:
            return self._cfg.timeout

    @property
    def verify(self) -> bool:
        return self._cfg.verify

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            data = self._cfg.to_dict(mask=True)
            n = len(self._cfg.hops)
        data.update({
            "active": bool(data["enabled"] and n > 0),
            "hop_count": n,
            "route": self.route_label() or "direct",
            "hits": self.hits,
            "failures": self.failures,
            "last_error": self.last_error,
            "last_error_ts": self.last_error_ts,
            "last_probe": self.last_probe,
            "file": str(self.path) if self.path else "",
        })
        return data

    def route_label(self) -> str:
        hops = self.hops
        if not hops:
            return ""
        return " → ".join(h.label for h in hops)

    def apply(self, payload: dict[str, Any], *, save: bool = True) -> dict[str, Any]:
        """校验并热应用新配置；save=True 时落盘。只有全部校验通过才替换。"""
        with self._lock:
            cur = self._cfg
            enabled = bool(payload.get("enabled", cur.enabled))
            verify = bool(payload.get("verify", cur.verify))
            allow_direct = bool(payload.get("allow_direct", cur.allow_direct))
            try:
                timeout = float(payload.get("timeout", cur.timeout) or cur.timeout)
            except (TypeError, ValueError):
                raise ChainError("超时必须是数字")
            timeout = max(3.0, min(timeout, 120.0))

            raw_hops = payload.get("hops")
            if raw_hops is None:
                new_hops = list(cur.hops)
            else:
                # 面板回传的 "***" 密码表示「保持不变」
                merged: list[Hop] = []
                old = list(cur.hops)
                for idx, item in enumerate(raw_hops):
                    if isinstance(item, dict) and item.get("password") == "***":
                        item = dict(item)
                        if idx < len(old) and old[idx].host == (item.get("host") or old[idx].host):
                            item["password"] = old[idx].password
                        else:
                            item["password"] = ""
                    merged.append(Hop.parse(item))
                new_hops = merged

            self._cfg = ChainConfig(
                enabled=enabled, hops=new_hops, verify=verify,
                timeout=timeout, allow_direct=allow_direct,
            )
            if save:
                self.save()
        return self.snapshot()

    # ---------------- 持久化 ----------------
    def save(self) -> None:
        if not self.path:
            return
        with self._lock:
            data = self._cfg.to_dict(mask=False)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            try:
                os.chmod(tmp, 0o600)   # 含中转密码，仅服务账号可读
            except OSError:
                pass
            tmp.replace(self.path)
        except OSError as exc:
            raise ChainError(f"链路配置写入失败：{exc}")

    def load(self) -> bool:
        if not self.path or not self.path.is_file():
            return False
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        with self._lock:
            try:
                hops = [Hop.parse(h) for h in (data.get("hops") or [])]
            except ChainError:
                return False
            self._cfg = ChainConfig(
                enabled=bool(data.get("enabled")),
                hops=hops,
                verify=bool(data.get("verify")),
                timeout=float(data.get("timeout") or 20.0),
                allow_direct=bool(data.get("allow_direct")),
            )
        return True

    # ---------------- 统计 ----------------
    def note_ok(self) -> None:
        self.hits += 1

    def note_failure(self, exc: Any) -> None:
        self.failures += 1
        self.last_error = f"{type(exc).__name__}: {exc}"
        self.last_error_ts = time.time()

    # ---------------- 建链 ----------------
    def _proxy_tls_ctx(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = self.verify
        ctx.verify_mode = ssl.CERT_REQUIRED if self.verify else ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except NotImplementedError:
            pass
        return ctx

    async def _dial(self, hop: Hop, timeout: float):
        use_tls = hop.scheme == "https"
        ctx = self._proxy_tls_ctx() if use_tls else None
        return await asyncio.wait_for(
            asyncio.open_connection(
                hop.host, hop.port, ssl=ctx,
                server_hostname=hop.host if use_tls else None,
                limit=MAX_HEAD,
            ),
            timeout=timeout,
        )

    async def open_tunnel(self, host: str, port: int, *, timeout: float | None = None):
        """逐跳打洞，返回一条直通 host:port 的明文双向流。

        链路关闭（或无中转）时等价于直连，保证 probe() 在两种状态下都能工作。
        """
        hops = self.hops
        budget = timeout or self.timeout
        if not hops:
            if self.enabled:
                raise ChainError("出口链路已开启，但未配置任何中转地址")
            return await asyncio.wait_for(
                asyncio.open_connection(host, port, limit=MAX_HEAD), timeout=budget)
        reader = writer = None
        try:
            for idx, hop in enumerate(hops):
                if idx + 1 < len(hops):
                    nxt = hops[idx + 1]
                    dst_host, dst_port = nxt.host, nxt.port
                else:
                    dst_host, dst_port = host, port

                if idx == 0:
                    reader, writer = await self._dial(hop, budget)
                if hop.is_socks:
                    await self._socks5_connect(reader, writer, dst_host, dst_port, hop, budget)
                else:
                    await self._http_connect(reader, writer, dst_host, dst_port, hop, budget)
            return reader, writer  # type: ignore[return-value]
        except Exception:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
            raise

    async def open_stream(self, host: str, port: int, use_tls: bool,
                          tls_ctx: ssl.SSLContext | None = None,
                          *, timeout: float | None = None):
        """在链路末端与目标建立流；use_tls 时再做一次客户端 TLS 握手。"""
        reader, writer = await self.open_tunnel(host, port, timeout=timeout)
        if not use_tls:
            return reader, writer
        ctx = tls_ctx or self._proxy_tls_ctx()
        try:
            if hasattr(writer, "start_tls"):
                await writer.start_tls(ctx, server_hostname=host)
            else:  # Python <= 3.10
                loop = asyncio.get_running_loop()
                transport = writer.transport
                protocol = transport.get_protocol()
                new_transport = await loop.start_tls(
                    transport, protocol, ctx, server_side=False, server_hostname=host,
                )
                if new_transport is None:
                    raise ChainError("隧道内 TLS 升级失败")
                writer._transport = new_transport  # type: ignore[attr-defined]
        except Exception:
            try:
                writer.close()
            except Exception:
                pass
            raise
        return reader, writer

    # ---------------- 协议握手 ----------------
    @staticmethod
    async def _http_connect(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                            host: str, port: int, hop: Hop, timeout: float) -> None:
        target = f"{host}:{port}" if ":" not in host else f"[{host}]:{port}"
        lines = [
            f"CONNECT {target} HTTP/1.1",
            f"Host: {target}",
            "Proxy-Connection: keep-alive",
            "User-Agent: MIMT-chain/1.0",
        ]
        if hop.username:
            token = base64.b64encode(
                f"{hop.username}:{hop.password or ''}".encode("utf-8")
            ).decode("ascii")
            lines.append(f"Proxy-Authorization: Basic {token}")
        writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        try:
            await writer.drain()
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
        except asyncio.TimeoutError:
            raise ChainError(f"中转 {hop.label} 响应超时（{timeout:.0f}s）")
        except asyncio.IncompleteReadError:
            raise ChainError(f"中转 {hop.label} 提前关闭连接（可能是端口不通或非 HTTP 代理）")
        first = head.split(b"\r\n", 1)[0].decode("latin-1", "replace").strip()
        code = 0
        parts = first.split(" ")
        if len(parts) >= 2 and parts[1].isdigit():
            code = int(parts[1])
        if code == 407:
            raise ChainError(f"中转 {hop.label} 要求代理认证（407），请检查用户名/密码")
        if code == 401:
            raise ChainError(f"中转 {hop.label} 返回 401，凭据可能无效")
        if code != 200:
            raise ChainError(f"中转 {hop.label} 拒绝 CONNECT {target}：{first or '无响应状态行'}")

    @staticmethod
    async def _socks5_connect(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                              host: str, port: int, hop: Hop, timeout: float) -> None:
        async def read(n: int) -> bytes:
            try:
                return await asyncio.wait_for(reader.readexactly(n), timeout=timeout)
            except asyncio.TimeoutError:
                raise ChainError(f"SOCKS5 中转 {hop.label} 响应超时（{timeout:.0f}s）")
            except asyncio.IncompleteReadError:
                raise ChainError(f"SOCKS5 中转 {hop.label} 提前关闭连接")

        methods = b"\x00\x02" if hop.username else b"\x00"
        writer.write(b"\x05" + bytes([len(methods)]) + methods)
        await writer.drain()
        ver, method = await read(2)
        if ver != 5:
            raise ChainError(f"中转 {hop.label} 不是 SOCKS5（首字节 {ver:#x}）")
        if method == 0xFF:
            raise ChainError(f"SOCKS5 中转 {hop.label} 拒绝了所有认证方式")
        if method == 0x02:
            if not hop.username:
                raise ChainError(f"SOCKS5 中转 {hop.label} 要求用户名/密码，但未配置")
            u = hop.username.encode("utf-8")[:255]
            p = (hop.password or "").encode("utf-8")[:255]
            writer.write(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            await writer.drain()
            _, status = await read(2)
            if status != 0:
                raise ChainError(f"SOCKS5 中转 {hop.label} 用户名/密码认证失败")
        elif method != 0x00:
            raise ChainError(f"SOCKS5 中转 {hop.label} 使用了不支持的认证方式 {method:#x}")

        try:  # 域名一律交给中转解析（等价 socks5h），避免本机 DNS 泄漏
            ip = ipaddress.ip_address(host)
            atyp = b"\x01" if ip.version == 4 else b"\x04"
            addr = ip.packed
        except ValueError:
            hb = host.encode("idna") if not host.isascii() else host.encode("ascii")
            if len(hb) > 255:
                raise ChainError(f"目标域名过长：{host}")
            atyp = b"\x03"
            addr = bytes([len(hb)]) + hb
        writer.write(b"\x05\x01\x00" + atyp + addr + struct.pack("!H", int(port)))
        await writer.drain()
        ver, rep, _, addr_type = await read(4)
        if ver != 5:
            raise ChainError(f"SOCKS5 中转 {hop.label} 响应异常")
        if rep != 0:
            reason = {
                1: "一般性失败", 2: "规则不允许", 3: "网络不可达", 4: "主机不可达",
                5: "连接被拒绝", 6: "TTL 过期", 7: "不支持的命令", 8: "不支持的地址类型",
            }.get(rep, f"错误码 {rep}")
            raise ChainError(f"SOCKS5 中转 {hop.label} 无法连接 {host}:{port}（{reason}）")
        if addr_type == 0x01:
            await read(4 + 2)
        elif addr_type == 0x03:
            n = (await read(1))[0]
            await read(n + 2)
        elif addr_type == 0x04:
            await read(16 + 2)

    # ---------------- 探测 ----------------
    async def probe(self, url: str | None = None, *, timeout: float | None = None,
                    compare_direct: bool = True) -> dict[str, Any]:
        """沿链路访问出口 IP 接口，返回链路出口 IP（可选同时给直连出口 IP 作对照）。

        候选接口并行探测，谁先返回用谁：串行会让一次探测最坏耗时
        候选数 × 单跳超时（实测 40s+），并行后约等于最慢一次。
        """
        budget = timeout or self.timeout
        started = time.time()
        candidates = [url] if url else list(PROBE_URLS)

        async def try_one(target: str):
            return target, await self._http_get_via_chain(target, budget)

        chain_ip: str | None = None
        chain_http: dict[str, Any] = {}
        errors: list[str] = []

        tasks = [asyncio.create_task(try_one(u)) for u in candidates]
        direct_task = (asyncio.create_task(direct_exit_ip(budget))
                       if compare_direct else None)
        try:
            pending = set(tasks)
            while pending and chain_ip is None:
                done, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    try:
                        target, res = task.result()
                    except Exception as exc:
                        continue
                    ip = _extract_ip(res.get("body", ""))
                    if ip and chain_ip is None:
                        chain_ip = ip
                        chain_http = res
                    else:
                        errors.append(f"{target} → 响应中没有 IP")
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            if direct_task is not None:
                try:
                    direct_ip = await asyncio.wait_for(direct_task, timeout=budget)
                except Exception as exc:
                    direct_ip = None
                    errors.append(f"直连对照失败：{type(exc).__name__}: {exc}")
            else:
                direct_ip = None
        if chain_ip is None and not errors:
            errors.append("所有探测接口均未返回有效 IP")
        if chain_ip is None:
            for task in tasks:
                if task.done() and task.exception() is not None:
                    tgt = candidates[tasks.index(task)]
                    exc = task.exception()
                    errors.append(f"{tgt} → {type(exc).__name__}: {exc}")

        result = {
            "ok": bool(chain_ip),
            "chain_exit_ip": chain_ip,
            "direct_exit_ip": direct_ip,
            "hidden": bool(chain_ip and direct_ip and chain_ip != direct_ip),
            "route": self.route_label() or "direct",
            "enabled": self.enabled,
            "via_chain": bool(self.enabled and self.hops),
            "hop_count": len(self.hops),
            "status": chain_http.get("status"),
            "probe_url": chain_http.get("url", ""),
            "elapsed_ms": round((time.time() - started) * 1000, 1),
            "errors": errors,
        }
        self.last_probe = result
        if chain_ip:
            self.note_ok()
        else:
            self.note_failure(ChainError("; ".join(errors[-2:]) or "链路探测失败"))
        return result

    async def _http_get_via_chain(self, url: str, timeout: float) -> dict[str, Any]:
        u = urlsplit(url)
        scheme = u.scheme or "https"
        host = u.hostname or ""
        port = u.port or (443 if scheme == "https" else 80)
        path = (u.path or "/") + ("?" + u.query if u.query else "")
        ctx = self._proxy_tls_ctx() if scheme == "https" else None
        reader, writer = await self.open_stream(
            host, port, scheme == "https", ctx, timeout=timeout)
        try:
            req = (
                f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                "User-Agent: MIMT-chain-probe/1.0\r\nAccept: */*\r\n"
                "Connection: close\r\n\r\n"
            )
            writer.write(req.encode("latin-1"))
            await writer.drain()
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
            status = 0
            first = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            parts = first.split(" ")
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])
            body = bytearray()
            while len(body) < 8192:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if not chunk:
                    break
                body += chunk
            return {"url": url, "status": status,
                    "body": bytes(body).decode("utf-8", "replace")}
        finally:
            try:
                writer.close()
            except Exception:
                pass


def _extract_ip(text: str) -> str | None:
    if not text:
        return None
    text = text.strip()
    if text.startswith("{"):
        try:
            data = json.loads(text)
            for key in ("ip", "query", "origin", "address"):
                val = data.get(key)
                if isinstance(val, str) and val.strip():
                    return val.split(",")[0].strip()
        except json.JSONDecodeError:
            pass
    m = _IPV4_RE.search(text)
    if m:
        return m.group(0)
    m = _IPV6_RE.search(text)
    if m:
        return m.group(0)
    return None


async def direct_exit_ip(timeout: float = 10.0, url: str = PROBE_URLS[0]) -> str | None:
    """不经中转直接查本机出口 IP，用于证明链路确实换掉了出口。"""
    u = urlsplit(url)
    scheme = u.scheme or "https"
    host = u.hostname or ""
    port = u.port or (443 if scheme == "https" else 80)
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    ctx = None
    if scheme == "https":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx,
                                server_hostname=host if ctx else None),
        timeout=timeout)
    try:
        writer.write((
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
            "User-Agent: MIMT-direct-probe/1.0\r\nAccept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("latin-1"))
        await writer.drain()
        await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
        body = bytearray()
        while len(body) < 8192:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            if not chunk:
                break
            body += chunk
        return _extract_ip(bytes(body).decode("utf-8", "replace"))
    finally:
        try:
            writer.close()
        except Exception:
            pass
