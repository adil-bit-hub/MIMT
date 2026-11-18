"""ProxyScope 重放模块：按修改后的请求重新发一次，并把这次流量入库。

用于漏洞复现：在面板里改方法 / 路径 / Header / Body 后重发，
新流量会作为一条新记录出现在列表里（client_addr 标注为 replay）。

特性：
  * 支持 http / https，自带 CA 校验开关（默认不校验，方便打自签名站点）
  * 逐跳头（Connection / Transfer-Encoding 等）自动剥离
  * 自动重算 Content-Length
  * 有界超时，避免面板被慢站点拖死
"""
from __future__ import annotations

import asyncio
import json
import ssl
import time
from typing import Any
from urllib.parse import urlsplit

MAX_BODY = 2 * 1024 * 1024
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length", "host",
}


def _split_headers(raw: Any) -> list[tuple[str, str]]:
    """把三种可能的 header 表示统一成 [(k, v), ...]。"""
    if not raw:
        return []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            out = []
            for line in raw.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    out.append((k.strip(), v.strip()))
            return out
    out: list[tuple[str, str]] = []
    if isinstance(raw, dict):
        for k, v in raw.items():
            out.append((str(k), str(v)))
    elif isinstance(raw, (list, tuple)):
        for item in raw:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                out.append((str(item[0]), str(item[1])))
            elif isinstance(item, str) and ":" in item:
                k, _, v = item.partition(":")
                out.append((k.strip(), v.strip()))
    return out


async def _read_head(reader: asyncio.StreamReader) -> bytes:
    return await reader.readuntil(b"\r\n\r\n")


def _parse_status(head: bytes) -> tuple[int, str]:
    line = head.split(b"\r\n", 1)[0].decode("latin-1")
    parts = line.split(" ", 2)
    try:
        code = int(parts[1])
    except (IndexError, ValueError):
        code = 0
    text = parts[2] if len(parts) > 2 else ""
    return code, text


def _parse_headers(head: bytes) -> list[tuple[str, str]]:
    out = []
    for line in head.split(b"\r\n")[1:]:
        if not line:
            break
        if b":" in line:
            k, _, v = line.partition(b":")
            out.append((k.decode("latin-1").strip(), v.decode("latin-1").strip()))
    return out


async def _read_resp_body(reader: asyncio.StreamReader,
                          headers: list[tuple[str, str]]) -> bytes:
    hmap = {k.lower(): v for k, v in headers}
    if hmap.get("transfer-encoding", "").lower() == "chunked":
        buf = bytearray()
        while True:
            try:
                line = await reader.readuntil(b"\r\n")
            except asyncio.IncompleteReadError:
                break
            size_s = line.strip().split(b";")[0]
            try:
                size = int(size_s, 16)
            except ValueError:
                break
            if size == 0:
                break
            try:
                buf += await reader.readexactly(size)
            except asyncio.IncompleteReadError:
                break
            try:
                await reader.readexactly(2)
            except asyncio.IncompleteReadError:
                break
            if len(buf) > MAX_BODY:
                break
        return bytes(buf)

    cl = hmap.get("content-length")
    if cl and cl.isdigit():
        want = min(int(cl), MAX_BODY)
        try:
            return await reader.readexactly(want)
        except asyncio.IncompleteReadError as exc:
            return exc.partial

    # 无长度：读到 EOF
    buf = bytearray()
    while len(buf) < MAX_BODY:
        try:
            chunk = await reader.read(65536)
        except Exception:
            break
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


async def replay_request(flow: dict[str, Any], store: Any, *,
                         method: str | None = None,
                         url: str | None = None,
                         headers: Any = None,
                         body: Any = None,
                         timeout: float = 30.0,
                         verify: bool = False) -> dict[str, Any]:
    """执行一次重放，返回本次响应摘要，并写入 store。"""
    started = time.time()

    # ---- 1. 解析目标 ----
    orig_scheme = flow.get("scheme") or "https"
    orig_host = flow.get("host") or ""
    orig_port = int(flow.get("port") or (443 if orig_scheme == "https" else 80))
    orig_path = flow.get("path") or "/"
    orig_query = flow.get("query") or ""

    if url:
        p = urlsplit(url if "://" in url else f"{orig_scheme}://{url}")
        scheme = p.scheme or orig_scheme
        host = p.hostname or orig_host
        port = p.port or (443 if scheme == "https" else 80)
        path = p.path or "/"
        query = p.query
    else:
        scheme = orig_scheme
        host = orig_host
        port = orig_port
        path = orig_path
        query = orig_query

    method = (method or flow.get("method") or "GET").upper()

    # ---- 2. 组装头 ----
    src_headers = _split_headers(headers) if headers is not None \
        else _split_headers(flow.get("req_headers"))
    out: list[tuple[str, str]] = [(k, v) for k, v in src_headers
                                  if k.lower() not in HOP_BY_HOP]

    if body is None:
        body_bytes = flow.get("req_body") or b""
        if isinstance(body_bytes, str):
            body_bytes = body_bytes.encode()
    else:
        body_bytes = body.encode() if isinstance(body, str) else bytes(body)

    default_host = host if port in (80, 443) else f"{host}:{port}"
    if not any(k.lower() == "host" for k, _ in out):
        out.insert(0, ("Host", default_host))

    if body_bytes:
        out.append(("Content-Length", str(len(body_bytes))))
    elif method in ("POST", "PUT", "PATCH"):
        out.append(("Content-Length", "0"))
    out.append(("Connection", "close"))

    target = path + ("?" + query if query else "")
    head = f"{method} {target} HTTP/1.1\r\n" + "".join(
        f"{k}: {v}\r\n" for k, v in out) + "\r\n"

    # ---- 3. 发起 ----
    resp_status = 0
    resp_text = ""
    resp_headers: list[tuple[str, str]] = []
    resp_body = b""
    error = ""

    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
                timeout=timeout)
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout)

        try:
            writer.write(head.encode("latin-1") + body_bytes)
            await writer.drain()
            raw_head = await asyncio.wait_for(_read_head(reader), timeout=timeout)
            resp_status, resp_text = _parse_status(raw_head)
            resp_headers = _parse_headers(raw_head)
            resp_body = await asyncio.wait_for(
                _read_resp_body(reader, resp_headers), timeout=timeout)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    except asyncio.TimeoutError:
        error = f"重放超时（{timeout}s）"
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    duration_ms = (time.time() - started) * 1000

    # ---- 4. 入库 ----
    hmap = {k.lower(): v for k, v in resp_headers}
    mime = (hmap.get("content-type") or "").split(";")[0].strip()

    record = {
        "ts": started,
        "scheme": scheme,
        "method": method,
        "host": host,
        "port": port,
        "path": path or "/",
        "query": query,
        "http_version": "HTTP/1.1",
        "status": resp_status or None,
        "status_text": resp_text,
        "mime": mime,
        "req_headers": [[k, v] for k, v in out],
        "req_body": body_bytes or None,
        "resp_headers": [[k, v] for k, v in resp_headers],
        "resp_body": resp_body or None,
        "duration_ms": duration_ms,
        "tls": 1 if scheme == "https" else 0,
        "client_addr": "replay",
        "error": error,
        "note": "replay",
    }
    try:
        new_id = store.add(record)
    except Exception as exc:
        new_id = None
        error = error or f"入库失败: {exc}"

    return {
        "ok": not error,
        "id": new_id,
        "status": resp_status or None,
        "status_text": resp_text,
        "mime": mime,
        "duration_ms": round(duration_ms, 1),
        "resp_size": len(resp_body),
        "error": error,
        "target": f"{scheme}://{host}{'' if port in (80,443) else ':'+str(port)}{target}",
    }
