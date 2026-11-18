"""Web 服务：本地 HTTP 界面 + REST API，用于检索已抓取的流量。

零第三方依赖，基于 http.server.ThreadingHTTPServer。
"""
from __future__ import annotations

import base64
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .replay import replay_request
from .store import FlowStore

STATIC_DIR = Path(__file__).parent / "static"


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "ProxyScope/1.0"
    protocol_version = "HTTP/1.1"

    store: FlowStore
    proxy_stats = None

    # ---------------- 基础 ----------------
    def setup(self):
        """禁用 Nagle，避免小响应被 delayed-ACK 拖慢 160ms。"""
        super().setup()
        try:
            import socket as _sock
            self.connection.setsockopt(_sock.IPPROTO_TCP, _sock.TCP_NODELAY, 1)
        except (OSError, AttributeError):
            pass

    def finish(self):
        try:
            self.connection.setsockopt(
                __import__("socket").IPPROTO_TCP,
                __import__("socket").TCP_NODELAY, 1)
        except Exception:
            pass
        super().finish()

    def address_string(self) -> str:
        """覆盖默认实现：避免 socket.getfqdn() 反向 DNS 拖慢每个请求。"""
        return self.client_address[0] if self.client_address else "-"

    def log_message(self, fmt, *args):  # 静音
        if getattr(self.server, "verbose", False):
            super().log_message(fmt, *args)

    def _send(self, code: int, body: bytes, ctype: str,
              extra: dict[str, str] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _json(self, data, code: int = 200) -> None:
        self._send(code, json.dumps(data, ensure_ascii=False, default=str).encode(),
                   "application/json; charset=utf-8")

    def _err(self, msg: str, code: int = 400) -> None:
        self._json({"error": msg}, code)

    # ---------------- 服务控制 ----------------
    SERVICE_UNIT = "proxyscope.service"

    def _service_status(self) -> dict:
        import subprocess
        out = {"active": False, "state": "unknown", "pid": None,
               "since": None, "uptime": None}
        try:
            p = subprocess.run(
                ["systemctl", "show", self.SERVICE_UNIT,
                 "-p", "ActiveState", "-p", "MainPID", "-p", "ActiveEnterTimestamp"],
                capture_output=True, timeout=5, text=True)
            kv = {}
            for line in p.stdout.splitlines():
                if "=" in line:
                    k, _, v = line.partition("=")
                    kv[k.strip()] = v.strip()
            state = kv.get("ActiveState", "unknown")
            pid = kv.get("MainPID", "0")
            out["state"] = state
            out["active"] = state == "active"
            out["pid"] = int(pid) if pid.isdigit() and pid != "0" else None
            ts = kv.get("ActiveEnterTimestamp", "")
            if ts and ts != "n/a":
                out["since"] = ts
        except Exception as exc:
            out["error"] = str(exc)
        return out

    def _service_action(self, action: str) -> str:
        """用 systemd-run 脱离当前进程执行，避免重启时把自己杀掉而中断响应。"""
        import subprocess
        unit = self.SERVICE_UNIT
        if action == "stop":
            # 停止会杀掉自己，所以先应答、后执行
            subprocess.Popen(
                ["systemd-run", "--quiet", "--collect", "--on-active=2s",
                 "/bin/systemctl", "stop", unit],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return "停止指令已下发，服务将在 2 秒内停止"
        if action == "restart":
            subprocess.Popen(
                ["systemd-run", "--quiet", "--collect", "--on-active=2s",
                 "/bin/systemctl", "restart", unit],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return "重启指令已下发，服务将在数秒内恢复"
        # start：服务已在运行则无意义
        st = self._service_status()
        if st.get("active"):
            return "服务已在运行中"
        subprocess.Popen(
            ["systemd-run", "--quiet", "--collect", "--on-active=1s",
             "/bin/systemctl", "start", unit],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return "启动指令已下发"

    def _run_replay(self, flow, **kwargs):
        """在同步 handler 里跑一次 async 重放。"""
        import asyncio
        return asyncio.run(replay_request(flow, self.store, **kwargs))

    # ---------------- 面板认证 ----------------
    def _auth_check(self) -> bool:
        """返回 True 表示放行；False 表示已回 401，调用方应直接 return。"""
        auth_store = getattr(self.server, "auth", None)
        if auth_store is None or not auth_store.enabled("panel"):
            return True
        hdr = self.headers.get("Authorization")
        ok, reason = auth_store.check_basic("panel", hdr)
        if ok:
            return True
        body = json.dumps({"error": reason, "auth_required": True},
                          ensure_ascii=False).encode()
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="ProxyScope"')
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        return False

    # ---------------- 路由 ----------------
    def do_GET(self):
        if not self._auth_check():
            return
        url = urlsplit(self.path)
        qs = parse_qs(url.query, keep_blank_values=True)
        path = url.path

        if path in ("/", "/index.html"):
            return self._static("index.html", "text/html; charset=utf-8")
        if path.startswith("/static/"):
            return self._static(path[len("/static/"):])
        if path == "/api/flows":
            return self._api_list(qs)
        if path.startswith("/api/flows/"):
            return self._api_detail(path)
        if path == "/api/stats":
            return self._json({
                "store": self.store.stats(),
                "proxy": (self.proxy_stats() if self.proxy_stats else {}),
            })
        if path == "/api/ca.crt":
            ca = getattr(self.server, "ca_pem", None)
            if not ca:
                return self._err("CA 未启用", 404)
            return self._send(200, ca, "application/x-x509-ca-cert", {
                "Content-Disposition": 'attachment; filename="proxyscope-ca.crt"'
            })
        if path == "/api/auth":
            a = getattr(self.server, "auth", None)
            if a is None:
                return self._json({"proxy": {"enabled": False, "username": ""},
                                   "panel": {"enabled": False, "username": ""}})
            payload = {"proxy": a.summary("proxy"), "panel": a.summary("panel")}
            return self._json(payload)
        if path == "/api/proxy-url":
            # 返回可用于复制的完整代理地址（含明文密码）。
            # 该接口与面板同权限（需 Basic 认证），仅本机回环服务暴露。
            a = getattr(self.server, "auth", None)
            if a is None or not a.enabled("proxy"):
                return self._json({"url": "", "reason": "代理认证未启用"})
            user = a.username("proxy")
            pw = a.plain_password("proxy")
            if not pw:
                return self._json({"url": "", "reason": "密码不可用"})
            port = getattr(self.server, "proxy_port", 18888) or 18888
            host = self.headers.get("X-Real-IP") or "127.0.0.1"
            fwd = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or ""
            pub_host = fwd.split(":")[0] if fwd else self.server.server_address[0]
            if pub_host in ("127.0.0.1", "localhost", "::1") and fwd:
                pub_host = fwd.split(":")[0]
            return self._json({
                "url": f"http://{user}:{pw}@{pub_host}:{port}",
                "user": user,
                "host": pub_host,
                "port": port,
            })
        if path == "/api/service":
            return self._json(self._service_status())
        if path == "/api/ca.crl":
            pem = b""
            ca = getattr(self.server, "ca", None)
            if ca is not None:
                try:
                    pem = ca.crl_pem()
                except Exception:
                    pem = b""
            if not pem:
                return self._err("CRL 未启用（需设置 PROXYSCOPE_CRL_URL）", 404)
            return self._send(200, pem, "application/pkix-crl", {
                "Content-Disposition": 'attachment; filename="proxyscope-ca.crl"'
            })
        if path == "/api/health":
            return self._json({"ok": True, "ts": time.time()})
        return self._err("not found", 404)

    def do_POST(self):
        if not self._auth_check():
            return
        url = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            payload = {}

        if url.path == "/api/flows/delete":
            ids = payload.get("ids") or []
            return self._json({"deleted": self.store.delete(ids)})
        if url.path == "/api/flows/clear":
            self.store.clear()
            return self._json({"ok": True})
        if url.path == "/api/flows/replay":
            fid = payload.get("id")
            if fid is None:
                return self._err("缺少 id", 400)
            try:
                fid = int(fid)
            except (TypeError, ValueError):
                return self._err("id 必须是整数", 400)
            flow = self.store.get(fid)
            if flow is None:
                return self._err("原记录不存在", 404)
            try:
                timeout = float(payload.get("timeout") or 30)
            except (TypeError, ValueError):
                timeout = 30.0
            timeout = max(1.0, min(timeout, 120.0))
            try:
                result = self._run_replay(
                    flow,
                    method=payload.get("method"),
                    url=payload.get("url"),
                    headers=payload.get("headers"),
                    body=payload.get("body"),
                    timeout=timeout,
                    verify=bool(payload.get("verify")),
                )
            except Exception as exc:
                return self._err(f"重放失败: {exc}", 500)
            return self._json(result)
        if url.path == "/api/service":
            action = (payload.get("action") or "").strip()
            if action not in ("start", "stop", "restart"):
                return self._err("action 必须是 start / stop / restart", 400)
            try:
                msg = self._service_action(action)
            except Exception as exc:
                return self._err(f"操作失败: {exc}", 500)
            return self._json({"ok": True, "action": action, "msg": msg})
        if url.path == "/api/auth/set":
            a = getattr(self.server, "auth", None)
            if a is None:
                return self._err("认证模块未启用", 500)
            scope = (payload.get("scope") or "").strip()
            if scope not in ("proxy", "panel"):
                return self._err("scope 必须是 proxy 或 panel", 400)
            user = (payload.get("username") or "").strip()
            pw = payload.get("password") or ""
            if not user or len(pw) < 6:
                return self._err("用户名不能为空、密码至少 6 位", 400)
            en = payload.get("enabled", True)
            a.set_credentials(scope, user, pw, enabled=bool(en))
            return self._json({"ok": True, "scope": scope, "summary": a.summary(scope)})
        if url.path == "/api/auth/toggle":
            a = getattr(self.server, "auth", None)
            if a is None:
                return self._err("认证模块未启用", 500)
            scope = (payload.get("scope") or "").strip()
            if scope not in ("proxy", "panel"):
                return self._err("scope 必须是 proxy 或 panel", 400)
            en = bool(payload.get("enabled", True))
            ok = a.set_enabled(scope, en)
            if not ok:
                return self._err("请先设置该范围的账号密码，再启用认证", 400)
            return self._json({"ok": True, "scope": scope, "summary": a.summary(scope)})
        if url.path == "/api/auth/clear":
            a = getattr(self.server, "auth", None)
            if a is None:
                return self._err("认证模块未启用", 500)
            scope = (payload.get("scope") or "").strip()
            if scope not in ("proxy", "panel"):
                return self._err("scope 必须是 proxy 或 panel", 400)
            a.clear(scope)
            return self._json({"ok": True, "scope": scope})
        return self._err("not found", 404)

    def do_HEAD(self):
        self.do_GET()

    # ---------------- 具体实现 ----------------
    def _static(self, rel: str, ctype: str | None = None) -> None:
        target = (STATIC_DIR / rel).resolve()
        if not str(target).startswith(str(STATIC_DIR.resolve())) or not target.is_file():
            return self._err("not found", 404)
        if ctype is None:
            ctype = {
                ".html": "text/html; charset=utf-8",
                ".js": "application/javascript; charset=utf-8",
                ".css": "text/css; charset=utf-8",
                ".svg": "image/svg+xml",
                ".png": "image/png",
                ".ico": "image/x-icon",
            }.get(target.suffix.lower(), "application/octet-stream")
        self._send(200, target.read_bytes(), ctype)

    def _api_list(self, qs: dict[str, list[str]]) -> None:
        def g(name: str, default: str = "") -> str:
            return (qs.get(name) or [default])[0]

        def f(name: str) -> float | None:
            raw = g(name)
            if not raw:
                return None
            try:
                return float(raw)
            except ValueError:
                return None

        try:
            limit = int(g("limit", "100") or 100)
            offset = int(g("offset", "0") or 0)
        except ValueError:
            return self._err("limit/offset 需要整数")
        data = self.store.list(
            q=g("q"), host=g("host"), method=g("method"), status=g("status"),
            scheme=g("scheme"), mime=g("mime"),
            since=f("since"), until=f("until"),
            limit=limit, offset=offset, order=g("order", "id_desc"),
        )
        return self._json(data)

    def _api_detail(self, path: str) -> None:
        tail = path[len("/api/flows/"):].strip("/")
        if not tail.isdigit():
            return self._err("无效 id", 400)
        flow = self.store.get(int(tail))
        if flow is None:
            return self._err("记录不存在", 404)
        return self._json(flow)


class ThreadingHTTPServerQuiet(ThreadingHTTPServer):
    """吞掉浏览器预连接/关闭引发的 ConnectionResetError，避免刷屏。"""

    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError,
                            BrokenPipeError, TimeoutError)):
            return
        super().handle_error(request, client_address)


class WebUI:
    def __init__(self, store: FlowStore, host: str = "127.0.0.1",
                 port: int = 8787, ca_pem: bytes | None = None,
                 proxy_stats=None, verbose: bool = False, auth=None,
                 ca=None):
        self.store = store
        self.auth = auth
        self.ca = ca
        self.host = host
        self.port = port
        self.ca_pem = ca_pem
        self.proxy_stats = proxy_stats
        self.verbose = verbose
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        handler = type("Handler", (ApiHandler,), {
            "store": self.store,
            "proxy_stats": staticmethod(self.proxy_stats) if self.proxy_stats else None,
        })
        self._httpd = ThreadingHTTPServerQuiet((self.host, self.port), handler)
        self._httpd.daemon_threads = True
        self._httpd.verbose = self.verbose
        self._httpd.ca_pem = self.ca_pem
        self._httpd.auth = self.auth
        self._httpd.ca = self.ca
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, name="proxyscope-web", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
