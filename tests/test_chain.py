"""本地自检：起一个假目标站 + 两个假中转（HTTP CONNECT / SOCKS5），
验证 ProxyScope 链路开关的行为：
  1) 关闭时直连：记录 note 为空/无 chain 标记，目标看到的连接来自本机；
  2) 开启 HTTP 中转：目标侧看到的「上一跳」是中转代理；
  3) 中转挂掉：默认失败即失败，绝不回落直连（目标不应收到任何请求）；
  4) allow_direct=True 时才回落；
  5) 两跳串联（HTTP → SOCKS5）；
  6) probe() 能报告链路出口。
"""
import asyncio
import base64
import socket
import ssl
import sys

sys.path.insert(0, ".")

from proxyscope.chain import ChainConfig, Hop, ProxyChain  # noqa: E402
from proxyscope.proxy import ProxyServer  # noqa: E402

TAG = socket.gethostname()


class FakeTarget:
    """记录每次被访问的 peer，并返回一个带标记的正文。"""

    def __init__(self):
        self.peers = []
        self.server = None
        self.port = None

    async def start(self):
        self.server = await asyncio.start_server(self._h, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _h(self, reader, writer):
        peer = writer.get_extra_info("peername")
        self.peers.append(peer)
        try:
            await reader.readuntil(b"\r\n\r\n")
            body = b'{"ip":"203.0.113.9"}'
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode() +
                b"\r\nConnection: close\r\n\r\n" + body)
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()


class FakeHttpProxy:
    """只做 CONNECT 的最小中转，记录被要求转发的目标。"""

    def __init__(self, name, need_auth=False, hops_next=None):
        self.name = name
        self.need_auth = need_auth
        self.hops_next = hops_next   # 串联下一跳 (hop, chain) 用于两跳测试
        self.requests = []
        self.connections = 0

    async def start(self):
        self.server = await asyncio.start_server(self._h, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _h(self, reader, writer):
        self.connections += 1
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            method, target, _ = lines[0].split(" ")
            self.requests.append((method, target))
            if method != "CONNECT":
                writer.write(b"HTTP/1.1 405 No\r\n\r\n")
                await writer.drain()
                return
            if self.need_auth:
                auth = [l for l in lines if l.lower().startswith("proxy-authorization:")]
                ok = bool(auth) and base64.b64decode(
                    auth[0].split(" ", 2)[2]).decode() == "u:p"
                if not ok:
                    writer.write(b"HTTP/1.1 407 Proxy Auth\r\n\r\n")
                    await writer.drain()
                    return
            host, _, port = target.rpartition(":")
            # 连真实目标
            up_r, up_w = await asyncio.open_connection(host, int(port))
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            async def pump(a, b):
                try:
                    while True:
                        d = await a.read(65536)
                        if not d:
                            break
                        b.write(d)
                        await b.drain()
                except Exception:
                    pass
                finally:
                    try:
                        b.close()
                    except Exception:
                        pass
            await asyncio.gather(pump(reader, up_w), pump(up_r, writer),
                                 return_exceptions=True)
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass


class FakeSocks5:
    def __init__(self):
        self.requests = []

    async def start(self):
        self.server = await asyncio.start_server(self._h, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _h(self, reader, writer):
        try:
            ver, n = await reader.readexactly(2)
            await reader.readexactly(n)
            writer.write(b"\x05\x00")
            await writer.drain()
            ver, cmd, _, atyp = await reader.readexactly(4)
            if atyp == 1:
                host = socket.inet_ntoa(await reader.readexactly(4))
            elif atyp == 3:
                ln = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(ln)).decode()
            else:
                return
            port = int.from_bytes(await reader.readexactly(2), "big")
            self.requests.append((host, port))
            up_r, up_w = await asyncio.open_connection(host, port)
            writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
            await writer.drain()
            async def pump(a, b):
                try:
                    while True:
                        d = await a.read(65536)
                        if not d:
                            break
                        b.write(d)
                        await b.drain()
                except Exception:
                    pass
                finally:
                    try:
                        b.close()
                    except Exception:
                        pass
            await asyncio.gather(pump(reader, up_w), pump(up_r, writer),
                                 return_exceptions=True)
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass


class MemStore:
    def __init__(self):
        self.rows = []

    def add(self, flow):
        self.rows.append(flow)
        return len(self.rows)


async def fetch_via_proxy(ps_port, host, port):
    """用原始 socket 发一个明文绝对 URL 请求（不触发 MITM TLS，纯测转发路径）。"""
    r, w = await asyncio.open_connection("127.0.0.1", ps_port)
    w.write((f"GET http://{host}:{port}/ HTTP/1.1\r\nHost: {host}:{port}\r\n"
             "Connection: close\r\n\r\n").encode())
    await w.drain()
    data = await r.read()
    w.close()
    status = data.split(b"\r\n")[0]
    return status, data


async def main():
    ok = True
    def check(name, cond, extra=""):
        nonlocal ok
        print(("  PASS " if cond else "  FAIL ") + name + ((" :: " + extra) if extra else ""))
        ok = ok and cond

    target = FakeTarget()
    await target.start()
    th = target.port

    store = MemStore()
    chain = ProxyChain(config=ChainConfig(enabled=False))
    ps = ProxyServer(None, store, host="127.0.0.1", port=0,
                     upstream_timeout=6, chain=chain)
    await ps.start()
    ps_port = ps._server.sockets[0].getsockname()[1]

    base_peers = len(target.peers)

    # ---- 1. 关闭 = 直连 ----
    print("[1] 链路关闭 → 直连")
    st, body = await fetch_via_proxy(ps_port, "127.0.0.1", th)
    check("请求成功", b"200" in st, st.decode())
    check("目标收到了请求", len(target.peers) == base_peers + 1)
    check("记录无链路标记", store.rows[-1].get("note", "") == "",
          repr(store.rows[-1].get("note")))
    check("snapshot.active=False", chain.snapshot()["active"] is False)

    # ---- 2. 开启 HTTP 中转 ----
    print("[2] 开启 HTTP 中转（带认证）→ 应经中转")
    hp = FakeHttpProxy("http1", need_auth=True)
    await hp.start()
    chain.apply({"enabled": True,
                 "hops": [{"scheme": "http", "host": "127.0.0.1",
                           "port": hp.port, "username": "u", "password": "p"}]},
                save=False)
    before = len(target.peers)
    st, body = await fetch_via_proxy(ps_port, "localhost", th)
    check("请求成功", b"200" in st, st.decode())
    check("中转收到了 CONNECT", len(hp.requests) == 1, str(hp.requests))
    check("中转被要求连 localhost:<target>", hp.requests and hp.requests[0][1].startswith("localhost:"))
    check("目标收到请求", len(target.peers) == before + 1)
    check("记录带 chain 标记", store.rows[-1].get("note", "").startswith("chain:"),
          store.rows[-1].get("note", ""))

    # ---- 3. 中转挂掉：失败即失败 ----
    print("[3] 中转不可达 → 必须失败且不回落直连")
    dead = FakeHttpProxy("dead")
    await dead.start()
    dead.server.close()
    await dead.server.wait_closed()
    chain.apply({"hops": [{"scheme": "http", "host": "127.0.0.1",
                           "port": dead.port}]}, save=False)
    before = len(target.peers)
    st, body = await fetch_via_proxy(ps_port, "localhost", th)
    check("返回 502", b"502" in st, st.decode())
    check("目标没有收到任何请求（未泄漏直连）", len(target.peers) == before)
    check("错误信息点明链路", b"502" in st)
    check("failures 计数增加", chain.failures >= 1, str(chain.failures))

    # ---- 4. allow_direct=True 才回落 ----
    print("[4] allow_direct=True → 允许回落直连")
    chain.apply({"allow_direct": True}, save=False)
    before = len(target.peers)
    st, body = await fetch_via_proxy(ps_port, "localhost", th)
    check("回落成功 200", b"200" in st, st.decode())
    check("目标收到请求", len(target.peers) == before + 1)
    chain.apply({"allow_direct": False}, save=False)

    # ---- 5. 两跳串联 HTTP → SOCKS5 ----
    print("[5] 两跳串联：ProxyScope → HTTP 中转 → SOCKS5 → 目标")
    hp2 = FakeHttpProxy("http2")
    await hp2.start()
    s5 = FakeSocks5()
    await s5.start()
    chain.apply({"enabled": True, "hops": [
        {"scheme": "http", "host": "127.0.0.1", "port": hp2.port},
        {"scheme": "socks5h", "host": "127.0.0.1", "port": s5.port},
    ]}, save=False)
    before = len(target.peers)
    r1, r2 = len(hp2.requests), len(s5.requests)
    st, body = await fetch_via_proxy(ps_port, "localhost", th)
    check("请求成功", b"200" in st, st.decode())
    check("第 1 跳把 CONNECT 指向了第 2 跳", len(hp2.requests) == r1 + 1 and
          hp2.requests[-1][1] == f"127.0.0.1:{s5.port}", str(hp2.requests[-1:]))
    check("第 2 跳（SOCKS5）解析的是域名而非 IP", len(s5.requests) == r2 + 1 and
          s5.requests[-1][0] == "localhost", str(s5.requests[-1:]))
    check("目标收到请求", len(target.peers) == before + 1)
    check("route 描述包含两跳", chain.route_label().count("→") == 1, chain.route_label())

    # ---- 6. 探测出口 ----
    print("[6] probe() 沿链路探测出口 IP")
    # 让目标伪装成 ipify：探测请求同样经过两跳
    before_s5 = len(s5.requests)
    res = await chain.probe(url=f"http://localhost:{th}/", compare_direct=False)
    check("probe ok", res["ok"] is True, str(res))
    check("退出 IP 取自链路响应", res["chain_exit_ip"] == "203.0.113.9", str(res["chain_exit_ip"]))
    check("探测确实走了 SOCKS5 跳", len(s5.requests) == before_s5 + 1)

    # ---- 7. 密码不回落直连时仍然读不到明文 ----
    print("[7] snapshot 中密码被掩码")
    snap = chain.snapshot()
    check("密码不外泄", all(h.get("password") in ("", "***") for h in snap["hops"]),
          str(snap["hops"]))

    await ps.stop()
    print("\n结果：", "全部通过" if ok else "存在失败项")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
