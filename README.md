# ProxyScope

轻量 **MITM 抓包代理 + 本地 Web 检索界面**。启动一个代理端口，让流量经过它，
所有请求与响应被记录下来，再通过浏览器界面按关键字 / 主机 / 状态码检索。

定位类似 Burp Suite / Yakit 的「Proxy + HTTP History」部分，但只做一件事：
**抓下来、存起来、查得到**。

---

## 快速开始

### Windows

```
start.bat                # 启动代理 (18888) + Web 界面 (18787)
install-ca.bat           # 首次使用：安装根证书（HTTPS 解密必需）
set-proxy.bat            # 让 Windows 系统代理指向 ProxyScope
```

用完恢复直连：`set-proxy.bat off`

### Linux / macOS

```bash
chmod +x start.sh        # 首次需要加执行权限
./start.sh               # 启动
```

脚本会自动检查 Python 版本、openssl、端口占用和缺失的可选依赖，并在启动前
打印全部访问地址。常用环境变量：

```bash
PROXY_PORT=18888 ./start.sh              # 换代理端口
LISTEN=0.0.0.0 ./start.sh                # 允许局域网连入（会给出安全提示）
WEB_PORT=18787 DATA_DIR=/var/lib/ps ./start.sh
VERIFY_UPSTREAM=1 ./start.sh             # 校验上游证书
./start.sh --help                        # 查看全部参数
```

然后浏览器打开 **http://127.0.0.1:18787** 查看抓到的流量。

> 只想给某个工具单独配代理、不动系统设置：
> `http://127.0.0.1:18888`（HTTP 与 HTTPS 共用同一个端口）。


---

## v1.1.0 新功能

### 1. 内置认证（代理端 + 面板端）

无需外加 nginx / tinyproxy，ProxyScope 自己校验 Basic 认证。

```bash
# 首次启动时直接指定账号
python3 -m proxyscope --proxy-user psscan --proxy-pass '你的密码' \
                      --panel-user psadmin --panel-pass '你的密码'
```

也可在面板「账号设置」里随时修改，改完立即生效、无需重启：

| 范围 | 保护对象 | 失败响应 |
|---|---|---|
| `proxy` | 抓包代理端口 18888 | `407 Proxy Authentication Required` |
| `panel` | Web 面板及其全部 API | `401 Unauthorized` |

安全设计：
- 密码用 **PBKDF2-HMAC-SHA256** 存储，`data/auth.json` 里只有哈希
- 校验结果带缓存，改密码后自动失效 —— 面板响应从 ~160ms 降到 ~2ms
- 另存一份 XOR 流加密的密文（`data/auth.key`），仅用于在面板上生成「可复制的完整代理地址」，
  与校验哈希相互独立

### 2. 请求重放 / 改包（漏洞复现）

在任意一条记录上打开详情 → 「重放」页签：

- 方法、URL、Header、Body 全部可改，改完直接重发
- 支持校验/跳过上游证书
- **重放结果自动作为新记录入库**，`client_addr` 标记为 `replay`，可基于它继续迭代

### 3. 服务控制

面板顶部可直接「启动 / 停止 / 重启」抓包服务。

实现上用 `systemd-run --on-active=2s` 脱离当前进程执行，
避免重启时把自己杀掉导致响应中断。

### 4. 全新 UI

深色 / 浅色双主题，仿 Burp 风格的原始报文展示：

- 请求行 / 状态行 + Header + 空行 + Body，纯文本、等宽字体
- 内置内容搜索（支持正则、仅显示匹配行）
- 「复制请求 / 复制响应」一键导出标准 Burp 报文
- 敏感 Header（Cookie / Authorization）自动折叠，点击展开

### 5. 稳定性修复

| 问题 | 原因 | 修复 |
|---|---|---|
| 重启后历史记录丢失 | `store.close()` 从未被调用，WAL 未合并 | 停机流程调用 `close()`，幂等实现 |
| 文件句柄耗尽 | `threading.local()` 每线程建连接且不释放 | 改为单连接 + RLock |
| 代理自环死循环 | 目标指向自身时转发给自己，等满 60s 超时 | 检测到自环立即返回 502 |
| 面板每个请求都慢 160ms | 每次认证都重算 PBKDF2 | 校验结果缓存 |
| 301/302 被标记为错误 | 有响应头后的连接重置被当作异常 | 区分「正常收尾」与「真错误」 |

### 6. CRL 吊销检查支持（v1.1.1）

Windows 的 Schannel（系统 curl / PowerShell / 部分工具）默认强制检查证书吊销状态。
自签 CA 若不含 CRL 分发点，会直接报错：

```
CRYPT_E_NO_REVOCATION_CHECK (0x80092012) - 吊销功能无法检查证书是否吊销
```

设置环境变量即可自动解决 —— 叶子证书会带上 `crlDistributionPoints` 扩展，
ProxyScope 启动时自动签发并维护 CRL 文件：

```bash
export PROXYSCOPE_CRL_URL="http://你的服务器IP/ca.crl"
./start.sh
```

再把这个 URL 指向的 CRL 通过 Web 服务暴露出来（nginx 示例）：

```nginx
location = /ca.crl {
    alias /path/to/data/certs/proxyscope-ca.crl;
    default_type application/pkix-crl;
    auth_basic off;
}
```

也可以从 `/api/ca.crl` 获取。

> 浏览器（Chrome / Edge）使用自带校验器，对用户导入的根证书不会因缺 CRL 而拒绝，
> 所以只有命令行工具需要这个配置。临时方案是给 curl 加 `--ssl-no-revoke`。

### 7. 客户端一键接入（v1.1.2）

面板顶部「客户端接入」按钮，弹窗内按 Windows / Linux / macOS 分页给出三条命令：

1. **安装根证书** —— 一行命令完成下载 + 导入受信任根
2. **配置代理** —— 一行命令写入系统或终端代理设置
3. **验证** —— 一条 `curl` 确认链路可用

证书与 CRL 同时通过 **80 端口明文 HTTP** 下发，避免"要信任证书才能下载证书"的死循环：

```
http://<你的IP>/mitm-ca.crt     MITM 抓包 CA
http://<你的IP>/psui-ca.crt     面板 HTTPS CA
http://<你的IP>/ca.crl          CRL
```

命令示例：

```bash
# Linux
curl -s http://IP/mitm-ca.crt | sudo tee /usr/local/share/ca-certificates/proxyscope.crt >/dev/null && sudo update-ca-certificates

# Windows (cmd)
curl -s http://IP/mitm-ca.crt -o "%TEMP%\ps-ca.crt" && certutil -addstore -user Root "%TEMP%\ps-ca.crt" && del "%TEMP%\ps-ca.crt"
```

> 顺手修了一个前端 bug：当地址栏带有 `user:pass@` 凭据时，
> 浏览器会拒绝用相对路径发起 `fetch`（`Request cannot be constructed from a URL
> that includes credentials`），导致面板所有接口失效。现在加载时会自动清掉
> 地址栏凭据，并统一改用绝对 URL。

### 8. 出口链路：多级中转，隐藏服务器真实 IP（v1.2.0）

默认链路是「客户端 → ProxyScope → 目标站」，目标侧看到的是**本机公网 IP**。
开启出口链路后变成「客户端 → ProxyScope → 中转1 → 中转2 → … → 目标站」，
目标侧只能看到**最后一跳中转**的 IP。

面板顶部「出口链路」按钮：

| 控件 | 说明 |
|---|---|
| 总开关 | **关＝直连（默认，不启用任何中转）**；开＝全部出站走下面的链路。切换立即生效，无需重启 |
| 跳数列表 | 每跳可选 `http` / `https` / `socks5` / `socks5h`，填地址、端口、可选账号密码；「＋ 添加一跳」可加到任意深度 |
| 保存并生效 | 校验通过才写入 `data/chain.json`，写盘后对后续请求立即生效 |
| 测试出口 IP | 沿当前链路请求多个出口 IP 接口，同时给出「链路出口 IP」和「本机直连 IP」，并判断二者是否不同 |
| 校验中转/目标 TLS 证书 | 默认关闭（便于抓自签名站点与自签证书中转） |
| 链路失败时允许回落直连 | **默认关闭**，见下方安全语义 |
| 单跳超时 | 每跳建链超时，默认 20 秒 |

列表中经过中转的记录，HOST 下方会显示绿色的「· 中转」标记；记录 `note` 字段为
`chain:<中转地址>`，链路不通时为 `chain:<中转地址> failed`。

#### 安全语义（失败即失败）

链路**开启**且配置了中转时，出站失败会直接返回 502，错误信息里写明是「出口链路失败」
并附中转地址，**不会**静默回落直连——否则链路挂了你以为在隐身、其实在用本机 IP。
只有显式勾选「允许回落直连」才会退而直连。

#### 支持的用法

```bash
# 命令行直接指定一串中转（自动开启）
python3 -m proxyscope --port 18888 \
  --chain 'socks5h://user:pass@1.2.3.4:1080,http://5.6.7.8:8080'

# 只指定配置文件位置，开关仍由面板控制
python3 -m proxyscope --chain-file /opt/proxyscope/data/chain.json

# 允许链路失败回落直连（不推荐）
python3 -m proxyscope --chain-allow-direct
```

要点：

- **逐跳串联**：第 1 跳直连建立，之后每跳都在上一跳的隧道内发起 `CONNECT`，
  所以中间各跳只看到相邻一跳，看不到你的最终目标；
- **DNS 不泄漏**：只把域名交给中转（SOCKS5 用域名地址类型），由中转侧解析；
- **TLS 在隧道内完成**：HTTPS 目标是在中转隧道里做 TLS 握手，中转只看到 `host:port`；
- **热更新**：面板保存后对后续请求立即生效；密码只写不读，接口只回 `***`，
  `data/chain.json` 权限 600；
- **重放也走链路**：面板里的「重放」同样经中转发出，避免抓包走后门、重放却裸奔。

#### 实测对照（某云主机，链路为 1 跳 HTTP 中转）

| 状态 | 目标站看到的来源 IP |
|---|---|
| 关闭（直连） | 本机公网 IP（如 `203.0.113.10`） |
| 开启（经中转） | 中转侧出口 IP（如 `2408:8207:…`） |

---

## HTTPS 面板（可选）

面板本身是明文 HTTP。需要 HTTPS 时，可用自签证书 + nginx 反代：

```bash
# 1. 生成带 IP SAN 的证书（现代浏览器只认 SAN，不认 CN）
openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
  -keyout panel.key -out panel.crt \
  -subj "/CN=你的IP" \
  -addext "subjectAltName=IP:你的IP,DNS:localhost"

# 2. 导入 panel.crt 到系统/浏览器的受信任根证书，即可消除告警
```

---

## 让系统信任根证书

### Linux（Chrome / Chromium / curl / wget）

```bash
sudo cp data/certs/proxyscope-ca.crt /usr/local/share/ca-certificates/proxyscope.crt
sudo update-ca-certificates
```

Firefox 有独立证书库，需在界面里单独导入：
设置 → 隐私与安全 → 证书 → 查看证书 → 证书颁发机构 → 导入。

### macOS

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain data/certs/proxyscope-ca.crt
```

### 不装系统，只给单个工具用

```bash
curl --proxy http://127.0.0.1:18888 --cacert data/certs/proxyscope-ca.crt https://example.com/
export REQUESTS_CA_BUNDLE=$PWD/data/certs/proxyscope-ca.crt   # pip / requests
```

---

## 为什么需要装证书

HTTPS 要看到明文内容，代理必须在中间解密。ProxyScope 第一次运行会生成一套
自签 CA（`data/certs/proxyscope-ca.crt`），用它给每个访问的域名动态签发证书。

只有系统信任了这个 CA，浏览器才不会报证书错误。

卸载：Windows 用 `install-ca.bat remove`；Linux 删掉
`/usr/local/share/ca-certificates/proxyscope.crt` 后执行
`sudo update-ca-certificates --fresh`。

---

## 在 Linux 服务器上远程访问

代理跑在服务器、你想在本机浏览器操作时，**不要**把 Web 界面开在 0.0.0.0
（它没有登录认证，抓到的 Cookie / Token 会暴露给整个网络）。用 SSH 隧道：

```bash
# 服务器上：保持默认只监听回环
./start.sh

# 本机执行：把两个端口转发出来
ssh -L 18787:127.0.0.1:18787 -L 18888:127.0.0.1:18888 user@server
```

之后本机访问 `http://127.0.0.1:18787`，代理设为 `127.0.0.1:18888` 即可。

用 systemd 常驻（可选）：

```ini
# /etc/systemd/system/proxyscope.service
[Unit]
Description=ProxyScope
After=network.target

[Service]
User=youruser
WorkingDirectory=/opt/ProxyScope
ExecStart=/opt/ProxyScope/start.sh
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

---

## 界面功能

| 区域 | 说明 |
|---|---|
| 左侧列表 | 流式列出所有请求：方法 / 状态码 / 时间 / 主机 / 路径 / 大小 / 耗时 |
| 搜索框 | 全文检索 URL、请求体、响应体（SQLite FTS5，命中正文内容） |
| 过滤条件 | host 模糊匹配、HTTP 方法、状态码（支持 `2xx` `4xx` `>=400`）、协议 |
| 右侧详情 | 概要 / 请求头 / 请求体 / 响应头 / 响应体 / 原始报文 六个标签页 |
| 自动刷新 | 每 2 秒刷新列表；检索模式下不会打断当前结果 |

细节：

- 响应体自动解压 gzip / deflate / br / zstd 后再入库和展示；
- JSON 自动格式化，图片直接内联预览；
- 大文件默认截断到 2 MB（详情页会标注「已截断」）；
- 记录默认最多保留 20 万条，超出自动清理最旧的。

---

## 命令行参数

```
python -m proxyscope [选项]

--listen 127.0.0.1     代理监听地址（默认仅本机；需要局域网共享用 0.0.0.0）
--port 18888           代理端口
--web-host 127.0.0.1   Web 界面地址
--web-port 18787       Web 界面端口
--data-dir ./data      数据目录（证书 + SQLite 数据库）
--verify-upstream      校验上游服务器证书（默认关闭，方便抓自签名站点）
--max-flows 200000     最多保留记录数
--timeout 60           上游超时（秒）
--debug                输出调试日志
--no-web               只跑代理，不启 Web 界面
--chain 'a:1,b:2'      出口链路：逗号分隔的中转地址，按顺序串联，指定即开启
--chain-file PATH      链路配置文件（默认 <data-dir>/chain.json）
--chain-allow-direct   链路失败时允许回落直连（默认禁止）
```

---

## REST API

抓到的数据也能被脚本消费：

| 接口 | 说明 |
|---|---|
| `GET /api/flows` | 列表。参数：`q` `host` `method` `status` `scheme` `mime` `since` `until` `limit` `offset` `order` |
| `GET /api/flows/{id}` | 单条详情，含 base64 编码的请求/响应体 |
| `GET /api/stats` | 统计信息、代理运行状态、热点主机 |
| `POST /api/flows/delete` | `{"ids":[1,2]}` 删除指定记录 |
| `POST /api/flows/clear` | 清空全部记录 |
| `GET /api/ca.crt` | 下载 CA 证书 |
| `GET /api/health` | 健康检查 |
| `GET /api/chain` | 出口链路配置与统计（密码掩码为 `***`） |
| `POST /api/chain` | 保存并热应用链路配置：`{"enabled":true,"hops":[{"scheme":"socks5h","host":"1.2.3.4","port":1080,"username":"u","password":"p"}]}` |
| `POST /api/chain/enable` | 只切开关：`{"enabled":true|false}` |
| `POST /api/chain/test` | 沿链路探测出口 IP，返回 `chain_exit_ip` / `direct_exit_ip` / `hidden` |

示例：

```bash
# 检索所有响应体里含 "password" 的 HTTPS 请求
curl "http://127.0.0.1:18787/api/flows?q=password&scheme=https"

# 只看 4xx/5xx
curl "http://127.0.0.1:18787/api/flows?status=4xx,5xx"
```

---

## 技术实现

- **纯标准库**：`asyncio` + `http.server` + `sqlite3`，无 Web 框架依赖；
- **MITM**：`CONNECT` 建隧道 → 用自签证书做 TLS 握手 → 解析明文 HTTP/1.1；
- **证书**：调用系统 OpenSSL 动态签发，内存缓存，不重复生成；
- **存储**：SQLite（WAL 模式），FTS5 全文索引，写入线程独立连接；
- 可选依赖 `brotli` / `zstandard`，缺失时对应编码不解码（其余功能不受影响）。

目录结构：

```
ProxyScope/
├─ proxyscope/
│  ├─ certs.py      CA 与证书签发
│  ├─ proxy.py      MITM 代理核心
│  ├─ store.py      SQLite 存储与检索
│  ├─ webui.py      Web 服务与 REST API
│  ├─ static/       前端界面
│  └─ __main__.py   命令行入口
├─ data/            运行时生成（证书、flows.db）
├─ start.bat
├─ install-ca.bat
└─ set-proxy.bat
```

---

## 已知限制

- 只处理 **HTTP/1.1**。HTTP/2 会降级为 1.1（`ALPN` 只协商 `http/1.1`）；
- WebSocket 升级后转为隧道转发，只记录握手，不记录帧内容；
- 不做 HTTPS 之外的协议（如 SOCKS、FTP）；
- 单进程 asyncio，适合个人抓包调试，不适合做大规模网关。

---

## 合规提醒

这个工具会记录经过代理的全部明文流量，包含 Cookie、Token、密码等敏感信息。

仅用于**你拥有或已获授权**的系统与流量。数据库文件 `data/flows.db` 是明文存储，
用完建议清空记录，或删除该文件。
