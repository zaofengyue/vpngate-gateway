# VPNGate Gateway

将 [VPNGate](https://www.vpngate.net) 免费公共节点作为 VPS 出口 IP，本地暴露 SOCKS5/HTTP 双协议代理供 Xray/3x-ui 或其他工具使用。出口 IP 定期自动轮换，SSH 管理流量走 eth0 物理网卡，**不会因切换 VPN 而断连**。

## 架构

```
Xray / 3x-ui
    │ SOCKS5 出站
    ▼
127.0.0.1:7928  ← HTTP/SOCKS5 双协议代理
    │ SO_BINDTODEVICE → tun0（VPN 断开时直接返回 502，不泄露真实 IP）
    ▼
tun0  ← OpenVPN 虚拟网卡
    │ 策略路由表 100
    ▼
VPNGate 公共节点（日本 / 美国 / 韩国 / ...）
    │
    ▼
目标网站（看到 VPNGate 节点 IP，非 VPS 真实 IP）
```

## 快速安装

**Debian / Ubuntu：**

```bash
bash <(curl -Ls https://raw.githubusercontent.com/zaofengyue/vpngate-gateway/main/install.sh)
```

**Alpine**（默认没有 bash 和 curl，需先安装）：

```bash
apk add bash curl && bash <(curl -Ls https://raw.githubusercontent.com/zaofengyue/vpngate-gateway/main/install.sh)
```

安装脚本会自动识别包管理器（apt / apk）和服务管理器（systemd / OpenRC）。安装完成后输入 `vg` 打开交互菜单。

### 固定版本与完整性校验（推荐）

`install.sh` 内置了其余源码文件的 SHA256 清单，下载后逐个校验，**不一致就中止且不改动任何已安装文件**。
因此只要你信任手里这份 `install.sh`，就不必信任下载通道。把脚本固定到某个 tag 或 commit：

```bash
REF=<tag或commit>
VPNGATE_REF=$REF bash <(curl -Ls https://raw.githubusercontent.com/zaofengyue/vpngate-gateway/$REF/install.sh)
```

| 环境变量 | 作用 |
|----------|------|
| `VPNGATE_REF` | 下载哪个 tag/commit/分支的文件（默认 `main`） |
| `VPNGATE_RAW_BASE` | 从镜像下载（如 GitHub 访问不畅时）；完整性仍按清单校验，镜像无法夹带改动 |
| `VPNGATE_SKIP_VERIFY=1` | 跳过校验（仅限你自己维护的 fork，自担风险） |

已 clone / 解压源码时，在源码目录执行 `bash install.sh` 即直接安装本地文件（本地模式不做哈希校验）。
`vg service` 里的"快捷重装"走同样的校验流程；仅更新程序文件可用 `bash install.sh --files-only`。

> 维护者：修改四个程序文件后运行 `bash tools/update_hashes.sh` 重新生成清单（`--check` 可用于 CI）。

## 安全模型

VPNGate 节点由志愿者运营，**节点配置和节点本身都不可信**。本项目的防护：

| 威胁 | 措施 |
|------|------|
| 恶意 `.ovpn`（`up`/`plugin` 脚本、`route` 劫持路由、`redirect-gateway`、管理口、读写本地文件） | 配置按**白名单**清洗：只保留已知安全的指令，证书/密钥只认内联块；无法安全解析的节点直接丢弃。路径穿越/内网 IP 的节点字段也会被拒绝 |
| openvpn 被攻破 | 服务启动后自行**降权**为 `vpngate` 用户，只保留 `CAP_NET_ADMIN`/`CAP_NET_RAW`（bounding set 收紧、`no_new_privs`），openvpn 子进程继承同样的最小权限；程序文件归 root 只读 |
| DNS 泄漏 | 域名在**隧道内**解析（自带最小 DNS 客户端，`SO_BINDTODEVICE` 绑 tun0），不使用系统解析器 |
| IP 泄漏 | 所有出站连接绑定 tun0；VPN 断开时直接失败，绝不回落到物理网卡。`vg status --check` 会对比出口 IP 与 VPS 真实 IP，相同则告警 |
| 同机其他用户蹭用代理 | 可选的代理认证（SOCKS5 用户名密码 / HTTP Basic），口令用常量时间比较 |
| 供应链 | 安装器校验 SHA256 清单（见上） |

**仍然存在的局限**（请知悉）：
- 出口节点是陌生人的机器，能看到所有**未加密**流量（HTTP 等）。不要用它登录敏感账号。
- 出口 IP 是共享的公共 IP，很多网站会要求验证码或直接拒绝。
- 默认**不启用**代理认证（为兼容已有配置）；多用户机器请务必启用：`vg set proxy_user xxx` 然后 `vg set proxy_pass`（回车后隐藏输入），再 `vg restart`。
- 降权依赖内核支持相应能力操作；预检失败时会在日志里告警并**继续以 root 运行**，而不是起不来。
- 安装脚本为兼容部分云平台会把 `rp_filter` 放宽为 loose（2），这是全局内核参数。

## 交互菜单

```
 ╔══════════════════════════════════════════════════╗
 ║          VPNGate Gateway 管理菜单                ║
 ╠══════════════════════════════════════════════════╣
 ║  0.  修改设置                                    ║
 ║  1.  查看状态                                    ║
 ║  2.  抓取节点                                    ║
 ║  3.  查看节点列表                                ║
 ║  4.  自动连接最快节点                            ║
 ║  5.  检测节点延迟                                ║
 ║  6.  轮换节点                                    ║
 ║  7.  手动选择节点                                ║
 ║  8.  断开连接                                    ║
 ║  9.  查看日志                                    ║
 ║  10. 服务管理                                    ║
 ║  11. 卸载                                        ║
 ║  00. 退出                                        ║
 ╚══════════════════════════════════════════════════╝
```

## 命令参考

| 命令 | 说明 |
|------|------|
| `vg` | 打开交互菜单 |
| `vg status` | 查看状态 |
| `vg status --check` | 查看状态并实时检测出口 IP |
| `vg fetch` | 抓取节点并测速，完成后自动连接 |
| `vg fetch --country JP,US` | 只抓取日本/美国节点 |
| `vg fetch --top 30` | 保留前 30 个节点 |
| `vg auto` | 自动连接最快节点 |
| `vg nodes` | 查看节点列表 |
| `vg nodes --country JP` | 只看日本节点 |
| `vg connect <node_id>` | 连接指定节点 |
| `vg check-latency` | 手动检测所有节点延迟，删除不可达节点 |
| `vg rotate` | 切换到下一个节点 |
| `vg stop` | 断开 VPN 连接 |
| `vg logs` | 查看最近 50 行日志 |
| `vg logs -n 100` | 查看最近 100 行日志 |
| `vg restart` | 重启服务 |
| `vg set <key> <value>` | 修改设置 |
| `vg uninstall` | 卸载 |

`vpngw` 与 `vg` 完全等效。

## 设置项

在交互菜单选 `0` 或使用 `vg set` 命令修改：

| 序号 | 设置项 | 默认值 | 说明 |
|------|--------|--------|------|
| 1 | `country_filter` | 不限 | 国家白名单，如 `JP,US,KR`，空=不限 |
| 2 | `rotate_hours` | `2` | 自动轮换间隔（小时），`0`=关闭 |
| 3 | `latency_check_hours` | `1` | 定时延迟检测间隔（小时），`0`=关闭 |
| 4 | `min_nodes` | `5` | 节点数低于此值时自动重新抓取 |
| 5 | `top_nodes` | `20` | 抓取后保留前 N 个节点 |
| 6 | `probe_count` | `10` | OpenVPN 握手验证节点数，`0`=跳过 |
| 7 | `proxy_port` | `7928` | 代理监听端口 |
| 8 | `auto_fetch_on_start` | `true` | 服务启动时自动抓取节点 |
| 9 | `outlet_check_interval` | `60` | 出口连通性检测间隔（秒），`0`=关闭 |
| 10 | `outlet_max_fails` | `3` | 连续失败 N 次后标记节点不可用并轮换 |
| 11 | `dns_servers` | `1.1.1.1,8.8.8.8` | 经隧道解析域名所用的 DNS（IPv4，逗号分隔）；需重启 |
| 12 | `proxy_user` | 空 | 代理认证用户名；与 `proxy_pass` 同时设置才启用；`off` 清除；需重启 |
| 13 | `proxy_pass` | 空 | 代理认证密码；`vg set proxy_pass` 不带值会隐藏输入；`off` 清除；需重启 |
| 14 | `run_as_user` | `vpngate` | 降权运行的系统用户；`root`/空=不降权；需重启 |

用户名/密码只允许字母数字和 `. _ ~ ! @ # % ^ * + = -`（1–128 位）。只设置其中一个时服务会**拒绝启动**，而不是退化成无认证。

示例：

```bash
vg set rotate_hours 1          # 每1小时轮换一次
vg set country_filter JP,KR    # 只用日本/韩国节点
vg set latency_check_hours 2   # 每2小时检测一次延迟
vg set min_nodes 3             # 节点数低于3个时自动重抓
vg set probe_count 0           # 跳过握手验证，只用延迟排序
vg set proxy_user myname       # 启用代理认证（再执行 vg set proxy_pass，然后 vg restart）
```

## 自动化逻辑

```
定时延迟检测（latency_check_hours）
    │
    ▼
对所有节点重测延迟（TCP 节点测握手；UDP 节点发 OpenVPN 探测包）→ 删除不可达节点
    │
    ├─ 节点数 >= min_nodes → 重新排序保存，自动切换到更快节点
    │
    └─ 节点数 < min_nodes → 触发重新抓取 → 自动连接最快节点
```

此外：
- **定时轮换**（`rotate_hours`）：定时切换到下一个节点，出口 IP 持续变化
- **Watchdog**：OpenVPN 进程意外退出时自动重连，带指数退避防止频繁重试
- **手动停止**：`vg stop` 之后，watchdog、定时轮换、延迟检测都不会再把 VPN 拉起来，直到你执行 `vg auto` / `vg connect` / `vg rotate`（重启服务会重置）
- **UDP 节点**：无法用 TCP 测速。探测包有应答则显示真实延迟；没有应答（可能启用了 tls-auth/限速）时显示 `~500ms+` 的估算值并排在已验证节点之后，由握手验证和实际连接裁决
- **fetch 后自动连接**：手动或自动抓取节点后立即连接最快节点

## Xray / 3x-ui 出站配置

**SOCKS5：**

```json
{
  "tag": "vpngate-out",
  "protocol": "socks",
  "settings": {
    "servers": [{ "address": "127.0.0.1", "port": 7928 }]
  }
}
```

**HTTP：**

```json
{
  "tag": "vpngate-out",
  "protocol": "http",
  "settings": {
    "servers": [{ "address": "127.0.0.1", "port": 7928 }]
  }
}
```

启用代理认证后，在 `servers` 里加上 `users`（SOCKS5 和 HTTP 写法相同）：

```json
"servers": [{ "address": "127.0.0.1", "port": 7928,
              "users": [{ "user": "你的用户名", "pass": "你的密码" }] }]
```

其他工具：
- SOCKS5：`socks5://127.0.0.1:7928`（带认证：`socks5://用户名:密码@127.0.0.1:7928`；域名请用 `socks5h` 让代理解析）
- HTTP：`http://127.0.0.1:7928`（带认证：`http://用户名:密码@127.0.0.1:7928`）

## 服务管理

`vg restart` / `vg service` 在 systemd 和 OpenRC 下通用：

```bash
vg restart                          # 重启服务
vg service                          # 服务管理菜单（含快捷重装）
vg logs -n 100                      # 程序日志（所有系统通用）
```

底层命令：

```bash
# Debian / Ubuntu (systemd)
systemctl status vpngate-gateway
journalctl -u vpngate-gateway -f

# Alpine (OpenRC)
rc-service vpngate-gateway status
cat /var/log/vpngate-gateway.err    # 进程崩溃时的错误输出
```

## 卸载

```bash
vg uninstall
```

- **卸载服务**：删除服务和程序文件，保留 openvpn 等依赖，重新安装时无需重装
- **彻底卸载**：同时移除 openvpn、iproute2 等依赖包

## 常见问题

**节点探测显示 ✘？**
表示该节点的 OpenVPN 握手没有在限定时间内完成（节点已下线、拥塞或拒绝连接），连接时会被排在后面。若所有节点都 ✘，会保留全部节点继续尝试连接。（旧版本的握手验证存在 bug，几乎总是失败，所以曾有"✘ 也能连"的说法；现已修复。）想跳过验证可用 `vg set probe_count 0`。

**`vg stop` 之后过一会儿又连上了？**
旧版本会这样。现在手动停止后不会被自动拉起，需要 `vg auto` / `vg connect` / `vg rotate` 才会重新连接。

**通过环境变量改抓取源？**
`VPNGATE_API_URL=https://你的镜像/api/iphone/`（写进 systemd 的 `Environment=` 或 OpenRC 脚本）。只接受 http(s) 地址。

**出口 IP 和节点 IP 不一样？**
正常现象。VPNGate 节点是中继服务器，连接 IP 是入口地址，出口 IP 是实际出网地址，两者不同是正常的。

**修改端口后代理不可用？**
修改 `proxy_port` 后需要重启服务生效：`vg restart`，同时更新 Xray/3x-ui 里的端口配置。

**512M 内存够用吗？**
正常运行约占 150MB。fetch 抓取时峰值约 200MB。内存紧张时建议 `vg set probe_count 0` 和 `vg set top_nodes 15`。

## 开发与测试

```bash
python3 tests/test_patch.py        # 配置清洗（含模糊测试）、隧道 DNS
python3 tests/test_hardening.py    # 认证、UDP 探测、并发/定时/手动停止、降权（root 时）、CLI 设置
sudo bash tests/e2e/e2e.sh         # 端到端：真实 OpenVPN 服务端 + 真实安装器 + 真实服务进程（约 8 分钟）
bash tools/update_hashes.sh        # 改完程序文件后刷新 install.sh 的 SHA256 清单
```

端到端脚本会真的安装到 `/opt/vpngate-gateway`、创建 `vpngate` 用户并改策略路由，请在一次性机器/容器里运行（需要 `/dev/net/tun` 和网络命名空间）。

## 依赖

- Linux：Ubuntu 20.04+ / Debian 10+ / Alpine
- Python 3.8+
- OpenVPN 2.4+（Alpine 自带 2.6 系列）
- curl、iproute2（Alpine 上必须装 iproute2，busybox 自带的 `ip` 不支持策略路由）
- `/dev/net/tun` 设备（LXC/OpenVZ 需在服务商面板开启 TUN/TAP）
