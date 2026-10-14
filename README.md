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
bash <(curl -Ls https://raw.githubusercontent.com/wanchangkongyi/vpngate-gateway/main/install.sh)
```

**Alpine**（默认没有 bash 和 curl，需先安装）：

```bash
apk add bash curl && bash <(curl -Ls https://raw.githubusercontent.com/wanchangkongyi/vpngate-gateway/main/install.sh)
```

安装脚本会自动识别包管理器（apt / apk）和服务管理器（systemd / OpenRC）。安装完成后输入 `vg` 打开交互菜单。

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

示例：

```bash
vg set rotate_hours 1          # 每1小时轮换一次
vg set country_filter JP,KR    # 只用日本/韩国节点
vg set latency_check_hours 2   # 每2小时检测一次延迟
vg set min_nodes 3             # 节点数低于3个时自动重抓
vg set probe_count 0           # 跳过握手验证，只用延迟排序
```

## 自动化逻辑

```
定时延迟检测（latency_check_hours）
    │
    ▼
对所有节点重测延迟 → 删除不可达节点
    │
    ├─ 节点数 >= min_nodes → 重新排序保存，自动切换到更快节点
    │
    └─ 节点数 < min_nodes → 触发重新抓取 → 自动连接最快节点
```

此外：
- **定时轮换**（`rotate_hours`）：定时切换到下一个节点，出口 IP 持续变化
- **Watchdog**：OpenVPN 进程意外退出时自动重连，带指数退避防止频繁重试
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

其他工具：
- SOCKS5：`socks5://127.0.0.1:7928`
- HTTP：`http://127.0.0.1:7928`

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

**节点探测显示 ✘ 但能正常连接？**
正常现象。VPNGate 节点的握手验证在没有 VPN 的环境下容易被拦截，不代表节点不可用。可以用 `vg set probe_count 0` 跳过验证。

**出口 IP 和节点 IP 不一样？**
正常现象。VPNGate 节点是中继服务器，连接 IP 是入口地址，出口 IP 是实际出网地址，两者不同是正常的。

**修改端口后代理不可用？**
修改 `proxy_port` 后需要重启服务生效：`vg restart`，同时更新 Xray/3x-ui 里的端口配置。

**512M 内存够用吗？**
正常运行约占 150MB。fetch 抓取时峰值约 200MB。内存紧张时建议 `vg set probe_count 0` 和 `vg set top_nodes 15`。

## 依赖

- Linux：Ubuntu 20.04+ / Debian 10+ / Alpine
- Python 3.8+
- OpenVPN 2.4+（Alpine 自带 2.6 系列）
- curl、iproute2（Alpine 上必须装 iproute2，busybox 自带的 `ip` 不支持策略路由）
- `/dev/net/tun` 设备（LXC/OpenVZ 需在服务商面板开启 TUN/TAP）
