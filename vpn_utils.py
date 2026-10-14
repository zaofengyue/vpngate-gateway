#!/usr/bin/env python3
"""
工具函数：延迟测试、节点解析、IP 信息查询
"""
from __future__ import annotations
import csv
import io
import base64
import ipaddress
import json
import os
import queue
import re
import socket
import struct
import subprocess
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

# ── 国家名翻译 ────────────────────────────────────────────────────────────────
COUNTRY_ZH: dict[str, str] = {
    "Japan": "日本", "Korea Republic of": "韩国", "Thailand": "泰国",
    "United States": "美国", "United Kingdom": "英国", "Russian Federation": "俄罗斯",
    "Viet Nam": "越南", "Vietnam": "越南", "China": "中国", "Taiwan": "台湾",
    "Taiwan Province of China": "台湾", "Hong Kong": "香港", "Singapore": "新加坡",
    "Malaysia": "马来西亚", "Indonesia": "印度尼西亚", "India": "印度",
    "Philippines": "菲律宾", "Australia": "澳大利亚", "Canada": "加拿大",
    "France": "法国", "Germany": "德国", "Netherlands": "荷兰",
    "Sweden": "瑞典", "Brazil": "巴西", "Ukraine": "乌克兰",
    "Mongolia": "蒙古", "Cambodia": "柬埔寨", "Laos": "老挝",
    "Myanmar": "缅甸", "Bangladesh": "孟加拉国", "Sri Lanka": "斯里兰卡",
    "Nepal": "尼泊尔", "Pakistan": "巴基斯坦", "Turkey": "土耳其",
    "Mexico": "墨西哥", "Argentina": "阿根廷", "Chile": "智利",
    "Colombia": "哥伦比亚", "Italy": "意大利", "Spain": "西班牙",
    "Poland": "波兰", "Czech Republic": "捷克", "Romania": "罗马尼亚",
    "South Africa": "南非", "Egypt": "埃及", "Nigeria": "尼日利亚",
    "Israel": "以色列", "Saudi Arabia": "沙特阿拉伯", "United Arab Emirates": "阿联酋",
}

# 可用环境变量 VPNGATE_API_URL 指向镜像/中转（vpngate.net 在部分地区被屏蔽时有用）
API_URL      = os.environ.get("VPNGATE_API_URL", "").strip() or "https://www.vpngate.net/api/iphone/"
if not API_URL.lower().startswith(("http://", "https://")):
    raise RuntimeError(f"VPNGATE_API_URL 只允许 http(s):// 地址: {API_URL!r}")

_ip_cache: dict[str, dict] = {}
_ip_cache_lock = threading.RLock()


# ── API 抓取 ──────────────────────────────────────────────────────────────────
def fetch_api(timeout: int = 20, retries: int = 3) -> str:
    """抓取 VPNGate API，带重试"""
    last_err: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                API_URL,
                headers={"User-Agent": "Mozilla/5.0 vpngate-gateway/2.0"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", errors="replace")
        except Exception as e:
            last_err = e
            if attempt < retries - 1:
                time.sleep(2 ** attempt)  # 指数退避
    raise RuntimeError(f"API 抓取失败（已重试 {retries} 次）: {last_err}")


# ── 节点解析 ──────────────────────────────────────────────────────────────────
# 节点字段来自不可信的公开 API，会被拼进文件名（<id>.ovpn）并用于发起连接，必须先校验：
#   国家码只能是两个大写字母；IP 必须是公网 IPv4（防路径穿越，也防"节点"指向本机/内网服务）。
# 搭私有镜像/内网测试时可设环境变量 VPNGATE_ALLOW_PRIVATE_NODES=1 放开 IP 限制。
_CC_RE = re.compile(r"^[A-Z]{2}$")
_ALLOW_PRIVATE = os.environ.get("VPNGATE_ALLOW_PRIVATE_NODES") == "1"


def _valid_node_ip(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return _ALLOW_PRIVATE or addr.is_global


def parse_nodes(raw: str, country_filter: list[str] | None = None) -> list[dict]:
    """解析 VPNGate CSV，返回节点列表"""
    lines = [l for l in raw.splitlines() if not l.startswith("*")]
    if lines and lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    nodes: list[dict] = []
    seen: set[str] = set()

    for row in reader:
        ip = row.get("IP", "").strip()
        if not ip or ip in seen or not _valid_node_ip(ip):
            continue
        b64 = row.get("OpenVPN_ConfigData_Base64", "").strip()
        if not b64:
            continue
        cc = row.get("CountryShort", "").strip().upper()
        if not _CC_RE.match(cc):
            continue
        if country_filter and cc not in [c.upper() for c in country_filter]:
            continue
        try:
            config_text = base64.b64decode(b64).decode("utf-8", errors="replace")
        except Exception:
            continue

        # 白名单清洗不可信配置；无法安全解析的节点直接丢弃
        config_text = _sanitize_config(config_text)
        if not config_text:
            continue
        host, port, proto = _parse_remote(config_text, ip)
        if not (isinstance(port, int) and 1 <= port <= 65535) or proto not in ("tcp", "udp"):
            continue
        country_long = row.get("CountryLong", "").strip()

        nodes.append({
            "id":            f"{cc}_{ip.replace('.','_')}_{port}",
            "ip":            ip,
            "hostname":      host,
            "port":          port,
            "proto":         proto,
            "country":       COUNTRY_ZH.get(country_long, country_long or cc),
            "country_code":  cc,
            "score":         _safe_int(row.get("Score")),
            "ping":          _safe_int(row.get("Ping")),
            "speed":         _safe_int(row.get("Speed")),
            "uptime_days":   _safe_int(row.get("Uptime")) // 86400,
            "sessions":      _safe_int(row.get("NumVpnSessions")),
            "operator":      row.get("Operator", "").strip()[:40],
            "config_text":   config_text,
            "latency_ms":    0,
            "latency_est":   False,
            "probe_status":  "not_checked",
            "probe_message": "",
            "probed_at":     0.0,
            "isp":           "",
            "location":      "",
            "asn":           "",
            "active":        False,
        })
        seen.add(ip)
    return nodes


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val or default)
    except (ValueError, TypeError):
        return default


# ── 配置清洗（白名单） ────────────────────────────────────────────────────────
# VPNGate 节点由志愿者运营，.ovpn 完全不可信，而 openvpn 以 root 运行。
# 因此不用"删黑名单"，只保留已知安全的指令，其余一律丢弃：
#   up / down / plugin / tls-verify / learn-address ... → 脚本钩子，可 root 执行命令
#   route / redirect-gateway / route-gateway ...        → 篡改宿主机路由表（SSH 断连、流量劫持）
#   config / log / management / ca <路径> / http-proxy  → 读写本地文件、开管理口、改出站路径
# 证书/密钥只接受内联块（<ca> 等）；设备名、路由、认证文件由命令行统一指定。
_ALLOWED_DIRECTIVES = frozenset({
    "client", "tls-client", "pull", "remote", "remote-random", "proto",
    "nobind", "persist-key", "persist-tun",
    "resolv-retry", "connect-retry", "connect-retry-max", "connect-timeout",
    "server-poll-timeout",
    "cipher", "data-ciphers", "data-ciphers-fallback", "ncp-ciphers", "auth",
    "comp-lzo", "compress",
    "remote-cert-tls", "ns-cert-type", "verify-x509-name", "key-direction",
    "tls-version-min", "tls-version-max", "tls-cipher", "tls-ciphersuites",
    "tls-timeout", "hand-window", "tran-window", "reneg-sec",
    "keepalive", "ping", "ping-restart", "ping-exit", "explicit-exit-notify",
    "tun-mtu", "link-mtu", "mssfix", "fragment", "sndbuf", "rcvbuf", "float",
    "replay-window", "mute-replay-warnings", "verb", "mute",
    "auth-nocache", "auth-retry",
})
_ALLOWED_BLOCKS  = frozenset({"ca", "cert", "key", "tls-auth", "tls-crypt", "extra-certs"})
_BLOCK_OPEN      = re.compile(r"^<([A-Za-z0-9_-]+)>$")
_CTRL_CHARS      = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")   # 允许 \t（0x09）；\n 已用于分行
_MAX_CONFIG_SIZE = 64 * 1024
_MAX_LINE_LEN    = 2048


def _sanitize_config(config: str) -> str:
    """
    白名单清洗不可信的 .ovpn 配置。
    无法安全解析（过大/块未闭合/内联块含异常内容/缺少 remote）时返回空串，调用方应丢弃该节点。
    """
    if len(config) > _MAX_CONFIG_SIZE:
        return ""

    out: list[str] = []
    block: str | None = None      # 当前所在块名
    keep_block = False            # 当前块是否输出
    has_remote = has_client = has_cipher = has_auth_retry = False

    for raw in config.replace("\r\n", "\n").split("\n"):
        # ── 块内：按 OpenVPN 语义，只有以 </tag> 开头的原始行才算结束 ──
        if block is not None:
            if raw.startswith(f"</{block}>"):
                if keep_block:
                    out.append(f"</{block}>")
                block = None
            elif keep_block:
                # 内联证书/密钥内容里不可能出现以 < 开头的行或控制字符
                if (raw.startswith("<") or len(raw) > _MAX_LINE_LEN
                        or _CTRL_CHARS.search(raw) or not raw.isascii()):
                    return ""
                out.append(raw)
            continue

        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        if len(line) > _MAX_LINE_LEN or _CTRL_CHARS.search(line) or not line.isascii():
            continue

        m = _BLOCK_OPEN.match(line)
        if m:
            block = m.group(1)
            keep_block = block in _ALLOWED_BLOCKS
            if keep_block:
                out.append(f"<{block}>")
            continue

        name = line.split(None, 1)[0]
        if name not in _ALLOWED_DIRECTIVES:
            continue
        if name == "remote":
            has_remote = True
        elif name in ("client", "tls-client"):
            has_client = True
        elif name in ("cipher", "data-ciphers"):
            has_cipher = True
        elif name == "auth-retry":
            has_auth_retry = True
        out.append(line)

    if block is not None or not has_remote:
        return ""

    if not has_client:
        out.append("client")
    if not has_auth_retry:
        out.append("auth-retry nointeract")
    if not has_cipher:
        out.append("data-ciphers AES-128-CBC:AES-256-GCM:AES-128-GCM")
    out.append("connect-retry-max 1")
    out.append("resolv-retry 5")
    return "\n".join(out)


def _parse_remote(config: str, fallback_ip: str) -> tuple[str, int, str]:
    """从 OpenVPN config 解析 remote host/port/proto"""
    host, port, proto = fallback_ip, 443, "tcp"
    for line in config.splitlines():
        line = line.strip()
        if line.startswith("remote "):
            parts = line.split()
            if len(parts) >= 2:
                host = parts[1]
            if len(parts) >= 3:
                try:
                    port = int(parts[2])
                except ValueError:
                    pass
            if len(parts) >= 4:
                p = parts[3].lower()
                proto = "udp" if "udp" in p else "tcp"
        elif line.startswith("proto "):
            parts = line.split()
            if len(parts) >= 2:
                p = parts[1].lower()
                proto = "udp" if "udp" in p else "tcp"
    return host, port, proto


# ── 延迟测试 ──────────────────────────────────────────────────────────────────
def tcp_latency(host: str, port: int, timeout: float = 4.0) -> int:
    """TCP 握手延迟（ms）。失败返回 0，超时返回 0。"""
    try:
        # 使用系统 DNS 解析（比自制 DNS 更可靠）
        addrs = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        if not addrs:
            return 0
        _, _, _, _, sa = addrs[0]
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.monotonic()
        s.connect(sa)
        ms = int((time.monotonic() - t0) * 1000)
        s.close()
        return max(1, ms)
    except Exception:
        return 0


# P_CONTROL_HARD_RESET_CLIENT_V2 = 7 / P_CONTROL_HARD_RESET_SERVER_V2 = 8（opcode 在高 5 位）
_OVPN_HARD_RESET_CLIENT_V2 = 7
_OVPN_HARD_RESET_SERVER_V2 = 8
UDP_ESTIMATE_BASE = 500   # 无法探测的 UDP 节点：500 + API ping，排在已验证节点之后


def udp_latency(host: str, port: int, timeout: float = 3.0) -> int:
    """
    OpenVPN/UDP 存活探测：发送 HARD_RESET_CLIENT_V2，存活的服务端会回 HARD_RESET_SERVER_V2。
    返回值：>0 往返延迟 ms；0 无应答（未知：可能启用了 tls-auth/tls-crypt 或被限速）；
            -1 收到 ICMP 端口不可达/无法解析（确定不可用）。
    """
    pkt = (bytes([_OVPN_HARD_RESET_CLIENT_V2 << 3]) + os.urandom(8)
           + b"\x00" + b"\x00\x00\x00\x00")        # session_id + 空 ACK 数组 + packet_id=0
    try:
        sa = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
    except (OSError, IndexError):
        return -1
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(sa)                      # 已连接的 UDP 套接字才能收到 ICMP 不可达
        for _ in range(2):                 # UDP 可能丢包：发两次，各等一半时间
            t0 = time.monotonic()
            deadline = t0 + timeout / 2
            s.send(pkt)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                s.settimeout(remaining)
                try:
                    data = s.recv(2048)
                except socket.timeout:
                    break
                if data and (data[0] >> 3) == _OVPN_HARD_RESET_SERVER_V2:
                    return max(1, int((time.monotonic() - t0) * 1000))
        return 0
    except ConnectionRefusedError:
        return -1
    except OSError:
        return 0
    finally:
        s.close()


def measure_node(n: dict, timeout: float = 4.0) -> dict:
    """
    测量节点延迟，写入 latency_ms / latency_est 并返回该节点。
    TCP 节点：握手耗时。UDP 节点：HARD_RESET 探测；无应答时不能判死，
    用 500+API ping 作估算值（latency_est=True），由 OpenVPN 握手验证/实际连接再裁决。
    """
    n["latency_est"] = False
    if n.get("proto") == "udp":
        r = udp_latency(n["ip"], n["port"], min(timeout, 3.0))
        if r > 0:
            n["latency_ms"] = r
        elif r == 0:
            n["latency_ms"] = UDP_ESTIMATE_BASE + max(1, _safe_int(n.get("ping")))
            n["latency_est"] = True
        else:
            n["latency_ms"] = 0
    else:
        n["latency_ms"] = tcp_latency(n["ip"], n["port"], timeout)
    return n


# ── OpenVPN 握手验证 ──────────────────────────────────────────────────────────
def test_openvpn(config_text: str, timeout: int = 18) -> tuple[bool, str]:
    """
    快速 OpenVPN 握手验证（--route-nopull，不改系统路由）
    tun 设备用随机名，避免与主连接冲突
    返回 (ok, message)
    """
    import tempfile, random, string
    suffix = "".join(random.choices(string.ascii_lowercase, k=4))
    tun_dev = f"tun9{suffix}"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".ovpn", delete=False) as f:
        f.write(config_text)
        tmp_cfg = f.name

    tmp_auth = tmp_cfg + ".auth"
    with open(tmp_auth, "w") as f:
        f.write("vpn\nvpn\n")

    cmd = [
        "openvpn",
        "--config", tmp_cfg,
        "--route-nopull",
        "--dev", tun_dev,
        "--dev-type", "tun",
        "--connect-retry-max", "1",
        "--connect-timeout", "12",
        "--auth-user-pass", tmp_auth,
        "--auth-nocache",
        "--capath", "/etc/ssl/certs",
        "--verb", "3",
        # 注意：不能加 --log。--log 会把输出重定向到文件，stdout 就读不到
        # "Initialization Sequence Completed"，每次验证都会超时（原版的 bug）。
        # 仅允许内置 ifconfig/route；不能设为 0（会连 tun 地址都配不上）
        "--script-security", "1",
        "--pull-filter", "ignore", "redirect-gateway",
    ]
    ok, msg = False, "超时"
    proc: subprocess.Popen | None = None
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace"
        )
        q: queue.Queue[str | None] = queue.Queue()

        def _reader():
            assert proc and proc.stdout
            for line in proc.stdout:
                q.put(line.rstrip())
            q.put(None)

        threading.Thread(target=_reader, daemon=True).start()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                line = q.get(timeout=0.5)
            except queue.Empty:
                if proc.poll() is not None:
                    msg = "进程退出"
                    break
                continue
            if line is None:
                break
            low = line.lower()
            if "initialization sequence completed" in low:
                ok, msg = True, "握手成功"
                break
            if "auth_failed" in low or "authentication failed" in low:
                msg = "AUTH_FAILED（节点需要凭证）"
                break
            if "connection refused" in low or "connection timed out" in low:
                msg = "连接被拒绝/超时"
                break
    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        for p in (tmp_cfg, tmp_auth):
            try:
                os.unlink(p)
            except Exception:
                pass
    return ok, msg


# ── IP 信息查询 ───────────────────────────────────────────────────────────────
def enrich_ip(nodes: list[dict], cache_ttl: int = 7 * 86400) -> None:
    """批量查询 IP 地理/ISP 信息（ip-api.com 批量接口，每批≤100）"""
    now = time.time()
    with _ip_cache_lock:
        to_query = [
            n["ip"] for n in nodes
            if n["ip"] not in _ip_cache
            or now - _ip_cache[n["ip"]].get("at", 0) > cache_ttl
        ]

    if not to_query:
        _apply_ip_cache(nodes)
        return

    # 分批查询（每批 100 个）
    for i in range(0, len(to_query), 100):
        batch = to_query[i:i + 100]
        try:
            payload = json.dumps(batch).encode()
            req = urllib.request.Request(
                "http://ip-api.com/batch?fields=status,query,country,city,isp,org,as",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "vpngate-gateway/2.0",
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=12) as r:
                data: list[dict] = json.loads(r.read())
            with _ip_cache_lock:
                for item in data:
                    if item.get("status") == "success":
                        _ip_cache[item["query"]] = {
                            "isp":      item.get("org") or item.get("isp") or "",
                            "location": f"{item.get('country','')} {item.get('city','')}".strip(),
                            "asn":      item.get("as", ""),
                            "at":       now,
                        }
        except Exception:
            pass

    _apply_ip_cache(nodes)


def _apply_ip_cache(nodes: list[dict]) -> None:
    with _ip_cache_lock:
        for n in nodes:
            info = _ip_cache.get(n["ip"], {})
            n["isp"]      = info.get("isp", "")
            n["location"] = info.get("location", "")
            n["asn"]      = info.get("asn", "")


# ── 出口 IP 检测 ──────────────────────────────────────────────────────────────
# 不再调用 curl：代理开启认证后，口令放在 curl 命令行会被同机其他用户用 ps 看到。
_IP_ENDPOINTS = (("api.ipify.org", "/"), ("ipv4.icanhazip.com", "/"))


def _recv_n(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("连接提前关闭")
        buf += chunk
    return buf


def _socks5_open(proxy_port: int, host: str, port: int,
                 user: str = "", password: str = "", timeout: float = 8.0) -> socket.socket:
    """通过本机 SOCKS5 代理连接 host:port（域名由代理解析），返回已连通的套接字"""
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    try:
        s.settimeout(timeout)
        s.sendall(b"\x05\x02\x00\x02")                 # 同时提供 无认证 / 用户名密码
        ver, method = _recv_n(s, 2)
        if ver != 5:
            raise OSError("不是 SOCKS5 服务")
        if method == 2:
            if not user:
                raise OSError("代理需要认证，但未提供凭据")
            u, p = user.encode(), password.encode()
            s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            if _recv_n(s, 2)[1] != 0:
                raise OSError("代理认证失败")
        elif method != 0:
            raise OSError(f"代理拒绝了认证方式（{method}）")
        h = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack("!H", port))
        head = _recv_n(s, 4)
        if head[1] != 0:
            raise OSError(f"代理连接失败（SOCKS5 code={head[1]}）")
        atyp = head[3]                       # 跳过 BND.ADDR + BND.PORT
        if atyp == 1:
            _recv_n(s, 4 + 2)
        elif atyp == 4:
            _recv_n(s, 16 + 2)
        elif atyp == 3:
            _recv_n(s, _recv_n(s, 1)[0] + 2)
        else:
            raise OSError(f"未知地址类型 {atyp}")
        return s
    except Exception:
        s.close()
        raise


def check_proxy(port: int = 7928, user: str = "", password: str = "", timeout: int = 8) -> dict:
    """
    通过本地 SOCKS5 代理检测当前出口 IP。
    返回 {"ok": bool, "ip": str, "ms": int}
    """
    for host, path in _IP_ENDPOINTS:
        t0 = time.monotonic()
        try:
            s = _socks5_open(port, host, 80, user, password, timeout)
        except Exception:
            continue
        try:
            s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: vpngate-gateway\r\n"
                      f"Connection: close\r\n\r\n".encode())
            raw = b""
            while len(raw) < 8192:
                chunk = s.recv(2048)
                if not chunk:
                    break
                raw += chunk
            head, _, body = raw.partition(b"\r\n\r\n")
            if not head.startswith(b"HTTP/") or b" 200" not in head.split(b"\r\n")[0]:
                continue
            m = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", body.decode("ascii", errors="replace"))
            if not m:
                continue
            ip = str(ipaddress.IPv4Address(m.group(0)))
            return {"ok": True, "ip": ip, "ms": int((time.monotonic() - t0) * 1000)}
        except Exception:
            continue
        finally:
            s.close()
    return {"ok": False, "ip": "", "ms": 0}


def direct_ip(timeout: int = 6) -> str:
    """不经代理（走默认路由 = 物理网卡）查询 VPS 自身的出口 IP，用于泄漏检测；失败返回空串"""
    for host, path in _IP_ENDPOINTS:
        try:
            req = urllib.request.Request(f"http://{host}{path}", headers={"User-Agent": "vpngate-gateway"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                text = r.read(128).decode("ascii", errors="replace")
                m = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
                if m:
                    return str(ipaddress.IPv4Address(m.group(0)))
        except Exception:
            continue
    return ""
