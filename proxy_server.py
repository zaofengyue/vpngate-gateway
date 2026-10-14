#!/usr/bin/env python3
"""
HTTP/SOCKS5 双协议代理服务器
所有出站连接通过 SO_BINDTODEVICE 强制绑定 tun0
VPN 断开（tun0 不存在）时直接返回 502，不回落到真实 IP
"""
from __future__ import annotations
import base64
import hmac
import secrets
import select
import socket
import struct
import threading
import time
import urllib.parse
import os
import logging
from typing import Optional

log = logging.getLogger("proxy")

BIND_DEVICE   = b"tun0"
CONNECT_TIMEOUT = 20.0
RELAY_TIMEOUT   = 300.0   # 5 分钟无数据后断开


# ── tun0 状态检查 ─────────────────────────────────────────────────────────────
def _tun0_exists() -> bool:
    """网卡存在且处于 UP（读 /sys/class/net/<dev>/flags 的 IFF_UP 位）"""
    try:
        with open(f"/sys/class/net/{BIND_DEVICE.decode()}/flags") as f:
            return int(f.read().strip(), 16) & 0x1 == 0x1
    except (OSError, ValueError):
        return False


# ── 代理认证 ──────────────────────────────────────────────────────────────────
# 代理只监听 127.0.0.1，但同机任何用户/进程都能连上来蹭出口。
# 配置 proxy_user / proxy_pass 后：SOCKS5 走 RFC1929 用户名密码，HTTP 走 Proxy-Authorization: Basic。
_AUTH: Optional[tuple[bytes, bytes]] = None
AUTH_FAIL_DELAY = 0.3          # 认证失败后的延迟，减缓暴力猜解
HANDSHAKE_TIMEOUT = 15.0       # 握手阶段超时，防止半开连接长期占线程
MAX_CONNECTIONS = 512


def configure_auth(user: str, password: str) -> bool:
    """设置代理认证。两者都为空=不启用（返回 False）；只填一个或过长则抛 ValueError"""
    global _AUTH
    u, p = (user or "").encode("utf-8"), (password or "").encode("utf-8")
    if not u and not p:
        _AUTH = None
        return False
    if not u or not p or len(u) > 255 or len(p) > 255:
        raise ValueError("proxy_user 与 proxy_pass 必须同时设置，且各不超过 255 字节")
    _AUTH = (u, p)
    return True


def _check_credentials(u: bytes, p: bytes) -> bool:
    if _AUTH is None:
        return True
    ok_user = hmac.compare_digest(u, _AUTH[0])      # 两项都比较，避免短路泄露信息
    ok_pass = hmac.compare_digest(p, _AUTH[1])
    return ok_user and ok_pass


def _http_authorized(lines: list[str]) -> bool:
    if _AUTH is None:
        return True
    for line in lines[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() != "proxy-authorization":
            continue
        scheme, _, token = value.strip().partition(" ")
        if scheme.lower() != "basic":
            return False
        try:
            raw = base64.b64decode(token.strip(), validate=True)
        except Exception:
            return False
        user, sep, password = raw.partition(b":")
        return bool(sep) and _check_credentials(user, password)
    return False


# ── 工具 ──────────────────────────────────────────────────────────────────────
def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("连接提前关闭")
        data += chunk
    return data


# ── 隧道内 DNS 解析 ───────────────────────────────────────────────────────────
# 系统解析器（getaddrinfo）走物理网卡，会把用户访问的域名泄漏给 VPS 的 DNS，
# 还可能返回被污染的结果。这里自带一个最小 A 记录解析器，查询包同样
# SO_BINDTODEVICE 绑定 tun0：隧道不通就解析失败，绝不回落到物理网卡。
DNS_SERVERS: list[str] = ["1.1.1.1", "8.8.8.8"]
DNS_TIMEOUT      = 3.0
_DNS_MIN_TTL     = 30
_DNS_MAX_TTL     = 600
_DNS_CACHE_MAX   = 2048
_dns_cache: dict[str, tuple[float, list[str]]] = {}
_dns_lock = threading.Lock()


def configure_dns(servers: list[str]) -> None:
    """设置隧道 DNS（仅接受合法 IPv4；全部非法时保持原值）"""
    valid = []
    for item in servers:
        item = item.strip()
        try:
            socket.inet_pton(socket.AF_INET, item)
        except OSError:
            continue
        valid.append(item)
    if valid:
        DNS_SERVERS[:] = valid


def _encode_qname(name: str) -> bytes:
    name = name.rstrip(".")
    if not name or len(name) > 253:
        raise ValueError("域名长度非法")
    out = bytearray()
    for label in name.split("."):
        try:
            raw = label.encode("ascii")
        except UnicodeEncodeError:
            raw = label.encode("idna")
        if not 1 <= len(raw) <= 63:
            raise ValueError("域名标签长度非法")
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def _skip_name(data: bytes, pos: int) -> int:
    while True:
        if pos >= len(data):
            raise ValueError("报文被截断")
        n = data[pos]
        if n == 0:
            return pos + 1
        if n & 0xC0 == 0xC0:        # 压缩指针：占 2 字节，名字到此结束
            return pos + 2
        if n & 0xC0:
            raise ValueError("非法标签")
        pos += 1 + n


def _parse_response(data: bytes, qid: int, qname: bytes) -> tuple[int, bool, list[str], int]:
    """解析 DNS 响应 → (rcode, 是否截断, A 记录列表, 最小 TTL)；格式不符抛 ValueError"""
    try:
        if len(data) < 12:
            raise ValueError("报文过短")
        rid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
        if rid != qid or not flags & 0x8000 or qd != 1:
            raise ValueError("不是对应的响应")
        if data[12:12 + len(qname)].lower() != qname.lower():
            raise ValueError("问题段不匹配")
        pos = 12 + len(qname) + 4
        rcode, tc = flags & 0xF, bool(flags & 0x0200)
        ips: list[str] = []
        ttl_min = _DNS_MAX_TTL
        for _ in range(an):
            pos = _skip_name(data, pos)
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
            pos += 10
            rdata = data[pos:pos + rdlen]
            pos += rdlen
            if len(rdata) != rdlen:
                raise ValueError("报文被截断")
            if rtype == 1 and rclass == 1 and rdlen == 4:
                ips.append(socket.inet_ntoa(rdata))
                ttl_min = min(ttl_min, ttl)
        return rcode, tc, ips, ttl_min
    except struct.error as e:
        raise ValueError(f"报文格式错误: {e}") from e


def _dns_udp(server: str, pkt: bytes, qid: int, qname: bytes):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, BIND_DEVICE)
        deadline = time.monotonic() + DNS_TIMEOUT
        s.sendto(pkt, (server, 53))
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout("DNS 查询超时")
            s.settimeout(remaining)
            data, addr = s.recvfrom(4096)
            if addr[0] != server or addr[1] != 53:
                continue                      # 来源不符，丢弃（防伪造）
            try:
                return _parse_response(data, qid, qname)
            except ValueError:
                continue                      # ID/问题段不符，继续等
    finally:
        s.close()


def _dns_tcp(server: str, pkt: bytes, qid: int, qname: bytes):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(DNS_TIMEOUT)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, BIND_DEVICE)
        s.connect((server, 53))
        s.sendall(struct.pack("!H", len(pkt)) + pkt)
        size = struct.unpack("!H", _recv_exact(s, 2))[0]
        try:
            return _parse_response(_recv_exact(s, size), qid, qname)
        except ValueError as e:
            raise OSError(f"DNS(TCP) 响应无效: {e}") from e
    finally:
        s.close()


def _resolve(host: str) -> list[str]:
    """经隧道解析 IPv4 地址。绝不调用系统解析器。"""
    try:
        socket.inet_pton(socket.AF_INET, host)
        return [host]                          # 已是 IPv4 字面量
    except OSError:
        pass
    if ":" in host:
        raise OSError("暂不支持 IPv6 地址")

    key = host.lower().rstrip(".")
    now = time.monotonic()
    with _dns_lock:
        hit = _dns_cache.get(key)
        if hit and hit[0] > now:
            return list(hit[1])

    try:
        qname = _encode_qname(key)
    except (ValueError, UnicodeError) as e:
        raise OSError(f"非法域名: {host}") from e

    last_err: Exception = OSError("无可用 DNS 服务器")
    for server in list(DNS_SERVERS):
        qid = secrets.randbits(16)
        pkt = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
        try:
            rcode, tc, ips, ttl = _dns_udp(server, pkt, qid, qname)
            if tc:
                rcode, tc, ips, ttl = _dns_tcp(server, pkt, qid, qname)
        except OSError as e:
            last_err = e
            continue
        if rcode == 3:
            raise OSError(f"域名不存在: {host}")
        if rcode != 0:
            last_err = OSError(f"DNS 错误 rcode={rcode}（{server}）")
            continue
        if not ips:
            last_err = OSError(f"{host} 没有 A 记录")
            continue
        ttl = max(_DNS_MIN_TTL, min(_DNS_MAX_TTL, ttl))
        with _dns_lock:
            if len(_dns_cache) >= _DNS_CACHE_MAX:
                _dns_cache.pop(next(iter(_dns_cache)))
            _dns_cache[key] = (time.monotonic() + ttl, ips)
        return list(ips)
    raise last_err


def _create_upstream(host: str, port: int, timeout: float = CONNECT_TIMEOUT) -> socket.socket:
    """
    创建出站 TCP 连接，强制绑定 tun0。
    tun0 不存在时抛出 OSError（上层转为 502）。
    """
    if not _tun0_exists():
        raise OSError("tun0 未就绪，VPN 未连接")

    # 域名经隧道解析（不用系统解析器，避免 DNS 经物理网卡泄漏）
    ips = _resolve(host)

    last_err: Exception = OSError("无可用地址")
    for ip in ips:
        s: Optional[socket.socket] = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, BIND_DEVICE)
            s.connect((ip, port))
            s.settimeout(None)   # 进入 relay 后用 select，不需要超时
            return s
        except OSError as e:
            last_err = e
            if s:
                try:
                    s.close()
                except Exception:
                    pass
    raise last_err


# ── 双向中继 ──────────────────────────────────────────────────────────────────
def _relay(left: socket.socket, right: socket.socket) -> None:
    """
    双向透传，任一端关闭或超时则退出。
    """
    sockets = [left, right]
    try:
        while True:
            readable, _, errored = select.select(sockets, [], sockets, RELAY_TIMEOUT)
            if errored or not readable:
                return
            for src in readable:
                dst = right if src is left else left
                try:
                    data = src.recv(65536)
                    if not data:
                        return
                    dst.sendall(data)
                except OSError:
                    return
    except Exception:
        pass


# ── SOCKS5 ────────────────────────────────────────────────────────────────────
def _handle_socks5(client: socket.socket) -> None:
    upstream: Optional[socket.socket] = None
    try:
        client.settimeout(HANDSHAKE_TIMEOUT)
        # 握手
        n_methods = _recv_exact(client, 1)[0]
        methods = _recv_exact(client, n_methods)
        if _AUTH is None:
            client.sendall(b"\x05\x00")           # 无认证
        else:
            if 0x02 not in methods:                # 客户端不支持用户名密码
                client.sendall(b"\x05\xff")
                return
            client.sendall(b"\x05\x02")
            if _recv_exact(client, 1)[0] != 0x01:  # RFC1929 子协商版本
                return
            user = _recv_exact(client, _recv_exact(client, 1)[0])
            password = _recv_exact(client, _recv_exact(client, 1)[0])
            if not _check_credentials(user, password):
                time.sleep(AUTH_FAIL_DELAY)
                client.sendall(b"\x01\x01")
                return
            client.sendall(b"\x01\x00")

        # 请求
        header = _recv_exact(client, 4)
        ver, cmd, _, atype = header
        if ver != 5:
            return
        if cmd != 1:                              # 只支持 CONNECT
            client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return

        if atype == 0x01:                         # IPv4
            host = socket.inet_ntoa(_recv_exact(client, 4))
        elif atype == 0x03:                       # 域名
            dlen = _recv_exact(client, 1)[0]
            host = _recv_exact(client, dlen).decode("utf-8", errors="replace")
        elif atype == 0x04:                       # IPv6
            host = socket.inet_ntop(socket.AF_INET6, _recv_exact(client, 16))
        else:
            client.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
            return

        port = struct.unpack("!H", _recv_exact(client, 2))[0]

        try:
            upstream = _create_upstream(host, port)
        except OSError as e:
            # tun0 不可用或连接失败 → Host unreachable (0x04)
            log.warning(f"SOCKS5 上游连接失败 {host}:{port} — {e}")
            client.sendall(b"\x05\x04\x00\x01" + b"\x00" * 6)
            return

        client.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        client.settimeout(None)
        _relay(client, upstream)
    except Exception as e:
        log.debug(f"SOCKS5 处理异常: {e}")
    finally:
        _safe_close(client)
        _safe_close(upstream)


# ── HTTP/HTTPS ────────────────────────────────────────────────────────────────
def _handle_http(client: socket.socket, first_byte: bytes) -> None:
    upstream: Optional[socket.socket] = None
    try:
        # 读完整请求头
        buf = first_byte
        client.settimeout(10)
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            chunk = client.recv(4096)
            if not chunk:
                break
            buf += chunk
        client.settimeout(None)

        head, _, body = buf.partition(b"\r\n\r\n")
        try:
            head_str = head.decode("iso-8859-1")
        except Exception:
            return
        lines = head_str.split("\r\n")
        if not lines:
            return

        parts = lines[0].split(" ", 2)
        if len(parts) < 2:
            return
        method, target = parts[0], parts[1]

        if not _http_authorized(lines):
            time.sleep(AUTH_FAIL_DELAY)
            _send_ignore(client, b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                                 b"Proxy-Authenticate: Basic realm=\"vpngate\"\r\n"
                                 b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            return

        if method.upper() == "CONNECT":
            # HTTPS 隧道
            if ":" in target:
                host, _, port_s = target.rpartition(":")
                port = int(port_s) if port_s.isdigit() else 443
            else:
                host, port = target, 443
            try:
                upstream = _create_upstream(host, port)
            except OSError as e:
                log.warning(f"CONNECT 上游失败 {target} — {e}")
                _send_ignore(client, b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                return
            _send_ignore(client, b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if body:
                _send_ignore(upstream, body)
            _relay(client, upstream)
            return

        # 普通 HTTP 代理
        parsed = urllib.parse.urlsplit(target)
        if not parsed.hostname:
            return
        port   = parsed.port or 80
        path   = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        # 过滤 Proxy- 头
        fwd_headers = [
            l for l in lines[1:]
            if l and not l.lower().startswith(("proxy-connection:", "proxy-authorization:"))
        ]
        req = (
            f"{method} {path} HTTP/1.1\r\n"
            + "\r\n".join(fwd_headers)
            + "\r\nConnection: close\r\n\r\n"
        )
        try:
            upstream = _create_upstream(parsed.hostname, port)
        except OSError as e:
            log.warning(f"HTTP 上游失败 {parsed.hostname}:{port} — {e}")
            _send_ignore(client, b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        upstream.sendall(req.encode("iso-8859-1") + body)
        _relay(client, upstream)

    except Exception as e:
        log.debug(f"HTTP 处理异常: {e}")
        _send_ignore(client, b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
    finally:
        _safe_close(client)
        _safe_close(upstream)


# ── 分派 ──────────────────────────────────────────────────────────────────────
_conn_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)


def _handle_client(client: socket.socket) -> None:
    try:
        client.settimeout(15)
        first = _recv_exact(client, 1)
        client.settimeout(None)
        if first == b"\x05":
            _handle_socks5(client)
        else:
            _handle_http(client, first)
    except Exception as e:
        log.debug(f"客户端分派异常: {e}")
        _safe_close(client)
    finally:
        _conn_slots.release()


def _safe_close(s: Optional[socket.socket]) -> None:
    if s is None:
        return
    try:
        s.close()
    except Exception:
        pass


def _send_ignore(s: socket.socket, data: bytes) -> None:
    try:
        s.sendall(data)
    except Exception:
        pass


# ── 入口 ──────────────────────────────────────────────────────────────────────
def start_proxy_server(
    host: str = "127.0.0.1",
    port: int = 7928,
    backlog: int = 256,
) -> None:
    """启动代理服务器（阻塞）"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(backlog)
    print(f"[代理] HTTP/SOCKS5 监听 {host}:{port}", flush=True)
    while True:
        try:
            client, addr = server.accept()
            if not _conn_slots.acquire(blocking=False):   # 并发达到上限：直接拒绝，保护 fd/线程
                _safe_close(client)
                continue
            threading.Thread(
                target=_handle_client,
                args=(client,),
                daemon=True,
                name=f"proxy-{addr[0]}:{addr[1]}",
            ).start()
        except Exception as e:
            log.error(f"[代理] accept 异常: {e}")
            time.sleep(0.5)
