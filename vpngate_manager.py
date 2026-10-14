#!/usr/bin/env python3
"""
VPNGate Gateway 核心管理器
"""
from __future__ import annotations
import concurrent.futures
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import vpn_utils
import proxy_server

# ── 配置 ──────────────────────────────────────────────────────────────────────
INSTALL_DIR  = Path("/opt/vpngate-gateway")
DATA_DIR     = INSTALL_DIR / "data"
NODES_FILE   = DATA_DIR / "nodes.json"
STATE_FILE   = DATA_DIR / "state.json"
CONFIG_DIR   = DATA_DIR / "configs"
AUTH_FILE    = DATA_DIR / "auth.txt"
LOG_FILE     = DATA_DIR / "vpngate.log"
SETTINGS_FILE= DATA_DIR / "settings.json"
CMD_FILE     = DATA_DIR / "cmd.json"
CMD_RESULT   = DATA_DIR / "cmd_result.json"

PROXY_HOST   = "127.0.0.1"
PROXY_PORT   = 7928
TUN_DEV      = "tun0"
ROUTE_TABLE  = 100

_WD_MIN_INTERVAL = 30
_WD_MAX_INTERVAL = 600
_WD_BACKOFF_MULT = 2.0

# ── 全局状态 ──────────────────────────────────────────────────────────────────
_lock                         = threading.RLock()
_active_process: subprocess.Popen | None = None
_active_node_id: str          = ""
_is_connecting: bool          = False
_rotate_timer: threading.Timer | None  = None
_latency_timer: threading.Timer | None = None
_wd_fail_count: int           = 0
_outlet_fail_count: int       = 0  # 出口连通性连续失败计数

# ── 持久化 ────────────────────────────────────────────────────────────────────
def _read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default if default is not None else {}

def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)

# ── 设置 ──────────────────────────────────────────────────────────────────────
def load_settings() -> dict:
    defaults: dict = {
        "country_filter":      [],
        "rotate_hours":        2,
        "latency_check_hours": 1,    # 定时延迟检测间隔，0=关闭
        "min_nodes":           5,    # 节点数低于此值时自动重新抓取
        "top_nodes":           20,
        "proxy_port":          7928,
        "probe_count":         10,
        "auto_fetch_on_start": True,
        "outlet_check_interval": 60,   # 出口连通性检测间隔（秒），0=关闭
        "outlet_max_fails":     3,     # 连续失败N次后触发轮换
    }
    saved = _read_json(SETTINGS_FILE, {})
    defaults.update(saved)
    return defaults

def save_settings(s: dict) -> None:
    _write_json(SETTINGS_FILE, s)

# ── 节点 & 状态 ───────────────────────────────────────────────────────────────
def get_nodes() -> list[dict]:
    return _read_json(NODES_FILE, [])

def save_nodes(nodes: list[dict]) -> None:
    _write_json(NODES_FILE, nodes)

def get_state() -> dict:
    s = _read_json(STATE_FILE, {})
    s["active_node_id"] = _active_node_id
    s["is_connecting"]  = _is_connecting
    s["pid"]            = os.getpid()
    return s

def _update_state(**kw: Any) -> None:
    s = _read_json(STATE_FILE, {})
    s["active_node_id"] = _active_node_id
    s["is_connecting"]  = _is_connecting
    s.update(kw)
    _write_json(STATE_FILE, s)

# ── 日志 ──────────────────────────────────────────────────────────────────────
_log_lock = threading.Lock()

def log(msg: str) -> None:
    ts   = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _log_lock:
            if LOG_FILE.exists() and LOG_FILE.stat().st_size > 5 * 1024 * 1024:
                LOG_FILE.rename(LOG_FILE.with_suffix(".log.1"))
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception:
        pass

# ── 策略路由 ──────────────────────────────────────────────────────────────────
def _run(*args: str) -> int:
    """执行外部命令，命令不存在（如精简系统缺少 ip/pkill）时返回 127 而不是崩溃"""
    try:
        return subprocess.run(list(args), capture_output=True).returncode
    except OSError:
        return 127

_ovpn_version_cache: tuple[int, int] | None = None

def _openvpn_version() -> tuple[int, int]:
    """返回 OpenVPN (major, minor)，解析失败按 2.4 处理"""
    global _ovpn_version_cache
    if _ovpn_version_cache is not None:
        return _ovpn_version_cache
    ver = (2, 4)
    try:
        r = subprocess.run(["openvpn", "--version"], capture_output=True, text=True, timeout=5)
        m = re.search(r"OpenVPN\s+(\d+)\.(\d+)", (r.stdout or "") + (r.stderr or ""))
        if m:
            ver = (int(m.group(1)), int(m.group(2)))
    except Exception:
        pass
    _ovpn_version_cache = ver
    return ver

def _setup_routing() -> None:
    log(f"[路由] 等待 {TUN_DEV} 就绪...")
    for _ in range(30):
        if _run("ip", "link", "show", TUN_DEV) == 0:
            break
        time.sleep(1)
    else:
        log(f"[路由] 警告：{TUN_DEV} 30秒内未就绪")
        return
    _cleanup_routing()
    rc_route = _run("ip", "route", "add", "default", "dev", TUN_DEV, "table", str(ROUTE_TABLE))
    rc_rule  = _run("ip", "rule", "add", "oif", TUN_DEV, "table", str(ROUTE_TABLE), "priority", "100")
    if rc_route == 0 and rc_rule == 0:
        log(f"[路由] 策略路由已配置：oif={TUN_DEV} → table {ROUTE_TABLE}")
    else:
        log(f"[路由] 警告：策略路由配置失败（route={rc_route}, rule={rc_rule}），请确认已安装 iproute2（Alpine: apk add iproute2）")

def _cleanup_routing() -> None:
    _run("ip", "rule", "del", "table", str(ROUTE_TABLE))
    _run("ip", "route", "flush", "table", str(ROUTE_TABLE))

# ── OpenVPN ───────────────────────────────────────────────────────────────────
def _openvpn_alive() -> bool:
    return _active_process is not None and _active_process.poll() is None

def _stop_openvpn() -> None:
    global _active_process, _active_node_id
    _cleanup_routing()
    if _active_process:
        if _active_process.poll() is None:
            _active_process.terminate()
            try:
                _active_process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                _active_process.kill()
        _active_process = None
    _run("pkill", "-f", r"openvpn.*vpngate-gateway")
    _active_node_id = ""

def _launch_openvpn(node: dict) -> tuple[bool, str]:
    global _active_process, _active_node_id

    cfg_path = CONFIG_DIR / f"{node['id']}.ovpn"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(node["config_text"], encoding="utf-8")
    AUTH_FILE.write_text("vpn\nvpn\n", encoding="utf-8")
    AUTH_FILE.chmod(0o600)

    cmd = [
        "openvpn",
        "--config",            str(cfg_path),
        "--dev",               TUN_DEV,
        "--dev-type",          "tun",
        "--route-nopull",
        "--connect-retry-max", "1",
        "--connect-timeout",   "20",
        "--auth-user-pass",    str(AUTH_FILE),
        "--auth-nocache",
        "--capath", "/etc/ssl/certs",
        "--pull-filter", "ignore", "route-ipv6",
        "--pull-filter", "ignore", "ifconfig-ipv6",
        "--verb", "3",
    ]
    # VPNGate 节点多为 AES-128-CBC；OpenVPN 2.6（如 Alpine）默认密码列表更严格，显式声明以保证兼容
    ciphers = "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"
    if _openvpn_version() >= (2, 5):
        cmd += ["--data-ciphers", ciphers]
    else:
        cmd += ["--ncp-ciphers", ciphers]

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace"
    )
    q: queue.Queue[str | None] = queue.Queue()
    streaming = [True]

    def _reader() -> None:
        assert proc.stdout
        for line in proc.stdout:
            s = line.rstrip()
            q.put(s)
            if not streaming[0]:
                log(f"[VPN] {s}")
        q.put(None)

    threading.Thread(target=_reader, daemon=True).start()

    ok, msg = False, "超时（40s）"
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        try:
            line = q.get(timeout=0.5)
        except queue.Empty:
            if proc.poll() is not None:
                msg = f"进程退出（code={proc.returncode}）"
                break
            continue
        if line is None:
            msg = "进程退出"
            break
        low = line.lower()
        if "initialization sequence completed" in low:
            ok, msg = True, "连接成功"
            break
        if "auth_failed" in low or "authentication failed" in low:
            msg = "AUTH_FAILED"
            break
        if "connection refused" in low:
            msg = "连接被拒绝"
            break
        if "tls handshake failed" in low:
            msg = "TLS握手失败"
            break

    streaming[0] = False

    if ok:
        _active_process = proc
        _active_node_id = node["id"]
        threading.Thread(target=_setup_routing, daemon=True).start()
    else:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            pass

    return ok, msg

# ── 节点抓取 ──────────────────────────────────────────────────────────────────
def fetch_and_test(
    country_filter: list[str] | None = None,
    top: int = 20,
    probe_count: int = 10,
    auto_connect_after: bool = False,
) -> list[dict]:
    """抓取节点，直接覆盖现有列表，完成后可自动连接"""
    log("[抓取] 正在获取 VPNGate 节点列表...")
    _update_state(message="正在获取节点列表...", fetching=True)
    try:
        raw = vpn_utils.fetch_api()
    except RuntimeError as e:
        log(f"[抓取] 失败: {e}")
        _update_state(message=str(e), fetching=False)
        raise

    nodes = vpn_utils.parse_nodes(raw, country_filter)
    log(f"[抓取] 解析到 {len(nodes)} 个节点")
    _update_state(message=f"正在测试 {len(nodes)} 个节点延迟...")

    def _do_latency(n: dict) -> dict:
        n["latency_ms"] = vpn_utils.tcp_latency(n["ip"], n["port"])
        return n

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        nodes = list(ex.map(_do_latency, nodes))

    reachable = sorted(
        [n for n in nodes if n["latency_ms"] > 0],
        key=lambda n: n["latency_ms"]
    )[:top]
    log(f"[测速] 可达 {len(reachable)} 个，保留前 {top} 个")
    _update_state(message=f"正在验证 {min(probe_count, len(reachable))} 个节点可用性...")

    check_n = min(probe_count, len(reachable))

    def _do_probe(n: dict) -> dict:
        ok, msg = vpn_utils.test_openvpn(n["config_text"])
        n["probe_status"]  = "available" if ok else "unavailable"
        n["probe_message"] = msg
        n["probed_at"]     = time.time()
        return n

    if check_n > 0:
        workers = min(check_n, 5)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            probed = list(ex.map(_do_probe, reachable[:check_n]))
        reachable[:check_n] = probed
        available = sum(1 for n in probed if n["probe_status"] == "available")
        log(f"[握手] 验证完成：{available}/{check_n} 个可用")
        if available > 0:
            reachable = [n for n in reachable if n.get("probe_status") != "unavailable"]
            log(f"[筛选] 剔除不可用节点后剩余 {len(reachable)} 个")
        else:
            log(f"[筛选] 握手全部失败，保留全部 {len(reachable)} 个节点")

    vpn_utils.enrich_ip(reachable)
    save_nodes(reachable)
    _update_state(
        message=f"节点更新完成，共 {len(reachable)} 个",
        fetching=False,
        fetched_at=time.time(),
    )
    log(f"[完成] 节点列表已保存，共 {len(reachable)} 个节点")

    if auto_connect_after:
        log("[抓取] 自动连接最快节点...")
        ok, msg = auto_connect()
        log(f"[抓取] 自动连接结果: {msg}")

    return reachable

# ── 延迟检测（不抓取，只测现有列表） ─────────────────────────────────────────
def check_latency() -> tuple[int, int]:
    """
    对现有节点列表重新测延迟：
    - 删除不可达节点
    - 按延迟重新排序
    - 节点数不足 min_nodes 时自动触发 fetch_and_test
    返回 (剩余节点数, 删除节点数)
    """
    nodes = get_nodes()
    if not nodes:
        log("[延迟检测] 列表为空，触发抓取...")
        s = load_settings()
        fetch_and_test(
            country_filter=s.get("country_filter") or None,
            top=s.get("top_nodes", 20),
            probe_count=s.get("probe_count", 10),
            auto_connect_after=True,
        )
        return len(get_nodes()), 0

    log(f"[延迟检测] 开始测试 {len(nodes)} 个节点...")
    _update_state(message=f"正在检测 {len(nodes)} 个节点延迟...")

    def _do_latency(n: dict) -> dict:
        n["latency_ms"] = vpn_utils.tcp_latency(n["ip"], n["port"])
        return n

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        nodes = list(ex.map(_do_latency, nodes))

    reachable = sorted(
        [n for n in nodes if n["latency_ms"] > 0],
        key=lambda n: n["latency_ms"]
    )
    removed = len(nodes) - len(reachable)
    log(f"[延迟检测] 删除不可达 {removed} 个，剩余 {len(reachable)} 个")

    s = load_settings()
    min_nodes = s.get("min_nodes", 5)

    if len(reachable) < min_nodes:
        log(f"[延迟检测] 节点数 {len(reachable)} < 最低阈值 {min_nodes}，触发重新抓取...")
        save_nodes(reachable)
        fetch_and_test(
            country_filter=s.get("country_filter") or None,
            top=s.get("top_nodes", 20),
            probe_count=s.get("probe_count", 10),
            auto_connect_after=True,
        )
        return len(get_nodes()), removed

    save_nodes(reachable)
    _update_state(message=f"延迟检测完成，剩余 {len(reachable)} 个节点")

    # 未连接、连接已断、或当前节点被删除 → 自动连接最快节点
    active_ids = {n["id"] for n in reachable}
    if not _openvpn_alive():
        log(f"[延迟检测] 当前未连接，自动连接最快节点...")
        auto_connect()
    elif _active_node_id not in active_ids:
        log(f"[延迟检测] 当前节点已失效，自动切换...")
        auto_connect()

    return len(reachable), removed

# ── 定时延迟检测 ──────────────────────────────────────────────────────────────
def _schedule_latency_check() -> None:
    global _latency_timer
    with _lock:
        if _latency_timer:
            _latency_timer.cancel()
        s = load_settings()
        hours = float(s.get("latency_check_hours", 1))
        if hours <= 0:
            return
        _latency_timer = threading.Timer(hours * 3600, _do_latency_check)
        _latency_timer.daemon = True
        _latency_timer.start()
        log(f"[延迟检测] 已设置 {hours:.1f} 小时后自动检测")

def _do_latency_check() -> None:
    log("[延迟检测] 开始定时检测...")
    remaining, removed = check_latency()
    log(f"[延迟检测] 完成，剩余 {remaining} 个节点，删除 {removed} 个")
    _schedule_latency_check()  # 重新设置下次

# ── 连接管理 ──────────────────────────────────────────────────────────────────
def connect_node(node_id: str) -> tuple[bool, str]:
    global _is_connecting, _wd_fail_count
    with _lock:
        if _is_connecting:
            return False, "正在连接中，请稍候"
        _is_connecting = True

    try:
        nodes = get_nodes()
        node  = next((n for n in nodes if n["id"] == node_id), None)
        if not node:
            return False, f"节点不存在: {node_id}"

        log(f"[连接] 开始连接: {node_id} ({node.get('country','')} {node.get('ip','')})")
        _update_state(message=f"正在连接 {node_id}...", is_connecting=True)
        _stop_openvpn()
        ok, msg = _launch_openvpn(node)

        if ok:
            for n in nodes:
                n["active"] = (n["id"] == node_id)
            save_nodes(nodes)
            _update_state(
                message=f"已连接: {node_id}",
                is_connecting=False,
                connected_at=time.time(),
                connected_node=node_id,
                active_node_id=node_id,
            )
            log(f"[连接] 成功: {node_id} | 延迟 {node.get('latency_ms',0)} ms")
            _wd_fail_count = 0
            _schedule_rotate()
        else:
            _update_state(message=f"连接失败: {msg}", is_connecting=False)
            log(f"[连接] 失败: {node_id} — {msg}")
            # 标记该节点不可用，避免下次 auto_connect 继续选它
            for n in nodes:
                if n["id"] == node_id:
                    n["probe_status"]  = "unavailable"
                    n["probe_message"] = msg
                    break
            save_nodes(nodes)

        return ok, msg
    finally:
        _is_connecting = False

def auto_connect(country: str | None = None) -> tuple[bool, str]:
    nodes = get_nodes()
    if not nodes:
        return False, "没有节点，请先执行 fetch"
    if country:
        filtered = [n for n in nodes if n.get("country_code") == country.upper()]
        if not filtered:
            return False, f"没有 {country.upper()} 节点"
        nodes = filtered

    def _priority(n: dict) -> tuple:
        order = {"available": 0, "not_checked": 1, "unavailable": 2}
        return (order.get(n.get("probe_status", "not_checked"), 1), n.get("latency_ms") or 9999)

    # 优先选非 unavailable 节点，全部失败则也尝试 unavailable
    candidates = [n for n in nodes if n.get("probe_status") != "unavailable"]
    if not candidates:
        # 所有节点都被标记不可用，重置状态重新尝试
        log("[连接] 所有节点已标记不可用，重置状态重新尝试...")
        for n in nodes:
            n["probe_status"] = "not_checked"
        save_nodes(nodes)
        candidates = nodes

    candidates.sort(key=_priority)

    # 逐个尝试直到成功
    for candidate in candidates:
        ok, msg = connect_node(candidate["id"])
        if ok:
            return ok, msg
        log(f"[连接] 跳过 {candidate['id']}，尝试下一个...")

    return False, "所有节点连接失败"

def rotate_node() -> tuple[bool, str]:
    nodes = get_nodes()
    if not nodes:
        return False, "没有节点"
    available = [n for n in nodes if n.get("probe_status") != "unavailable"] or nodes
    ids = [n["id"] for n in available]
    idx = (ids.index(_active_node_id) + 1) % len(ids) if _active_node_id in ids else 0
    return connect_node(ids[idx])

def disconnect() -> None:
    global _rotate_timer, _latency_timer
    with _lock:
        for t in [_rotate_timer, _latency_timer]:
            if t:
                t.cancel()
        _rotate_timer = None
    _stop_openvpn()
    nodes = get_nodes()
    for n in nodes:
        n["active"] = False
    save_nodes(nodes)
    _update_state(message="已断开连接", is_connecting=False, connected_node="", active_node_id="")
    log("[断开] VPN 已断开")

# ── 定时轮换 ──────────────────────────────────────────────────────────────────
def _schedule_rotate() -> None:
    global _rotate_timer
    with _lock:
        if _rotate_timer:
            _rotate_timer.cancel()
        hours = float(load_settings().get("rotate_hours", 0))
        if hours <= 0:
            return
        _rotate_timer = threading.Timer(hours * 3600, _do_scheduled_rotate)
        _rotate_timer.daemon = True
        _rotate_timer.start()
        log(f"[轮换] 已设置 {hours:.1f} 小时后自动轮换")

def _do_scheduled_rotate() -> None:
    log("[轮换] 自动轮换节点...")
    ok, msg = rotate_node()
    log(f"[轮换] {'成功' if ok else '失败'} — {msg}")

# ── Watchdog ──────────────────────────────────────────────────────────────────
def _watchdog() -> None:
    global _wd_fail_count
    interval = _WD_MIN_INTERVAL
    while True:
        time.sleep(15)
        if _is_connecting:
            continue
        if not get_nodes():
            continue
        if _openvpn_alive():
            if _wd_fail_count > 0:
                _wd_fail_count = 0
                interval = _WD_MIN_INTERVAL
            continue
        _wd_fail_count += 1
        wait = min(interval, _WD_MAX_INTERVAL)
        log(f"[监控] VPN 未连接（第 {_wd_fail_count} 次），{wait}s 后重连...")
        time.sleep(wait)
        interval = min(interval * _WD_BACKOFF_MULT, _WD_MAX_INTERVAL)
        if not _is_connecting:
            ok, msg = auto_connect()
            log(f"[监控] 重连{'成功' if ok else '失败'}: {msg}")
            if ok:
                _wd_fail_count = 0
                interval = _WD_MIN_INTERVAL

# ── 出口连通性检测 ───────────────────────────────────────────────────────────────
def _check_outlet(port: int, timeout: int = 8) -> bool:
    """通过代理访问外网，返回是否连通"""
    try:
        cmd = ["curl", "-4", "-s", "--proxy", f"socks5h://127.0.0.1:{port}",
               "https://api.ipify.org", "--max-time", str(timeout)]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        return r.returncode == 0 and r.stdout.strip() != ""
    except Exception:
        return False

def _outlet_watchdog() -> None:
    """持续检测出口连通性，失败超过阈值则标记节点不可用并轮换"""
    global _outlet_fail_count
    while True:
        s = load_settings()
        interval = int(s.get("outlet_check_interval", 60))
        if interval <= 0:
            time.sleep(30)
            continue
        time.sleep(interval)

        # 没有连接时不检测
        if not _active_node_id or _is_connecting or not _openvpn_alive():
            _outlet_fail_count = 0
            continue

        port = s.get("proxy_port", PROXY_PORT)
        reachable = _check_outlet(port)

        if reachable:
            if _outlet_fail_count > 0:
                log(f"[出口检测] 连通性恢复正常")
            _outlet_fail_count = 0
            continue

        _outlet_fail_count += 1
        max_fails = int(s.get("outlet_max_fails", 3))
        log(f"[出口检测] 连通性失败（{_outlet_fail_count}/{max_fails}）")

        if _outlet_fail_count >= max_fails:
            log(f"[出口检测] 连续失败 {_outlet_fail_count} 次，标记节点不可用并轮换...")
            _outlet_fail_count = 0

            # 标记当前节点为不可用
            nodes = get_nodes()
            for n in nodes:
                if n["id"] == _active_node_id:
                    n["probe_status"] = "unavailable"
                    n["probe_message"] = "出口连通性检测失败"
                    break
            save_nodes(nodes)

            # 轮换到下一个节点
            if not _is_connecting:
                ok, msg = rotate_node()
                log(f"[出口检测] 轮换结果: {'成功' if ok else '失败'} — {msg}")

# ── 命令总线 ──────────────────────────────────────────────────────────────────
def _cmd_bus() -> None:
    last_ts = 0.0
    while True:
        time.sleep(0.5)
        try:
            if not CMD_FILE.exists():
                continue
            cmd = _read_json(CMD_FILE)
            ts  = cmd.get("ts", 0.0)
            if ts <= last_ts:
                continue
            last_ts = ts

            action = cmd.get("cmd", "")
            args   = cmd.get("args", [])
            ok, msg = False, "未知命令"

            try:
                if action == "fetch":
                    s = load_settings()
                    nodes = fetch_and_test(
                        country_filter=args[0].split(",") if args else s.get("country_filter") or None,
                        top=int(args[1]) if len(args) > 1 else s.get("top_nodes", 20),
                        probe_count=s.get("probe_count", 10),
                        auto_connect_after=True,
                    )
                    ok, msg = True, f"抓取完成，共 {len(nodes)} 个节点"
                elif action == "check_latency":
                    remaining, removed = check_latency()
                    ok, msg = True, f"检测完成，剩余 {remaining} 个节点，删除 {removed} 个"
                elif action == "auto_connect":
                    ok, msg = auto_connect(args[0] if args else None)
                elif action == "connect" and args:
                    ok, msg = connect_node(args[0])
                elif action == "rotate":
                    ok, msg = rotate_node()
                elif action == "disconnect":
                    disconnect()
                    ok, msg = True, "已断开"
                elif action == "status":
                    ok, msg = True, json.dumps(get_state(), ensure_ascii=False)
            except Exception as e:
                msg = str(e)

            _write_json(CMD_RESULT, {"cmd": action, "ok": ok, "msg": msg, "ts": time.time()})
        except Exception:
            pass

# ── 初始化 ────────────────────────────────────────────────────────────────────
def init() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    AUTH_FILE.write_text("vpn\nvpn\n", encoding="utf-8")
    AUTH_FILE.chmod(0o600)

    s = load_settings()
    port = s.get("proxy_port", PROXY_PORT)

    threading.Thread(target=proxy_server.start_proxy_server,
                     args=(PROXY_HOST, port), daemon=True, name="proxy-server").start()
    log(f"[启动] 代理服务启动 {PROXY_HOST}:{port}")

    threading.Thread(target=_watchdog, daemon=True, name="watchdog").start()
    log("[启动] Watchdog 已启动")

    threading.Thread(target=_cmd_bus, daemon=True, name="cmd-bus").start()
    log("[启动] 命令总线已启动")

    threading.Thread(target=_outlet_watchdog, daemon=True, name="outlet-watchdog").start()
    log("[启动] 出口检测已启动")

# ── 主程序 ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log("=" * 60)
    log("[启动] VPNGate Gateway v2 启动中...")
    log("=" * 60)
    init()

    s = load_settings()
    if s.get("auto_fetch_on_start", True):
        try:
            fetch_and_test(
                country_filter=s.get("country_filter") or None,
                top=s.get("top_nodes", 20),
                probe_count=s.get("probe_count", 10),
                auto_connect_after=True,
            )
        except Exception as e:
            log(f"[启动] 初始化失败: {e}")
    else:
        log("[启动] 跳过自动抓取")

    # 启动定时延迟检测
    _schedule_latency_check()

    while True:
        time.sleep(60)
