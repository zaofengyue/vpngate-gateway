#!/usr/bin/env python3
"""
VPNGate Gateway 核心管理器
"""
from __future__ import annotations
import concurrent.futures
import ctypes
import json
import os
import platform
import pwd
import queue
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import vpn_utils
import proxy_server

# ── 配置 ──────────────────────────────────────────────────────────────────────
INSTALL_DIR  = Path(os.environ.get("VPNGATE_HOME", "/opt/vpngate-gateway"))
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
# 锁顺序（必须按此顺序获取，禁止反向）：_op_lock → _lock → _nodes_lock / _state_file_lock
_op_lock                      = threading.RLock()   # 串行化 连接/断开/轮换（持有期间可能长达数十秒）
_lock                         = threading.RLock()   # 保护下面这些全局变量
_nodes_lock                   = threading.RLock()   # 保护 nodes.json 的读-改-写
_state_file_lock              = threading.Lock()    # 保护 state.json 的读-改-写
_manual_stop: bool            = False               # 用户执行了 vg stop：自动重连/轮换/检测都不得把 VPN 拉起来
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
        "dns_servers":          "1.1.1.1,8.8.8.8",  # 经隧道解析域名所用的 DNS（逗号分隔 IPv4）
        "proxy_user":           "",    # 代理认证用户名；与 proxy_pass 同时设置才启用认证
        "proxy_pass":           "",
        "run_as_user":          "vpngate",  # 降权运行的系统用户；留空或 root = 不降权
    }
    saved = _read_json(SETTINGS_FILE, {})
    defaults.update(saved)
    return defaults

def save_settings(s: dict) -> None:
    _write_json(SETTINGS_FILE, s)

# ── 节点 & 状态 ───────────────────────────────────────────────────────────────
def get_nodes() -> list[dict]:
    with _nodes_lock:
        return _read_json(NODES_FILE, [])

def save_nodes(nodes: list[dict]) -> None:
    with _nodes_lock:
        _write_json(NODES_FILE, nodes)

def _mutate_nodes(fn) -> Any:
    """在锁内完成 读取→修改→写回，避免多个线程同时改节点列表导致丢更新"""
    with _nodes_lock:
        nodes = _read_json(NODES_FILE, [])
        result = fn(nodes)
        _write_json(NODES_FILE, nodes)
        return result

def get_state() -> dict:
    s = _read_json(STATE_FILE, {})
    s["active_node_id"] = _active_node_id
    s["is_connecting"]  = _is_connecting
    s["pid"]            = os.getpid()
    return s

def _update_state(**kw: Any) -> None:
    with _state_file_lock:
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
    while _run("ip", "rule", "del", "table", str(ROUTE_TABLE)) == 0:
        pass
    _run("ip", "route", "flush", "table", str(ROUTE_TABLE))

# ── OpenVPN ───────────────────────────────────────────────────────────────────
def _openvpn_alive() -> bool:
    proc = _active_process          # 取快照：别的线程可能同时把它置为 None
    return proc is not None and proc.poll() is None

def _stop_openvpn() -> None:
    global _active_process, _active_node_id
    _cleanup_routing()
    with _lock:
        proc, _active_process = _active_process, None
        _active_node_id = ""
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=2)
            except Exception:
                pass
    _run("pkill", "-f", rf"openvpn.*{re.escape(str(CONFIG_DIR))}")

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
        "--pull-filter", "ignore", "redirect-gateway",
        # 兜底：即使配置清洗漏网，也只允许内置 ifconfig/route，禁止外部脚本。
        # 注意不能设为 0，那样 openvpn 连 tun 地址都无法配置。
        "--script-security", "1",
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
        with _lock:
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
    user_initiated: bool = True,
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

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        nodes = list(ex.map(vpn_utils.measure_node, nodes))

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
        ok, msg = auto_connect(user_initiated=user_initiated)
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
            auto_connect_after=not _manual_stop,
            user_initiated=False,
        )
        return len(get_nodes()), 0

    log(f"[延迟检测] 开始测试 {len(nodes)} 个节点...")
    _update_state(message=f"正在检测 {len(nodes)} 个节点延迟...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        nodes = list(ex.map(vpn_utils.measure_node, nodes))

    # 不可达的删除；UDP 无应答的节点只有估算延迟，若已被连接失败/握手验证判为不可用也一并清理
    reachable = sorted(
        [n for n in nodes
         if n["latency_ms"] > 0
         and not (n.get("latency_est") and n.get("probe_status") == "unavailable")],
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
            auto_connect_after=not _manual_stop,
            user_initiated=False,
        )
        return len(get_nodes()), removed

    save_nodes(reachable)
    _update_state(message=f"延迟检测完成，剩余 {len(reachable)} 个节点")

    # 未连接、连接已断、或当前节点被删除 → 自动连接最快节点（用户手动断开后不得自动拉起）
    if _manual_stop:
        return len(reachable), removed
    active_ids = {n["id"] for n in reachable}
    if not _openvpn_alive():
        log(f"[延迟检测] 当前未连接，自动连接最快节点...")
        auto_connect(user_initiated=False)
    elif _active_node_id not in active_ids:
        log(f"[延迟检测] 当前节点已失效，自动切换...")
        auto_connect(user_initiated=False)

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
    try:
        log("[延迟检测] 开始定时检测...")
        remaining, removed = check_latency()
        log(f"[延迟检测] 完成，剩余 {remaining} 个节点，删除 {removed} 个")
    except Exception as e:
        # 抓取 API 失败等异常不能让定时链断掉，否则之后再也不会检测
        log(f"[延迟检测] 异常: {e}")
    finally:
        _schedule_latency_check()  # 无论成败都重新设置下次

# ── 连接管理 ──────────────────────────────────────────────────────────────────
def connect_node(node_id: str, user_initiated: bool = True) -> tuple[bool, str]:
    """
    连接指定节点。user_initiated=False 表示由 watchdog/定时器等自动触发：
    若用户已手动断开（vg stop）则直接放弃，不会把 VPN 拉起来。
    """
    global _is_connecting, _wd_fail_count, _manual_stop
    if not _op_lock.acquire(blocking=False):
        return False, "正在连接中，请稍候"
    try:
        with _lock:
            if _manual_stop and not user_initiated:
                return False, "已手动断开，跳过自动连接"
            _manual_stop = False
            _is_connecting = True

        node = next((n for n in get_nodes() if n["id"] == node_id), None)
        if not node:
            return False, f"节点不存在: {node_id}"

        log(f"[连接] 开始连接: {node_id} ({node.get('country','')} {node.get('ip','')})")
        _update_state(message=f"正在连接 {node_id}...", is_connecting=True)
        _stop_openvpn()
        ok, msg = _launch_openvpn(node)

        if ok:
            def _mark_active(all_nodes: list[dict]) -> None:
                for n in all_nodes:
                    n["active"] = (n["id"] == node_id)
            _mutate_nodes(_mark_active)
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
            def _mark_bad(all_nodes: list[dict]) -> None:
                for n in all_nodes:
                    if n["id"] == node_id:
                        n["probe_status"]  = "unavailable"
                        n["probe_message"] = msg
                        break
            _mutate_nodes(_mark_bad)

        return ok, msg
    finally:
        with _lock:
            _is_connecting = False
        _op_lock.release()

def auto_connect(country: str | None = None, user_initiated: bool = True) -> tuple[bool, str]:
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
        # 所有（符合条件的）节点都被标记不可用，重置状态重新尝试
        log("[连接] 所有节点已标记不可用，重置状态重新尝试...")
        ids = {n["id"] for n in nodes}

        def _reset(all_nodes: list[dict]) -> None:
            for n in all_nodes:
                if n["id"] in ids:
                    n["probe_status"] = "not_checked"
        _mutate_nodes(_reset)
        candidates = [n for n in get_nodes() if n["id"] in ids]

    candidates.sort(key=_priority)

    # 逐个尝试直到成功
    for candidate in candidates:
        ok, msg = connect_node(candidate["id"], user_initiated=user_initiated)
        if ok:
            return ok, msg
        if not user_initiated and _manual_stop:
            return False, msg
        log(f"[连接] 跳过 {candidate['id']}，尝试下一个...")

    return False, "所有节点连接失败"

def rotate_node(user_initiated: bool = True) -> tuple[bool, str]:
    nodes = get_nodes()
    if not nodes:
        return False, "没有节点"
    available = [n for n in nodes if n.get("probe_status") != "unavailable"] or nodes
    ids = [n["id"] for n in available]
    with _lock:
        current = _active_node_id
    idx = (ids.index(current) + 1) % len(ids) if current in ids else 0
    return connect_node(ids[idx], user_initiated=user_initiated)

def disconnect() -> None:
    """用户主动断开：之后 watchdog/定时器/延迟检测都不会再自动把 VPN 拉起来，直到用户再次连接"""
    global _rotate_timer, _manual_stop
    with _lock:
        _manual_stop = True
        if _rotate_timer:
            _rotate_timer.cancel()
            _rotate_timer = None
    with _op_lock:                  # 若有连接正在进行，等它结束后再断开
        _stop_openvpn()

        def _clear(all_nodes: list[dict]) -> None:
            for n in all_nodes:
                n["active"] = False
        _mutate_nodes(_clear)
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
    try:
        if _manual_stop:
            log("[轮换] 已手动断开，跳过本次轮换")
            return
        log("[轮换] 自动轮换节点...")
        ok, msg = rotate_node(user_initiated=False)
        log(f"[轮换] {'成功' if ok else '失败'} — {msg}")
    except Exception as e:
        log(f"[轮换] 异常: {e}")
    finally:
        # 无论成败都重新排期（成功时 connect_node 已排过一次，这里只是刷新），
        # 否则一次轮换失败后定时轮换就再也不会触发
        if not _manual_stop:
            _schedule_rotate()

# ── Watchdog ──────────────────────────────────────────────────────────────────
def _watchdog() -> None:
    global _wd_fail_count
    interval = _WD_MIN_INTERVAL
    while True:
        try:
            time.sleep(15)
            if _is_connecting or _manual_stop:
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
            if not _is_connecting and not _manual_stop:
                ok, msg = auto_connect(user_initiated=False)
                log(f"[监控] 重连{'成功' if ok else '失败'}: {msg}")
                if ok:
                    _wd_fail_count = 0
                    interval = _WD_MIN_INTERVAL
        except Exception as e:      # 线程不能因为一次异常就永久退出
            log(f"[监控] 异常: {e}")
            time.sleep(5)

# ── 出口连通性检测 ───────────────────────────────────────────────────────────────
def _check_outlet(s: dict, timeout: int = 8) -> bool:
    """通过代理（带认证）访问外网，返回是否连通。凭据只在进程内传递，不出现在命令行"""
    port = s.get("proxy_port", PROXY_PORT)
    return vpn_utils.check_proxy(port, str(s.get("proxy_user", "")), str(s.get("proxy_pass", "")),
                                 timeout)["ok"]

def _outlet_watchdog() -> None:
    """持续检测出口连通性，失败超过阈值则标记节点不可用并轮换"""
    global _outlet_fail_count
    while True:
        try:
            s = load_settings()
            interval = int(s.get("outlet_check_interval", 60))
            if interval <= 0:
                time.sleep(30)
                continue
            time.sleep(interval)

            # 没有连接（或用户手动断开）时不检测
            if not _active_node_id or _is_connecting or _manual_stop or not _openvpn_alive():
                _outlet_fail_count = 0
                continue

            if _check_outlet(s):
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
                with _lock:
                    bad_id = _active_node_id

                def _mark_bad(all_nodes: list[dict]) -> None:
                    for n in all_nodes:
                        if n["id"] == bad_id:
                            n["probe_status"] = "unavailable"
                            n["probe_message"] = "出口连通性检测失败"
                            break
                _mutate_nodes(_mark_bad)

                if not _is_connecting and not _manual_stop:
                    ok, msg = rotate_node(user_initiated=False)
                    log(f"[出口检测] 轮换结果: {'成功' if ok else '失败'} — {msg}")
        except Exception as e:
            log(f"[出口检测] 异常: {e}")
            time.sleep(5)

# ── 命令总线 ──────────────────────────────────────────────────────────────────
def _cmd_bus() -> None:
    last_ts = time.time()      # 忽略服务启动前遗留在 cmd.json 里的旧命令
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
            def _dispatch(act=action, a=args, req_ts=ts):
                ok, msg = False, "未知命令"
                try:
                    if act == "fetch":
                        s = load_settings()
                        nodes = fetch_and_test(
                            country_filter=a[0].split(",") if a else s.get("country_filter") or None,
                            top=int(a[1]) if len(a) > 1 else s.get("top_nodes", 20),
                            probe_count=s.get("probe_count", 10),
                            auto_connect_after=True,
                        )
                        ok, msg = True, f"抓取完成，共 {len(nodes)} 个节点"
                    elif act == "check_latency":
                        remaining, removed = check_latency()
                        ok, msg = True, f"检测完成，剩余 {remaining} 个节点，删除 {removed} 个"
                    elif act == "auto_connect":
                        ok, msg = auto_connect(a[0] if a else None)
                    elif act == "connect" and a:
                        ok, msg = connect_node(a[0])
                    elif act == "rotate":
                        ok, msg = rotate_node()
                    elif act == "disconnect":
                        disconnect()
                        ok, msg = True, "已断开"
                    elif act == "status":
                        ok, msg = True, json.dumps(get_state(), ensure_ascii=False)
                except Exception as e:
                    msg = str(e)
                _write_json(CMD_RESULT, {"cmd": act, "ok": ok, "msg": msg, "ts": time.time()})

            threading.Thread(target=_dispatch, daemon=True, name=f"cmd-{action}").start()
        except Exception:
            pass

# ── 降权 ──────────────────────────────────────────────────────────────────────
# 服务以 root 启动（要创建目录/改属主），随后自己切换到专用低权限用户，只保留
# CAP_NET_ADMIN（建 tun、配策略路由）和 CAP_NET_RAW（SO_BINDTODEVICE）。
# openvpn 作为子进程继承这两项 ambient 能力：它是直接解析陌生服务器数据的进程，
# 一旦被攻破，拿到的是 vpngate 用户而不是 root。
_CAP_NET_ADMIN, _CAP_NET_RAW = 12, 13
_KEEP_CAPS = (1 << _CAP_NET_ADMIN) | (1 << _CAP_NET_RAW)
_CAPSET_NR = {"x86_64": 126, "aarch64": 91, "arm64": 91, "riscv64": 91,
              "i686": 185, "i386": 185, "armv7l": 185, "armv6l": 185}
_TUN_PATH = "/dev/net/tun"


class _CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                ("inheritable", ctypes.c_uint32)]


def _libc() -> ctypes.CDLL:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    libc.prctl.restype = ctypes.c_int
    return libc


def _prctl(libc: ctypes.CDLL, option: int, a2: int = 0, a3: int = 0, a4: int = 0, a5: int = 0) -> int:
    r = libc.prctl(ctypes.c_int(option), ctypes.c_ulong(a2), ctypes.c_ulong(a3),
                   ctypes.c_ulong(a4), ctypes.c_ulong(a5))
    if r < 0:
        err = ctypes.get_errno()
        raise OSError(err, f"prctl({option}) 失败: {os.strerror(err)}")
    return r


def _capset(libc: ctypes.CDLL, nr: int, caps: int) -> None:
    hdr = _CapHeader(0x20080522, 0)               # _LINUX_CAPABILITY_VERSION_3
    data = (_CapData * 2)()
    data[0] = _CapData(caps & 0xFFFFFFFF, caps & 0xFFFFFFFF, caps & 0xFFFFFFFF)
    data[1] = _CapData(caps >> 32, caps >> 32, caps >> 32)
    if libc.syscall(ctypes.c_long(nr), ctypes.byref(hdr), data) != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"capset 失败: {os.strerror(err)}")


def _apply_drop(pw: "pwd.struct_passwd", nr: int) -> None:
    """真正执行降权（不可逆）。顺序：保留能力位 → 收紧 bounding set → 换身份 → 恢复所需能力 → no_new_privs"""
    libc = _libc()
    _prctl(libc, 8, 1)                                        # PR_SET_KEEPCAPS：setuid 后保留 permitted
    with open("/proc/sys/kernel/cap_last_cap") as f:
        last_cap = int(f.read())
    for cap in range(last_cap + 1):                           # bounding set 只留两项，之后任何 exec 都拿不回别的能力
        if not (_KEEP_CAPS >> cap) & 1:
            _prctl(libc, 24, cap)                             # PR_CAPBSET_DROP
    os.setgroups([])
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)
    _capset(libc, nr, _KEEP_CAPS)                             # setuid 清空了 effective，重新设为两项
    for cap in (_CAP_NET_ADMIN, _CAP_NET_RAW):
        _prctl(libc, 47, 2, cap)                              # PR_CAP_AMBIENT_RAISE：让 ip/openvpn 子进程继承
    _prctl(libc, 38, 1)                                       # PR_SET_NO_NEW_PRIVS
    os.umask(0o077)


def _status_field(name: str) -> int:
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith(name + ":"):
                return int(line.split()[1], 16)
    return -1


def _verify_dropped(pw: "pwd.struct_passwd") -> None:
    """降权后的自检（只在预检子进程里跑）：身份、能力、绑网卡、打开 tun 设备"""
    import socket as _s
    if os.geteuid() != pw.pw_uid or os.getuid() != pw.pw_uid:
        raise RuntimeError("uid 不符")
    if _status_field("CapEff") != _KEEP_CAPS or _status_field("CapAmb") != _KEEP_CAPS:
        raise RuntimeError("能力位不符")
    if _status_field("CapBnd") != _KEEP_CAPS:
        raise RuntimeError("bounding set 未收紧")
    sk = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
    try:
        sk.setsockopt(_s.SOL_SOCKET, _s.SO_BINDTODEVICE, b"lo")
    finally:
        sk.close()
    os.close(os.open(_TUN_PATH, os.O_RDWR))


def _chown_tree(path: Path, uid: int, gid: int) -> None:
    os.lchown(path, uid, gid)
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            try:
                os.lchown(os.path.join(root, name), uid, gid)
            except OSError:
                pass


def _drop_privileges(user: str) -> tuple[bool, str]:
    """
    root → 低权限用户。返回 (是否已降权, 说明)。
    任何一步在预检中失败都保持 root 运行并返回 False（宁可功能可用，也不要把服务搞坏）；
    预检在 fork 出的子进程里完整演练一遍，通过后父进程才真正降权。
    """
    if os.geteuid() != 0:
        return True, "已是非 root 用户"
    if not user or user == "root":
        return False, "run_as_user 为空/root，按配置不降权"
    if sys.platform != "linux":
        return False, "仅支持 Linux 降权"
    nr = _CAPSET_NR.get(platform.machine())
    if nr is None:
        return False, f"不支持的 CPU 架构 {platform.machine()}"
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        return False, f"系统用户 {user} 不存在（请重新运行安装脚本）"
    try:
        st = os.stat(_TUN_PATH)
        if (st.st_mode & 0o006) != 0o006:                     # openvpn 需要读写 /dev/net/tun
            os.chmod(_TUN_PATH, 0o666)
    except OSError as e:
        return False, f"{_TUN_PATH} 不可用: {e}"

    try:
        _chown_tree(DATA_DIR, pw.pw_uid, pw.pw_gid)
    except OSError as e:
        return False, f"无法修改数据目录属主: {e}"

    pid = os.fork()                                            # 预检：在子进程里完整演练
    if pid == 0:
        code = 1
        try:
            _apply_drop(pw, nr)
            _verify_dropped(pw)
            code = 0
        except BaseException:
            code = 1
        finally:
            os._exit(code)
    _, status = os.waitpid(pid, 0)
    if not (os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0):
        return False, "降权预检失败（内核/容器不支持所需能力操作），继续以 root 运行"

    _apply_drop(pw, nr)
    return True, f"已降权为 {user}（仅保留 CAP_NET_ADMIN/CAP_NET_RAW）"


def _prepare_runtime() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    user = str(load_settings().get("run_as_user", "vpngate")).strip()
    ok, msg = _drop_privileges(user)
    log(f"[启动] {'降权: ' if ok else '警告: 未降权，仍以 root 运行 — '}{msg}")


# ── 初始化 ────────────────────────────────────────────────────────────────────
def init() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    AUTH_FILE.write_text("vpn\nvpn\n", encoding="utf-8")
    AUTH_FILE.chmod(0o600)

    s = load_settings()
    port = s.get("proxy_port", PROXY_PORT)
    proxy_server.configure_dns(str(s.get("dns_servers", "")).split(","))
    try:
        authed = proxy_server.configure_auth(str(s.get("proxy_user", "")), str(s.get("proxy_pass", "")))
    except ValueError as e:                      # 配置了一半的认证 → 拒绝启动，绝不退化成无认证
        log(f"[启动] 错误: 代理认证配置无效 — {e}")
        raise SystemExit(78)
    log(f"[启动] 代理认证: {'已启用' if authed else '未启用（仅 127.0.0.1 可访问；同机用户均可使用）'}")

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
    _prepare_runtime()
    init()

    def _on_term(signum, _frame) -> None:
        log(f"[退出] 收到信号 {signum}，关闭 openvpn 并清理路由...")
        try:
            _stop_openvpn()
        finally:
            os._exit(0)
    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGINT, _on_term)

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
