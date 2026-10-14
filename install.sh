#!/bin/bash
# VPNGate Gateway v2 安装脚本
# 支持: Debian/Ubuntu (apt + systemd)、Alpine (apk + OpenRC)
#
# Debian/Ubuntu:
#   bash <(curl -Ls https://raw.githubusercontent.com/zaofengyue/vpngate-gateway/main/install.sh)
# Alpine（默认没有 bash/curl，需先安装）:
#   apk add bash curl && bash <(curl -Ls https://raw.githubusercontent.com/zaofengyue/vpngate-gateway/main/install.sh)
#
# 固定版本（推荐）：把 main 换成某个 tag 或 commit，并设置同名环境变量，
# 安装器会按本脚本内置的 SHA256 清单校验其余文件，被篡改/不一致则拒绝安装：
#   VPNGATE_REF=<tag或commit> bash <(curl -Ls https://raw.githubusercontent.com/zaofengyue/vpngate-gateway/<tag或commit>/install.sh)
#
# 本地安装（已 git clone / 解压源码）：在源码目录里执行 bash install.sh，直接使用本地文件。
# 仅更新程序文件、不动依赖/向导：bash install.sh --files-only

# 必须放在 set -o pipefail 之前：Alpine 默认 sh(ash) 不认识 bash 语法
if [ -z "${BASH_VERSION:-}" ]; then
    echo "请使用 bash 运行本脚本。Alpine 请先执行: apk add bash curl"
    exit 1
fi

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# ── 颜色 ─────────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
C='\033[0;36m'; B='\033[0;34m'; NC='\033[0m'; BOLD='\033[1m'

# ── 权限检查 ──────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && echo -e "${R}请用 root 权限运行（sudo bash install.sh）${NC}" && exit 1

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${B}"
cat << 'EOF'
 __   ____  _  _  ___    ___   __  ____  ____  _      __  _  _
 \ \ / /  \| \| |/ __| _ / __| / _||_  _|| ___|| | /\ \ \/ \/ /
  \ V /| () | .` | (_ |(_| (_ || |_  | |  | _|  | |/ /\ \\ ' ' /
   \_/  \__/|_|\_|\___| _\___/ \__| |_|  |___| |__/ /_/\_\\_/\_/
EOF
echo -e "${NC}"

INSTALL_DIR="/opt/vpngate-gateway"
GITHUB_REPO="zaofengyue/vpngate-gateway"
REF="${VPNGATE_REF:-main}"
# 镜像/自建源：VPNGATE_RAW_BASE=https://你的镜像/路径（下载走镜像，完整性仍按下面的 SHA256 清单校验，镜像无法夹带改动）
RAW_BASE="${VPNGATE_RAW_BASE:-https://raw.githubusercontent.com/${GITHUB_REPO}/${REF}}"
CURL_PROTO='=https'
[ -n "${VPNGATE_RAW_BASE:-}" ] && CURL_PROTO='=http,https'
SERVICE="vpngate-gateway"
SVC_USER="vpngate"
FILES=(vpn_utils.py proxy_server.py vpngate_manager.py vpngw)

# ── 源码完整性清单（由 tools/update_hashes.sh 生成，请勿手改）─────────────────
# >>> SHA256SUMS >>>
declare -A EXPECTED_SHA256=(
    [vpn_utils.py]="05defaa2f28e52a41cdd7089f3e5c65faefbf0712e66c7e5b1f4b02f1bf6e442"
    [proxy_server.py]="afd66c295d34a7e76ce11d3c29a879e7f8226d5f0dbee83306e4eeea2ca9c9bd"
    [vpngate_manager.py]="4af977189d288917328401e30c8992ab8dc85600ea7cb7346995732cb6a8ae91"
    [vpngw]="ac39ac41589e583f7f3cb5e191e8d6318678d2133956568d9854c43991770162"
)
# <<< SHA256SUMS <<<

FILES_ONLY=0
for _arg in "$@"; do
    case "$_arg" in
        --files-only) FILES_ONLY=1 ;;
        *) echo -e "${R}未知参数: ${_arg}${NC}"; exit 1 ;;
    esac
done

fail() { echo -e "${R}$*${NC}"; exit 1; }
sha256_of() { sha256sum "$1" | awk '{print $1}'; }

# 本地源码模式：脚本本身是磁盘上的真实文件，且旁边有源码文件（bash <(curl ...) 时脚本是管道，不会命中）
SRC_DIR=""
_self="${BASH_SOURCE[0]:-}"
if [ -n "$_self" ] && [ -f "$_self" ]; then
    _dir="$(cd "$(dirname "$_self")" && pwd)"
    if [ -f "$_dir/vpngate_manager.py" ] && [ -f "$_dir/vpn_utils.py" ] && [ -f "$_dir/proxy_server.py" ] && [ -f "$_dir/vpngw" ]; then
        SRC_DIR="$_dir"
    fi
fi

# ── 系统检测：包管理器 + 服务管理器 ───────────────────────────────────────────
if command -v apt-get >/dev/null 2>&1; then
    PKG_MGR="apt"
elif command -v apk >/dev/null 2>&1; then
    PKG_MGR="apk"
else
    echo -e "${R}不支持的系统：未找到 apt-get 或 apk（目前支持 Debian/Ubuntu 和 Alpine）${NC}"
    exit 1
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    INIT_SYS="systemd"
elif command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
    INIT_SYS="openrc"
else
    INIT_SYS="none"
fi
echo -e "    包管理器: ${C}${PKG_MGR}${NC}  服务管理: ${C}${INIT_SYS}${NC}"

svc() {   # svc <start|stop|restart>
    case "$INIT_SYS" in
        systemd) systemctl "$1" "$SERVICE" ;;
        openrc)  rc-service "$SERVICE" "$1" ;;
        *)       return 1 ;;
    esac
}
svc_active() {
    case "$INIT_SYS" in
        systemd) systemctl is-active -q "$SERVICE" ;;
        openrc)  rc-service "$SERVICE" status >/dev/null 2>&1 ;;
        *)       return 1 ;;
    esac
}

# ── 步骤 1：依赖 ──────────────────────────────────────────────────────────────
echo -e "${Y}[1/6] 安装系统依赖...${NC}"
if [ "$FILES_ONLY" = 1 ]; then
    echo "    --files-only：跳过"
elif [ "$PKG_MGR" = "apt" ]; then
    apt-get update -qq
    apt-get install -y -qq \
        openvpn curl python3 \
        iproute2 iptables net-tools ca-certificates
else
    # Alpine 的 busybox 自带的 ip 不支持策略路由，必须装 iproute2
    apk add --no-cache openvpn curl python3 iproute2 ca-certificates bash
    update-ca-certificates >/dev/null 2>&1 || true
fi

# 检查 openvpn 版本（openvpn --version 退出码可能非 0，加 || true 防止 set -e 误杀）
OVPN_VER=$(openvpn --version 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || true)
echo -e "    OpenVPN 版本: ${C}${OVPN_VER:-未知}${NC}"

# ── 步骤 2：获取并校验源码 ────────────────────────────────────────────────────
echo -e "${Y}[2/6] 获取源码...${NC}"
WAS_ACTIVE=0
if svc_active; then WAS_ACTIVE=1; fi
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

if [ -n "$SRC_DIR" ]; then
    echo -e "    本地源码模式: ${C}${SRC_DIR}${NC}（跳过哈希校验）"
    for f in "${FILES[@]}"; do cp "$SRC_DIR/$f" "$STAGE/$f"; done
else
    echo -e "    版本: ${C}${REF}${NC}"
    for f in "${FILES[@]}"; do
        echo -n "    下载 $f ... "
        if curl -fsSL --proto "$CURL_PROTO" --max-time 60 "${RAW_BASE}/${f}" -o "${STAGE}/${f}"; then
            echo -e "${G}✔${NC}"
        else
            echo -e "${R}✘ 失败${NC}"
            fail "请检查网络或仓库地址: ${RAW_BASE}/${f}"
        fi
    done
    if [ "${VPNGATE_SKIP_VERIFY:-0}" = 1 ]; then
        echo -e "    ${Y}警告：已通过 VPNGATE_SKIP_VERIFY=1 跳过完整性校验${NC}"
    else
        for f in "${FILES[@]}"; do
            want="${EXPECTED_SHA256[$f]:-}"
            [ -n "$want" ] || fail "本安装脚本没有 $f 的哈希清单，无法校验（开发分支？可设 VPNGATE_SKIP_VERIFY=1 自担风险）"
            got="$(sha256_of "${STAGE}/${f}")"
            if [ "$got" != "$want" ]; then
                fail "✘ 完整性校验失败: $f
    期望 $want
    实际 $got
    文件与安装脚本不是同一版本，或在传输/仓库中被篡改。已中止，未修改任何已安装文件。"
            fi
        done
        echo -e "    ${G}✔ SHA256 校验通过${NC}"
    fi
fi

# 校验通过后才替换：先停服务
if [ "$WAS_ACTIVE" = 1 ]; then svc stop >/dev/null 2>&1 || true; sleep 1; fi
mkdir -p "$INSTALL_DIR"
for f in "${FILES[@]}"; do
    cp "${STAGE}/${f}" "${INSTALL_DIR}/${f}"
done
rm -rf "${INSTALL_DIR}/__pycache__" 2>/dev/null || true

# ── 步骤 3：用户、目录、权限、命令、TUN 设备 ──────────────────────────────────
echo -e "${Y}[3/6] 配置用户、目录与权限...${NC}"

# 专用低权限用户：服务启动后自行降权为它（仅保留 CAP_NET_ADMIN/CAP_NET_RAW）
if ! id "$SVC_USER" >/dev/null 2>&1; then
    if [ "$PKG_MGR" = "apk" ]; then
        addgroup -S "$SVC_USER" >/dev/null 2>&1 || true
        adduser -S -D -H -s /sbin/nologin -G "$SVC_USER" "$SVC_USER" >/dev/null 2>&1 || true
    else
        useradd --system --no-create-home --home-dir /nonexistent \
            --shell /usr/sbin/nologin --user-group "$SVC_USER" >/dev/null 2>&1 || true
    fi
fi
if id "$SVC_USER" >/dev/null 2>&1; then
    echo -e "    服务用户: ${C}${SVC_USER}${NC}"
else
    echo -e "    ${Y}警告：无法创建用户 ${SVC_USER}，服务将以 root 运行（不降权）${NC}"
fi

# 程序文件归 root、不可被服务用户改写（服务被攻破时无法篡改自身代码）
chown root:root "$INSTALL_DIR"/vpn_utils.py "$INSTALL_DIR"/proxy_server.py \
                "$INSTALL_DIR"/vpngate_manager.py "$INSTALL_DIR"/vpngw 2>/dev/null || true
chmod 644 "$INSTALL_DIR"/vpn_utils.py "$INSTALL_DIR"/proxy_server.py "$INSTALL_DIR"/vpngate_manager.py
chmod 755 "$INSTALL_DIR"/vpngw
# 数据目录归服务用户，其他用户不可进入（里面有节点配置和可能的代理口令）
mkdir -p "$INSTALL_DIR/data/configs"
if id "$SVC_USER" >/dev/null 2>&1; then
    chown -R "$SVC_USER:$SVC_USER" "$INSTALL_DIR/data"
fi
chmod 750 "$INSTALL_DIR/data"

# 命令软链接（vpngw 和 vg 都可用）
ln -sf "$INSTALL_DIR/vpngw" /usr/local/bin/vpngw
ln -sf "$INSTALL_DIR/vpngw" /usr/local/bin/vg

# TUN 设备：没有它 OpenVPN 无法创建 tun0
if [ ! -c /dev/net/tun ]; then
    modprobe tun 2>/dev/null || true
    if [ ! -c /dev/net/tun ]; then
        mkdir -p /dev/net
        mknod /dev/net/tun c 10 200 2>/dev/null || true
    fi
fi
if [ -c /dev/net/tun ]; then
    # 降权后的 openvpn 需要读写该设备（Debian 默认就是 666，这里兜底）
    chmod 666 /dev/net/tun 2>/dev/null || true
    echo "    TUN 设备: 可用"
else
    echo -e "    ${R}警告：没有 /dev/net/tun，VPN 将无法建立。LXC/OpenVZ 需在服务商面板开启 TUN/TAP${NC}"
fi
# Alpine：开机自动加载 tun 模块
if [ "$PKG_MGR" = "apk" ] && [ -f /etc/modules ] && ! grep -qx tun /etc/modules; then
    echo tun >> /etc/modules
fi

# ── 步骤 4：网络策略调整 ──────────────────────────────────────────────────────
echo -e "${Y}[4/6] 调整内核网络参数（放宽反向路径过滤）...${NC}"
if [ "$FILES_ONLY" = 0 ]; then
# 部分云平台（如 GCP）默认开启严格反向路径过滤（rp_filter=1），
# 会导致策略路由下 VPN 隧道的非对称回程流量被内核直接丢弃，
# 造成 VPN 握手成功但实际无法出网。此处放宽为 loose 模式（2）以兼容。
mkdir -p /etc/sysctl.d
cat > /etc/sysctl.d/99-vpngate-rpfilter.conf << 'RPEOF'
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
RPEOF
sysctl -p /etc/sysctl.d/99-vpngate-rpfilter.conf >/dev/null 2>&1 || true
# 兜底：直接写 /proc（busybox sysctl 不一定支持 -p）
for k in all default; do
    { echo 2 > "/proc/sys/net/ipv4/conf/$k/rp_filter"; } 2>/dev/null || true
done
# Alpine：确保 sysctl 服务开机加载 /etc/sysctl.d
if [ "$INIT_SYS" = "openrc" ]; then
    rc-update add sysctl boot >/dev/null 2>&1 || true
fi
echo "    rp_filter 已设置为宽松模式（兼容 GCP/AWS 等云平台的策略路由）"
else
    echo "    --files-only：跳过"
fi

# ── 步骤 5：系统服务 ──────────────────────────────────────────────────────────
echo -e "${Y}[5/6] 配置系统服务（${INIT_SYS}）...${NC}"
PYBIN=$(command -v python3)

case "$INIT_SYS" in
systemd)
cat > /etc/systemd/system/${SERVICE}.service << EOF
[Unit]
Description=VPNGate Gateway v2
Documentation=https://github.com/${GITHUB_REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${PYBIN} ${INSTALL_DIR}/vpngate_manager.py
Restart=always
RestartSec=15
RestartPreventExitStatus=0 78
TimeoutStopSec=30

# 安全加固：进程以 root 启动后自行降权为 ${SVC_USER}（只保留 CAP_NET_ADMIN/CAP_NET_RAW）
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes

# 环境
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=PYTHONPATH=${INSTALL_DIR}

# 日志
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE}

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$SERVICE" --quiet
    echo "    服务已注册: ${SERVICE}（systemd）"
    ;;
openrc)
# 程序自己会把日志写到 data/vpngate.log（带轮转），所以这里 stdout 丢弃，
# 只把 stderr（崩溃回溯）留在 /var/log，避免日志无限增长。
cat > /etc/init.d/${SERVICE} << EOF
#!/sbin/openrc-run
name="${SERVICE}"
description="VPNGate Gateway v2"

export PYTHONUNBUFFERED=1
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="${INSTALL_DIR}"

command="${PYBIN}"
command_args="${INSTALL_DIR}/vpngate_manager.py"
command_background="yes"
directory="${INSTALL_DIR}"
pidfile="/run/${SERVICE}.pid"
output_log="/dev/null"
error_log="/var/log/${SERVICE}.err"

depend() {
    need net
    after firewall
}
EOF
    chmod +x /etc/init.d/${SERVICE}
    rc-update add "$SERVICE" default >/dev/null 2>&1 || true
    echo "    服务已注册: ${SERVICE}（OpenRC）"
    ;;
*)
    echo -e "    ${Y}未检测到 systemd 或 OpenRC，跳过服务注册。可手动运行:${NC}"
    echo "    cd ${INSTALL_DIR} && ${PYBIN} vpngate_manager.py"
    ;;
esac

# ── 步骤 6：初始化设置 ────────────────────────────────────────────────────────
echo -e "${Y}[6/6] 初始化配置...${NC}"
PROXY_PORT=7928

if [ "$FILES_ONLY" = 1 ]; then
    echo "    --files-only：保留现有设置"
    if [ "$WAS_ACTIVE" = 1 ]; then
        svc start >/dev/null 2>&1 || true
        echo "    服务已重新启动"
    fi
    exit 0
fi

svc stop >/dev/null 2>&1 || true
sleep 1

echo ""
echo -e "${C}┌─── 初始化向导 ────────────────────────────────┐${NC}"
echo -e "${C}│ 直接回车使用括号中的默认值                    │${NC}"
echo -e "${C}└───────────────────────────────────────────────┘${NC}"
echo ""

CC_INPUT=""; ROT_INPUT=""; TOP_INPUT=""; PROBE_INPUT=""; PORT_INPUT=""; AUTH_USER=""; AUTH_PASS=""
read -r -p "  国家过滤（如 JP,US,KR，留空=不限）: " CC_INPUT || true
read -r -p "  自动轮换间隔（小时，0=关闭，默认 2）: " ROT_INPUT || true
read -r -p "  保留节点数量（默认 20）: " TOP_INPUT || true
read -r -p "  握手验证节点数（默认 10，越多越慢）: " PROBE_INPUT || true
read -r -p "  代理端口（默认 7928）: " PORT_INPUT || true
echo -e "  ${Y}代理默认只监听 127.0.0.1，但本机所有用户/进程都能用它出网。${NC}"
read -r -p "  代理认证用户名（留空=不启用）: " AUTH_USER || true
if [ -n "$AUTH_USER" ]; then
    read -r -s -p "  代理认证密码（留空=自动生成）: " AUTH_PASS || true
    echo ""
fi

PROXY_PORT=${PORT_INPUT:-7928}

# 用户输入经环境变量传给 Python，不拼进源码（避免输入里的引号/特殊字符造成注入或语法错误）
VG_DIR="$INSTALL_DIR" VG_CC="$CC_INPUT" VG_ROT="${ROT_INPUT:-2}" VG_TOP="${TOP_INPUT:-20}" \
VG_PROBE="${PROBE_INPUT:-10}" VG_PORT="$PROXY_PORT" VG_AUTH_USER="$AUTH_USER" VG_AUTH_PASS="$AUTH_PASS" \
VG_SVC_USER="$SVC_USER" python3 - << 'VGPYEOF'
import json, os, pwd, re, secrets

env = os.environ
path = os.path.join(env["VG_DIR"], "data", "settings.json")
try:
    with open(path, encoding="utf-8") as f:
        settings = json.load(f)          # 重装时保留已有设置
except Exception:
    settings = {}

def num(name, default, cast, lo, hi):
    try:
        v = cast(env.get(name) or default)
        return v if lo <= v <= hi else cast(default)
    except ValueError:
        return cast(default)

cc = [x.strip().upper() for x in env.get("VG_CC", "").split(",") if x.strip()]
settings.update({
    "country_filter":      [c for c in cc if re.fullmatch(r"[A-Z]{2}", c)],
    "rotate_hours":        num("VG_ROT", 2, float, 0, 720),
    "top_nodes":           num("VG_TOP", 20, int, 1, 200),
    "probe_count":         num("VG_PROBE", 10, int, 0, 100),
    "proxy_port":          num("VG_PORT", 7928, int, 1, 65535),
    "auto_fetch_on_start": True,
})
settings.setdefault("run_as_user", env["VG_SVC_USER"])

cred = re.compile(r"^[A-Za-z0-9._~!@#%^*+=\-]{1,128}$")
user, pw = env.get("VG_AUTH_USER", "").strip(), env.get("VG_AUTH_PASS", "")
generated = False
if user:
    if not pw:
        pw, generated = secrets.token_urlsafe(15), True
    if cred.match(user) and cred.match(pw):
        settings["proxy_user"], settings["proxy_pass"] = user, pw
        print(f"  代理认证已启用: 用户名 {user}  密码 " + (pw if generated else "（你输入的）"))
        if generated:
            print("  ↑ 密码只显示这一次，请保存；之后可用 vg set proxy_pass 更换")
    else:
        print("  ✘ 用户名/密码含非法字符（允许字母数字和 . _ ~ ! @ # % ^ * + = -），认证未启用")

tmp = path + ".tmp"
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    json.dump(settings, f, indent=2, ensure_ascii=False)
try:
    ent = pwd.getpwnam(env["VG_SVC_USER"])
    os.chown(tmp, ent.pw_uid, ent.pw_gid)
except KeyError:
    pass
os.replace(tmp, path)
shown = {k: ("******" if k == "proxy_pass" else v) for k, v in settings.items()}
print(f"  设置已保存: {shown}")
VGPYEOF

# ── 完成 ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${G}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${G}║            安装完成！                            ║${NC}"
echo -e "${G}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${G}║${NC}  ${BOLD}vg${NC}                       交互管理菜单"
echo -e "${G}║${NC}  ${C}vg status${NC}                查看状态和出口 IP"
echo -e "${G}║${NC}  ${C}vg fetch${NC}                 抓取所有节点并测速"
echo -e "${G}║${NC}  ${C}vg fetch --country JP,US${NC} 仅抓取日美节点"
echo -e "${G}║${NC}  ${C}vg auto${NC}                  自动连接最快节点"
echo -e "${G}║${NC}  ${C}vg auto JP${NC}               自动连接最快日本节点"
echo -e "${G}║${NC}  ${C}vg nodes${NC}                 查看节点列表"
echo -e "${G}║${NC}  ${C}vg rotate${NC}                切换到下一个节点"
echo -e "${G}║${NC}  ${C}vg logs${NC}                  查看日志"
echo -e "${G}║${NC}  ${C}vg set rotate_hours 1${NC}    修改轮换间隔"
echo -e "${G}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${G}║${NC}  SOCKS5/HTTP 代理: ${C}127.0.0.1:${PROXY_PORT}${NC}"
echo -e "${G}║${NC}  权限: 服务降权为 ${C}${SVC_USER}${NC}；程序文件归 root 只读"
echo -e "${G}╚══════════════════════════════════════════════════╝${NC}"
echo ""

if [ "$INIT_SYS" = "none" ]; then
    echo -e "  ${Y}请按上面提示手动启动服务${NC}"
else
    read -r -p "  是否立即启动服务？[Y/n] " START_NOW || true
    if [[ "${START_NOW:-Y}" =~ ^[Yy]$ ]]; then
        svc start || true
        echo ""
        echo "  等待服务启动..."
        sleep 3
        if svc_active; then
            echo -e "  ${G}服务已启动${NC}，输入 ${BOLD}vg${NC} 查看状态"
            echo ""
            echo -e "  ${Y}提示：首次启动需要几分钟抓取和测速节点，请稍候...${NC}"
            echo -e "  ${Y}可运行 vg logs 查看进度${NC}"
        else
            echo -e "  ${R}服务启动失败，请查看日志：${NC}"
            if [ "$INIT_SYS" = "systemd" ]; then
                echo "  journalctl -u ${SERVICE} -n 30 --no-pager"
            else
                echo "  cat /var/log/${SERVICE}.err ; vg logs -n 30"
            fi
        fi
    fi
fi
echo ""
