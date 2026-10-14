#!/bin/bash
# VPNGate Gateway v2 安装脚本
# 支持: Debian/Ubuntu (apt + systemd)、Alpine (apk + OpenRC)
#
# Debian/Ubuntu:
#   bash <(curl -Ls https://raw.githubusercontent.com/wanchangkongyi/vpngate-gateway/main/install.sh)
# Alpine（默认没有 bash/curl，需先安装）:
#   apk add bash curl && bash <(curl -Ls https://raw.githubusercontent.com/wanchangkongyi/vpngate-gateway/main/install.sh)

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
GITHUB_REPO="wanchangkongyi/vpngate-gateway"
BRANCH="main"
RAW_BASE="https://raw.githubusercontent.com/${GITHUB_REPO}/${BRANCH}"
SERVICE="vpngate-gateway"

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
if [ "$PKG_MGR" = "apt" ]; then
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

# ── 步骤 2：下载源码 ──────────────────────────────────────────────────────────
echo -e "${Y}[2/6] 下载源码...${NC}"
mkdir -p "$INSTALL_DIR"
FILES="vpn_utils.py proxy_server.py vpngate_manager.py vpngw"
for f in $FILES; do
    echo -n "    下载 $f ... "
    if curl -fsSL "${RAW_BASE}/${f}" -o "${INSTALL_DIR}/${f}"; then
        echo -e "${G}✔${NC}"
    else
        echo -e "${R}✘ 失败${NC}"
        echo -e "${R}请检查网络或仓库地址: ${RAW_BASE}/${f}${NC}"
        exit 1
    fi
done

# ── 步骤 3：目录、权限、命令、TUN 设备 ────────────────────────────────────────
echo -e "${Y}[3/6] 配置目录与权限...${NC}"
mkdir -p "$INSTALL_DIR/data/configs"
chmod 750 "$INSTALL_DIR/data"
chmod +x "$INSTALL_DIR"/*.py "$INSTALL_DIR/vpngw" 2>/dev/null || true

# 命令软链接（vpngw 和 vg 都可用）
ln -sf "$INSTALL_DIR/vpngw" /usr/local/bin/vpngw
ln -sf "$INSTALL_DIR/vpngw" /usr/local/bin/vg
chmod +x /usr/local/bin/vpngw /usr/local/bin/vg

# TUN 设备：没有它 OpenVPN 无法创建 tun0
if [ ! -c /dev/net/tun ]; then
    modprobe tun 2>/dev/null || true
    if [ ! -c /dev/net/tun ]; then
        mkdir -p /dev/net
        mknod /dev/net/tun c 10 200 2>/dev/null && chmod 600 /dev/net/tun || true
    fi
fi
if [ -c /dev/net/tun ]; then
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
RestartPreventExitStatus=0
TimeoutStopSec=30

# 安全限制
NoNewPrivileges=no
PrivateTmp=no

# 环境
Environment=PYTHONUNBUFFERED=1
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

# 先停止旧服务
svc stop >/dev/null 2>&1 || true
sleep 1

echo ""
echo -e "${C}┌─── 初始化向导 ────────────────────────────────┐${NC}"
echo -e "${C}│ 直接回车使用括号中的默认值                    │${NC}"
echo -e "${C}└───────────────────────────────────────────────┘${NC}"
echo ""

read -p "  国家过滤（如 JP,US,KR，留空=不限）: " CC_INPUT
read -p "  自动轮换间隔（小时，0=关闭，默认 2）: " ROT_INPUT
read -p "  保留节点数量（默认 20）: " TOP_INPUT
read -p "  握手验证节点数（默认 10，越多越慢）: " PROBE_INPUT
read -p "  代理端口（默认 7928）: " PORT_INPUT

ROT_HOURS=${ROT_INPUT:-2}
TOP_NODES=${TOP_INPUT:-20}
PROBE_CNT=${PROBE_INPUT:-10}
PROXY_PORT=${PORT_INPUT:-7928}

python3 - << PYEOF
import json, os

cc_input = "${CC_INPUT}".strip()
cc_list = [x.strip().upper() for x in cc_input.split(',') if x.strip()] if cc_input else []

settings = {
    "country_filter":       cc_list,
    "rotate_hours":         float("${ROT_HOURS}"),
    "top_nodes":            int("${TOP_NODES}"),
    "probe_count":          int("${PROBE_CNT}"),
    "proxy_port":           int("${PROXY_PORT}"),
    "auto_fetch_on_start":  True,
}
os.makedirs("${INSTALL_DIR}/data", exist_ok=True)
with open("${INSTALL_DIR}/data/settings.json", "w") as f:
    json.dump(settings, f, indent=2, ensure_ascii=False)
print(f"  设置已保存: {settings}")
PYEOF

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
echo -e "${G}╚══════════════════════════════════════════════════╝${NC}"
echo ""

if [ "$INIT_SYS" = "none" ]; then
    echo -e "  ${Y}请按上面提示手动启动服务${NC}"
else
    read -p "  是否立即启动服务？[Y/n] " START_NOW
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
