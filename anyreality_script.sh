#!/bin/bash

# sing-box AnyReality (AnyTLS + Reality) 自动安装配置脚本
# 最终修复版：修正协议不匹配问题，确保服务端和客户端配置一致

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# 全局变量
IPv6_ENABLED=false
SERVER_IPv4=""
SERVER_IPv6=""
PREFER_IPv6=false

# 日志函数
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

info() {
    echo -e "${PURPLE}[IPv6]${NC} $1"
}

# 检测IPv6支持
detect_ipv6() {
    log "检测IPv6支持..."
    if ip -6 addr show | grep -q "inet6.*global"; then
        IPv6_ENABLED=true
        log "检测到IPv6地址配置"
        if ping -6 -c 1 -W 3 google.com >/dev/null 2>&1; then
            log "IPv6网络连通性测试成功"
        else
            warn "IPv6网络可能无法正常访问外网"
        fi
    else
        warn "未检测到IPv6配置"
        IPv6_ENABLED=false
    fi
}

# 获取服务器IP（支持IPv4和IPv6）
get_server_ip() {
    log "获取服务器IP地址..."
    SERVER_IPv4=$(curl -s4 --max-time 5 https://api.ipify.org 2>/dev/null || curl -s4 --max-time 5 https://ifconfig.me 2>/dev/null || echo "")
    if [[ -n "$SERVER_IPv4" ]]; then
        log "IPv4地址: $SERVER_IPv4"
    else
        warn "无法获取IPv4地址"
    fi

    if [[ "$IPv6_ENABLED" == "true" ]]; then
        SERVER_IPv6=$(curl -s6 --max-time 5 https://api6.ipify.org 2>/dev/null || curl -s6 --max-time 5 https://ifconfig.me 2>/dev/null || echo "")
        if [[ -n "$SERVER_IPv6" ]]; then
            info "IPv6地址: $SERVER_IPv6"
        else
            warn "无法获取IPv6地址"
        fi
    fi

    if [[ -z "$SERVER_IPv4" && -z "$SERVER_IPv6" ]]; then
        error "无法获取服务器IP地址"
        exit 1
    fi

    if [[ -n "$SERVER_IPv4" && -n "$SERVER_IPv6" ]]; then
        echo
        read -p "检测到双栈网络，请选择优先使用的IP版本 (1=IPv4, 2=IPv6) [默认1]: " ip_choice
        if [[ "${ip_choice:-1}" == "2" ]]; then
            PREFER_IPv6=true
            SERVER_IP="$SERVER_IPv6"
            info "选择优先使用IPv6"
        else
            PREFER_IPv6=false
            SERVER_IP="$SERVER_IPv4"
            log "选择优先使用IPv4（兼容性更好）"
        fi
    elif [[ -n "$SERVER_IPv6" ]]; then
        PREFER_IPv6=true
        SERVER_IP="$SERVER_IPv6"
        info "仅检测到IPv6，将使用IPv6"
    else
        PREFER_IPv6=false
        SERVER_IP="$SERVER_IPv4"
        log "仅检测到IPv4，将使用IPv4"
    fi
}

# 检查系统和已安装状态
check_system() {
    log "检查系统环境..."
    if [[ $EUID -ne 0 ]]; then
        error "请使用 root 权限运行此脚本"
        exit 1
    fi

    if [[ -f /etc/redhat-release ]]; then
        SYSTEM="centos"
        PACKAGE_MANAGER="yum"
    elif [[ -f /etc/debian_version ]]; then
        SYSTEM="debian"
        PACKAGE_MANAGER="apt"
    else
        error "不支持的系统类型"
        exit 1
    fi
    log "检测到系统: $SYSTEM"
    detect_ipv6

    if [[ -f /usr/local/bin/sing-box ]] || systemctl is-enabled sing-box >/dev/null 2>&1; then
        warn "检测到已安装的 sing-box，请选择操作..."
        select opt in "重新安装" "更新配置" "显示配置" "退出"; do
            case $opt in
                "重新安装")
                    cleanup_existing
                    break
                    ;;
                "更新配置")
                    UPDATE_MODE=true
                    break
                    ;;
                "显示配置")
                    show_share_info
                    exit 0
                    ;;
                "退出")
                    exit 0
                    ;;
                *) 
                    error "无效选项"
                    ;;
            esac
        done
    fi
}

# 清理现有安装
cleanup_existing() {
    log "停止并清理现有 sing-box 安装..."
    systemctl stop sing-box 2>/dev/null || true
    systemctl disable sing-box 2>/dev/null || true
    if [[ -f /etc/sing-box/config.json ]]; then
        mv /etc/sing-box/config.json "/etc/sing-box/config.json.backup.$(date +%Y%m%d_%H%M%S)"
        log "已备份旧配置文件"
    fi
    rm -f /usr/local/bin/sing-box
    log "清理完成"
}

# 安装依赖
install_dependencies() {
    log "安装系统依赖..."
    if [[ $SYSTEM == "debian" ]]; then
        apt-get update
        apt-get install -y curl wget unzip jq openssl qrencode coreutils
    else
        yum install -y curl wget unzip jq openssl qrencode coreutils
    fi
}

# 生成随机配置
generate_config() {
    log "生成随机配置参数..."
    HTTPS_PORTS=(443 8443 2053 2083 2087 2096)
    LISTEN_PORT=${HTTPS_PORTS[$RANDOM % ${#HTTPS_PORTS[@]}]}
    USERNAME="user_$(openssl rand -hex 4)"
    PASSWORD=$(openssl rand -base64 16)
    SHORT_ID=$(openssl rand -hex 8)
    DEST_SITES=("yahoo.com" "www.microsoft.com" "www.bing.com" "addons.mozilla.org" "www.lovelive-anime.jp")
    DEST=${DEST_SITES[$RANDOM % ${#DEST_SITES[@]}]}
    SNI=$DEST
}

# 安装sing-box
install_singbox() {
    log "下载并安装 sing-box..."
    mkdir -p /usr/local/bin /etc/sing-box /var/log/sing-box
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH_NAME="amd64" ;;
        aarch64|arm64) ARCH_NAME="arm64" ;;
        *) error "不支持的架构: $ARCH"; exit 1 ;;
    esac
    LATEST_VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name' | sed 's/v//')
    if [[ -z "$LATEST_VERSION" ]]; then
        error "获取 sing-box 版本失败"
        exit 1
    fi
    DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/v${LATEST_VERSION}/sing-box-${LATEST_VERSION}-linux-${ARCH_NAME}.tar.gz"
    wget -O /tmp/sing-box.tar.gz "$DOWNLOAD_URL"
    tar -xzf /tmp/sing-box.tar.gz -C /tmp
    cp /tmp/sing-box-*/sing-box /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
    rm -rf /tmp/sing-box*
    log "sing-box v$LATEST_VERSION 安装完成"
}

# 生成Reality密钥对
generate_reality_keys() {
    log "生成Reality密钥对..."
    REALITY_OUTPUT=$(/usr/local/bin/sing-box generate reality-keypair)
    PRIVATE_KEY=$(echo "$REALITY_OUTPUT" | grep -oP 'PrivateKey: \K.*')
    PUBLIC_KEY=$(echo "$REALITY_OUTPUT" | grep -oP 'PublicKey: \K.*')
}

# 生成sing-box服务端配置文件
generate_singbox_config() {
    log "生成 sing-box AnyReality 配置文件..."
    LISTEN_ADDR=$([[ "$PREFER_IPv6" == "true" ]] && echo "::" || echo "0.0.0.0")
    
    cat > /etc/sing-box/config.json << EOF
{
    "log": {"level": "info", "output": "/var/log/sing-box/sing-box.log", "timestamp": true},
    "inbounds": [{
        "type": "anytls",
        "tag": "anyreality-in",
        "listen": "$LISTEN_ADDR",
        "listen_port": $LISTEN_PORT,
        "users": [{"name": "$USERNAME", "password": "$PASSWORD"}],
        "padding_scheme": ["stop=8","0=30-30","1=100-400","2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000","3=9-9,500-1000","4=500-1000","5=500-1000","6=500-1000","7=500-1000"],
        "tls": {
            "enabled": true,
            "server_name": "$SNI",
            "reality": {
                "enabled": true,
                "handshake": {"server": "$DEST", "server_port": 443},
                "private_key": "$PRIVATE_KEY",
                "short_id": ["$SHORT_ID"]
            }
        }
    }],
    "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}],
    "route": {
        "rules": [{"ip_is_private": true, "outbound": "direct"}],
        "final": "direct",
        "auto_detect_interface": true
    }
}
EOF
}

# 创建systemd服务
create_systemd_service() {
    log "创建 systemd 服务..."
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=sing-box service
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    sleep 3
    if ! systemctl is-active --quiet sing-box; then
        error "sing-box 服务启动失败，请检查日志: journalctl -u sing-box -n 50"
        exit 1
    fi
    log "sing-box 服务启动成功"
}

# 配置防火墙
configure_firewall() {
    log "配置防火墙规则..."
    if command -v ufw >/dev/null 2>&1; then
        ufw allow $LISTEN_PORT/tcp
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=$LISTEN_PORT/tcp
        firewall-cmd --reload
    fi
}

# 生成客户端配置
generate_client_config() {
    log "生成客户端配置..."
    # 格式化IP地址，IPv6需要加括号
    FORMATTED_SERVER_IP=$([[ "$PREFER_IPv6" == "true" ]] && echo "[$SERVER_IP]" || echo "$SERVER_IP")
    ANYTLS_LINK="anytls://${USERNAME}:${PASSWORD}@${FORMATTED_SERVER_IP}:${LISTEN_PORT}?sni=${SNI}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&fp=chrome#AnyReality-${SHORT_ID}"
    
    # 客户端JSON配置是关键
    CLIENT_JSON_CONFIG=$(cat <<EOF
{
    "type": "anytls",
    "tag": "anyreality-out",
    "server": "$SERVER_IP",
    "server_port": $LISTEN_PORT,
    "password": "$PASSWORD",
    "tls": {
        "enabled": true,
        "server_name": "$SNI",
        "utls": {
            "enabled": true,
            "fingerprint": "chrome"
        },
        "reality": {
            "enabled": true,
            "public_key": "$PUBLIC_KEY",
            "short_id": "$SHORT_ID"
        }
    }
}
EOF
)
    # 保存到文件
    cat > /root/anyreality_client_config.txt << EOF
=== sing-box AnyReality 客户端配置 ===

服务器信息:
- 服务器地址: $SERVER_IP
- 端口: $LISTEN_PORT
- 协议: AnyTLS + Reality
- 用户名: $USERNAME
- 密码: $PASSWORD

Reality 配置:
- SNI: $SNI
- 公钥: $PUBLIC_KEY
- Short ID: $SHORT_ID

============================================================
=== 导入方法 (重要!) ===
1. 复制下面的 JSON 代码块。
2. 在 NekoBox 或其他 sing-box 客户端中，选择“从剪贴板导入”。
3. 不要使用下面的 anytls:// 链接，大多数客户端不支持直接导入。

=== 客户端 JSON 配置 (复制此部分) ===
$CLIENT_JSON_CONFIG
============================================================

AnyTLS 原始链接 (仅供参考):
$ANYTLS_LINK

二维码图片 (请下载后扫描):
/root/anyreality_qr.png
EOF

    # 生成二维码图片文件
    if command -v qrencode >/dev/null 2>&1; then
        qrencode -t PNG -o /root/anyreality_qr.png "$ANYTLS_LINK"
        log "二维码图片已保存到 /root/anyreality_qr.png"
    fi
}

# 显示配置信息
display_config() {
    clear
    echo -e "${GREEN}sing-box AnyReality 安装完成!${NC}"
    echo "================================================"
    echo -e "${BLUE}服务端信息:${NC}"
    echo -e "IP地址: ${YELLOW}$SERVER_IP${NC} $([[ "$PREFER_IPv6" == "true" ]] && echo '(IPv6)' || echo '(IPv4)')"
    echo -e "端口: ${YELLOW}$LISTEN_PORT${NC}"
    echo -e "用户名: ${YELLOW}$USERNAME${NC}"
    echo -e "密码: ${YELLOW}$PASSWORD${NC}"
    echo -e "SNI/目标站点: ${YELLOW}$SNI${NC}"
    echo -e "公钥: ${YELLOW}$PUBLIC_KEY${NC}"
    echo -e "Short ID: ${YELLOW}$SHORT_ID${NC}"
    echo
    echo -e "${RED}=== 重要：客户端配置方法 ===${NC}"
    echo "1. 请使用 cat /root/anyreality_client_config.txt 命令查看配置"
    echo "2. 复制文件中的 ${YELLOW}JSON 配置块${NC}"
    echo "3. 在 NekoBox 等客户端中 ${YELLOW}从剪贴板导入${NC}"
    echo "4. ${RED}不要直接使用 anytls:// 链接导入，兼容性很差！${NC}"
    echo
    echo -e "${CYAN}管理命令:${NC}"
    echo "查看配置: cat /root/anyreality_client_config.txt"
    echo "重启服务: systemctl restart sing-box"
    echo "查看日志: journalctl -u sing-box -f"
    echo "================================================"
}

# 主函数
main() {
    clear
    check_system
    install_dependencies
    generate_config
    get_server_ip
    install_singbox
    generate_reality_keys
    generate_singbox_config
    validate_config
    create_systemd_service
    configure_firewall
    generate_client_config
    display_config
}

main "$@"
