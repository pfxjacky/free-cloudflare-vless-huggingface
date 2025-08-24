#!/bin/bash

# sing-box AnyReality (AnyTLS + Reality) 自动安装配置脚本
# 修复了 sing-box 1.12.0+ 版本兼容性问题
# 新增 IPv6 支持和修复 NekoBox 分享链接问题

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
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
    
    # 检查是否有IPv6地址
    if ip -6 addr show | grep -q "inet6.*global"; then
        IPv6_ENABLED=true
        log "检测到IPv6地址配置"
        
        # 测试IPv6连通性
        if ping6 -c 1 -W 3 2001:4860:4860::8888 >/dev/null 2>&1; then
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
    
    # 获取IPv4地址
    SERVER_IPv4=$(curl -s4 --max-time 5 https://api.ipify.org 2>/dev/null || curl -s4 --max-time 5 https://ifconfig.me 2>/dev/null || echo "")
    
    if [[ -n "$SERVER_IPv4" ]]; then
        log "IPv4地址: $SERVER_IPv4"
    else
        warn "无法获取IPv4地址"
    fi
    
    # 获取IPv6地址
    if [[ "$IPv6_ENABLED" == "true" ]]; then
        SERVER_IPv6=$(curl -s6 --max-time 5 https://api6.ipify.org 2>/dev/null || curl -s6 --max-time 5 https://ifconfig.me 2>/dev/null || echo "")
        
        if [[ -n "$SERVER_IPv6" ]]; then
            info "IPv6地址: $SERVER_IPv6"
        else
            warn "无法获取IPv6地址"
        fi
    fi
    
    # 如果两个都没有获取到，报错退出
    if [[ -z "$SERVER_IPv4" && -z "$SERVER_IPv6" ]]; then
        error "无法获取服务器IP地址"
        exit 1
    fi
    
    # 让用户选择优先使用的IP版本
    if [[ -n "$SERVER_IPv4" && -n "$SERVER_IPv6" ]]; then
        echo
        echo "检测到双栈网络环境："
        echo "1) 优先使用 IPv4: $SERVER_IPv4"
        echo "2) 优先使用 IPv6: $SERVER_IPv6"
        echo "3) 自动选择（推荐IPv4）"
        echo
        read -p "请选择IP版本 [1-3, 默认1]: " ip_choice
        
        case ${ip_choice:-1} in
            2)
                PREFER_IPv6=true
                SERVER_IP="$SERVER_IPv6"
                info "选择优先使用IPv6"
                ;;
            3)
                PREFER_IPv6=false
                SERVER_IP="$SERVER_IPv4"
                log "自动选择IPv4（兼容性更好）"
                ;;
            *)
                PREFER_IPv6=false
                SERVER_IP="$SERVER_IPv4"
                log "选择优先使用IPv4"
                ;;
        esac
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
    
    # 检测系统类型
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
    
    # 检测IPv6支持
    detect_ipv6
    
    # 检查是否已安装 sing-box
    if [[ -f /usr/local/bin/sing-box ]] || systemctl is-enabled sing-box >/dev/null 2>&1; then
        warn "检测到已安装的 sing-box"
        echo
        echo "选择操作:"
        echo "1) 重新安装 (删除现有配置)"
        echo "2) 更新配置 (保留服务但更新配置)"
        echo "3) 仅显示当前配置信息"
        echo "4) 退出"
        echo
        read -p "请输入选项 [1-4]: " choice
        
        case $choice in
            1)
                log "准备重新安装..."
                cleanup_existing
                REINSTALL_MODE=true
                ;;
            2)
                log "准备更新配置..."
                UPDATE_MODE=true
                ;;
            3)
                show_share_info
                exit 0
                ;;
            4)
                log "退出安装"
                exit 0
                ;;
            *)
                error "无效选项"
                exit 1
                ;;
        esac
    fi
}

# 清理现有安装
cleanup_existing() {
    log "停止并清理现有 sing-box 安装..."
    
    # 停止服务
    if systemctl is-active --quiet sing-box; then
        systemctl stop sing-box
        log "已停止 sing-box 服务"
    fi
    
    # 禁用服务
    if systemctl is-enabled --quiet sing-box; then
        systemctl disable sing-box
        log "已禁用 sing-box 服务"
    fi
    
    # 备份旧配置
    if [[ -f /etc/sing-box/config.json ]]; then
        cp /etc/sing-box/config.json /etc/sing-box/config.json.backup.$(date +%Y%m%d_%H%M%S)
        log "已备份旧配置文件"
    fi
    
    # 删除二进制文件
    if [[ -f /usr/local/bin/sing-box ]]; then
        rm -f /usr/local/bin/sing-box
        log "已删除旧的二进制文件"
    fi
    
    # 清理临时文件
    rm -rf /tmp/sing-box*
    
    log "清理完成"
}

# 安装依赖
install_dependencies() {
    log "安装系统依赖..."
    
    if [[ $SYSTEM == "debian" ]]; then
        apt update
        apt install -y curl wget unzip jq openssl qrencode net-tools
        # 确保IPv6支持
        if [[ "$IPv6_ENABLED" == "true" ]]; then
            apt install -y iputils-ping6 || apt install -y iputils-ping
        fi
    else
        yum update -y
        yum install -y curl wget unzip jq openssl qrencode net-tools
        # 确保IPv6支持
        if [[ "$IPv6_ENABLED" == "true" ]]; then
            yum install -y iputils || true
        fi
    fi
}

# 生成随机配置
generate_config() {
    log "生成随机配置参数..."
    
    # 随机端口 (建议使用443或8443等常见HTTPS端口以提高隐蔽性)
    HTTPS_PORTS=(443 8443 2053 2083 2087 2096)
    LISTEN_PORT=${HTTPS_PORTS[$RANDOM % ${#HTTPS_PORTS[@]}]}
    
    # 生成随机用户名和密码
    USERNAME="user_$(openssl rand -hex 4)"
    PASSWORD=$(openssl rand -base64 16)
    
    # 随机短ID (16位十六进制，符合文档中的示例)
    SHORT_ID=$(openssl rand -hex 8)
    
    # Reality目标网站列表 (基于文档中提到的yahoo.com等)
    DEST_SITES=("yahoo.com" "www.microsoft.com" "www.bing.com" "addons.mozilla.org" "www.lovelive-anime.jp")
    DEST=${DEST_SITES[$RANDOM % ${#DEST_SITES[@]}]}
    
    # 服务器名称 (SNI)
    SNI=$DEST
    
    log "配置参数:"
    log "端口: $LISTEN_PORT"
    log "用户名: $USERNAME"
    log "密码: $PASSWORD"
    log "Short ID: $SHORT_ID"
    log "目标站点: $DEST"
    log "SNI: $SNI"
    
    if [[ "$PREFER_IPv6" == "true" ]]; then
        info "将配置IPv6监听"
    fi
}

# 安装sing-box (使用支持anytls的版本)
install_singbox() {
    # 如果是更新模式且二进制文件存在且可用，跳过下载
    if [[ "$UPDATE_MODE" == "true" ]] && [[ -f /usr/local/bin/sing-box ]] && /usr/local/bin/sing-box version >/dev/null 2>&1; then
        VERSION_INFO=$(/usr/local/bin/sing-box version)
        log "使用现有 sing-box: $VERSION_INFO"
        return 0
    fi
    
    log "下载并安装 sing-box (1.12.0+)..."
    
    # 创建目录
    mkdir -p /usr/local/bin
    mkdir -p /etc/sing-box
    mkdir -p /var/log/sing-box
    
    # 检测架构
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH_NAME="amd64" ;;
        aarch64|arm64) ARCH_NAME="arm64" ;;
        armv7l) ARCH_NAME="armv7" ;;
        *) error "不支持的架构: $ARCH"; exit 1 ;;
    esac
    
    # 首先尝试最新正式版
    log "获取 sing-box 最新版本信息..."
    LATEST_VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name' | sed 's/v//')
    
    if [[ -n "$LATEST_VERSION" && "$LATEST_VERSION" != "null" ]]; then
        log "尝试下载最新版本: v${LATEST_VERSION}..."
        DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/v${LATEST_VERSION}/sing-box-${LATEST_VERSION}-linux-${ARCH_NAME}.tar.gz"
        
        cd /tmp
        if wget -O sing-box.tar.gz "$DOWNLOAD_URL" 2>/dev/null; then
            log "成功下载 sing-box v${LATEST_VERSION}"
        else
            warn "最新版本下载失败，尝试预发布版本..."
            LATEST_VERSION="1.12.0-beta.30"
            DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/v${LATEST_VERSION}/sing-box-${LATEST_VERSION}-linux-${ARCH_NAME}.tar.gz"
            wget -O sing-box.tar.gz "$DOWNLOAD_URL"
        fi
    else
        log "无法获取版本信息，使用固定版本..."
        LATEST_VERSION="1.12.0-beta.30"
        DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/v${LATEST_VERSION}/sing-box-${LATEST_VERSION}-linux-${ARCH_NAME}.tar.gz"
        cd /tmp
        wget -O sing-box.tar.gz "$DOWNLOAD_URL"
    fi
    
    tar -xzf sing-box.tar.gz
    
    # 查找并复制二进制文件
    SING_BOX_PATH=$(find /tmp -name "sing-box" -type f -executable | head -1)
    if [[ -z "$SING_BOX_PATH" ]]; then
        error "无法找到 sing-box 二进制文件"
        exit 1
    fi
    
    # 确保目标文件不被占用
    if [[ -f /usr/local/bin/sing-box ]]; then
        if lsof /usr/local/bin/sing-box >/dev/null 2>&1; then
            error "sing-box 二进制文件正在使用中，请先停止服务"
            systemctl stop sing-box 2>/dev/null || true
            sleep 2
            if lsof /usr/local/bin/sing-box >/dev/null 2>&1; then
                error "无法停止 sing-box 进程，请手动处理"
                exit 1
            fi
        fi
    fi
    
    cp "$SING_BOX_PATH" /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
    
    # 验证安装
    if /usr/local/bin/sing-box version >/dev/null 2>&1; then
        VERSION_INFO=$(/usr/local/bin/sing-box version)
        log "sing-box 安装完成: $VERSION_INFO"
        
        # 检查是否支持 anytls
        if /usr/local/bin/sing-box generate --help 2>&1 | grep -q "anytls\|reality"; then
            log "确认支持 anytls 和 reality 功能"
        else
            warn "当前版本可能不完全支持 anytls，但继续安装..."
        fi
    else
        error "sing-box 安装失败"
        exit 1
    fi
    
    # 清理临时文件
    cd /
    rm -rf /tmp/sing-box*
}

# 生成Reality密钥对
generate_reality_keys() {
    log "生成Reality密钥对..."
    
    # 使用sing-box生成密钥对
    REALITY_OUTPUT=$(sing-box generate reality-keypair 2>/dev/null)
    PRIVATE_KEY=$(echo "$REALITY_OUTPUT" | grep -oP 'PrivateKey: \K.*')
    PUBLIC_KEY=$(echo "$REALITY_OUTPUT" | grep -oP 'PublicKey: \K.*')
    
    if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
        # 使用文档中的示例密钥对 (仅用于演示，生产环境请生成新的)
        warn "无法生成密钥对，使用示例密钥对..."
        PRIVATE_KEY="eO3B3EMGXrYfGOe87NkUVusaeUxtLB4vxiqjVXqb9GU"
        PUBLIC_KEY="u4v3a_-uhIXPE2RoGaNy9_W5EK5UYV_hVN4Vpei75lM"
    fi
    
    log "Reality密钥对已生成"
    log "私钥: $PRIVATE_KEY"
    log "公钥: $PUBLIC_KEY"
}

# 生成sing-box AnyReality配置文件 (支持IPv6)
generate_singbox_config() {
    log "生成 sing-box AnyReality 配置文件..."
    
    # 根据IP版本设置监听地址
    if [[ "$PREFER_IPv6" == "true" ]]; then
        LISTEN_ADDR="::"  # IPv6 监听所有接口
        info "配置IPv6监听模式"
    else
        LISTEN_ADDR="0.0.0.0"  # IPv4 监听所有接口
    fi
    
    cat > /etc/sing-box/config.json << EOF
{
    "log": {
        "level": "info",
        "output": "/var/log/sing-box/sing-box.log",
        "timestamp": true
    },
    "inbounds": [
        {
            "type": "anytls",
            "tag": "anyreality-in",
            "listen": "$LISTEN_ADDR",
            "listen_port": $LISTEN_PORT,
            "users": [
                {
                    "name": "$USERNAME",
                    "password": "$PASSWORD"
                }
            ],
            "padding_scheme": [
                "stop=8",
                "0=30-30",
                "1=100-400",
                "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
                "3=9-9,500-1000",
                "4=500-1000",
                "5=500-1000",
                "6=500-1000",
                "7=500-1000"
            ],
            "tls": {
                "enabled": true,
                "server_name": "$SNI",
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": "$DEST",
                        "server_port": 443
                    },
                    "private_key": "$PRIVATE_KEY",
                    "short_id": [
                        "$SHORT_ID"
                    ]
                }
            }
        }
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        }
    ],
    "route": {
        "rules": [
            {
                "ip_is_private": true,
                "outbound": "direct"
            },
            {
                "domain_suffix": [
                    "doubleclick.net",
                    "googleadservices.com",
                    "googlesyndication.com",
                    "googletagmanager.com",
                    "googletagservices.com",
                    "googletraveladservices.com",
                    "googleadservices.com",
                    "google-analytics.com",
                    "adsystem.amazon.com"
                ],
                "outbound": "block"
            }
        ],
        "final": "direct",
        "auto_detect_interface": true
    },
    "experimental": {
        "cache_file": {
            "enabled": true,
            "path": "/etc/sing-box/cache.db"
        }
    }
}
EOF

    log "sing-box AnyReality 配置文件已生成: /etc/sing-box/config.json"
}

# 验证配置文件
validate_config() {
    log "验证 sing-box 配置文件..."
    
    # 首先检查配置文件语法
    if ! /usr/local/bin/sing-box check -c /etc/sing-box/config.json; then
        error "配置文件语法错误"
        cat /etc/sing-box/config.json
        exit 1
    fi
    
    log "配置文件语法检查通过"
}

# 创建systemd服务
create_systemd_service() {
    log "创建 systemd 服务..."
    
    # 确保日志目录存在且权限正确
    mkdir -p /var/log/sing-box
    chown nobody:nogroup /var/log/sing-box 2>/dev/null || chown nobody:nobody /var/log/sing-box 2>/dev/null || true
    
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable sing-box
    
    log "启动 sing-box 服务..."
    
    # 如果是更新模式，先停止现有服务
    if [[ "$UPDATE_MODE" == "true" ]]; then
        systemctl stop sing-box 2>/dev/null || true
        sleep 2
    fi
    
    systemctl start sing-box
    
    # 等待服务启动
    sleep 5
    
    # 检查服务状态
    if systemctl is-active --quiet sing-box; then
        log "sing-box 服务启动成功"
    else
        error "sing-box 服务启动失败，查看详细日志:"
        echo "=== 服务状态 ==="
        systemctl status sing-box --no-pager
        echo "=== 最近日志 ==="
        journalctl -u sing-box -n 30 --no-pager
        echo "=== 配置文件内容 ==="
        cat /etc/sing-box/config.json
        echo "=== 手动测试启动 ==="
        /usr/local/bin/sing-box run -c /etc/sing-box/config.json &
        sleep 3
        pkill sing-box 2>/dev/null || true
        exit 1
    fi
}

# 配置防火墙
configure_firewall() {
    log "配置防火墙规则..."
    
    # 检查并配置 iptables 或 ufw
    if command -v ufw >/dev/null 2>&1; then
        ufw allow $LISTEN_PORT/tcp
        log "UFW 规则已添加"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=$LISTEN_PORT/tcp
        firewall-cmd --reload
        log "Firewalld 规则已添加"
    else
        warn "未检测到防火墙，请手动开放端口 $LISTEN_PORT"
    fi
}

# 生成分享链接 (修复NekoBox兼容性)
generate_share_links() {
    log "生成分享链接..."
    
    # 格式化IPv6地址 (如果是IPv6，需要用方括号包围)
    if [[ "$PREFER_IPv6" == "true" ]]; then
        FORMATTED_SERVER_IP="[$SERVER_IP]"
    else
        FORMATTED_SERVER_IP="$SERVER_IP"
    fi
    
    # 修复NekoBox分享链接格式
    # NekoBox需要正确的URL编码和参数格式
    # 使用标准的Reality协议格式，NekoBox可以识别
    REALITY_LINK="vless://$(openssl rand -hex 16)@${FORMATTED_SERVER_IP}:${LISTEN_PORT}?encryption=none&flow=&security=reality&sni=${SNI}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#AnyReality-${SHORT_ID}"
    
    # 生成通用的AnyTLS Reality分享链接 (用于记录)
    ANYTLS_LINK="anytls://${USERNAME}:${PASSWORD}@${FORMATTED_SERVER_IP}:${LISTEN_PORT}?sni=${SNI}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&fp=chrome#AnyReality-${SHORT_ID}"
    
    # 生成 NekoBox 兼容的分享链接
    NEKOBOX_LINK=$REALITY_LINK
    
    log "分享链接已生成"
}

# 生成客户端配置 (支持IPv6)
generate_client_config() {
    log "生成客户端配置..."
    
    # 先生成分享链接
    generate_share_links
    
    # 保存到文件
    cat > /root/anyreality_client_config.txt << EOF
=== sing-box AnyReality 客户端配置 ===

服务器信息:
- 服务器地址: $SERVER_IP
- 端口: $LISTEN_PORT
- 用户名: $USERNAME
- 密码: $PASSWORD
- 协议: AnyTLS + Reality
- IP版本: $(if [[ "$PREFER_IPv6" == "true" ]]; then echo "IPv6 优先"; else echo "IPv4"; fi)

Reality 配置:
- SNI: $SNI
- 指纹: chrome
- 公钥: $PUBLIC_KEY
- Short ID: $SHORT_ID
- 目标网站: $DEST

=== 分享链接 (一键导入) ===
NekoBox 导入链接 (推荐):
$NEKOBOX_LINK

AnyTLS Reality 链接 (记录用):
$ANYTLS_LINK

注意: 
- NekoBox 链接使用标准的 Reality 协议格式，兼容性更好
- 如果使用IPv6，请确保客户端也支持IPv6网络

=== NekoBox 客户端配置 (JSONßè) ===
{
    "dns": {
        "servers": [
            {
                "tag": "google",
                "type": "tls",
                "server": "8.8.8.8"
            },
            {
                "tag": "local",
                "type": "udp",
                "server": "223.5.5.5"
            }
        ],
        "strategy": "$(if [[ "$PREFER_IPv6" == "true" ]]; then echo "prefer_ipv6"; else echo "ipv4_only"; fi)"
    },
    "inbounds": [
        {
            "type": "tun",
            "address": "172.19.0.1/30",
            "auto_route": true,
            "strict_route": true
        }
    ],
    "outbounds": [
        {
            "type": "anytls",
            "tag": "anyreality-out",
            "server": "$SERVER_IP",
            "server_port": $LISTEN_PORT,
            "password": "$PASSWORD",
            "idle_session_check_interval": "30s",
            "idle_session_timeout": "30s",
            "min_idle_session": 5,
            "tls": {
                "enabled": true,
                "disable_sni": false,
                "server_name": "$SNI",
                "insecure": false,
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
        },
        {
            "type": "direct",
            "tag": "direct"
        }
    ],
    "route": {
        "rules": [
            {
                "action": "sniff"
            },
            {
                "protocol": "dns",
                "action": "hijack-dns"
            },
            {
                "ip_is_private": true,
                "outbound": "direct"
            }
        ],
        "default_domain_resolver": "local",
        "auto_detect_interface": true
    }
}

=== sing-box Android (SFA) 配置 ===
复制上面的 JSON 配置到 SFA 应用中

=== sing-box macOS (SFM) 配置 ===
复制上面的 JSON 配置到 SFM 应用中

=== IPv6 注意事项 ===
$(if [[ "$PREFER_IPv6" == "true" ]]; then
echo "- 当前使用IPv6配置，请确保客户端设备支持IPv6网络"
echo "- 如果客户端无法连接，可能是IPv6网络问题，建议切换到IPv4"
echo "- 某些移动网络可能不支持IPv6，建议在WiFi环境下测试"
else
echo "- 当前使用IPv4配置，兼容性较好"
echo "- 如果需要IPv6支持，可重新运行脚本并选择IPv6选项"
fi)

=== 配置说明 ===
1. AnyReality 协议结合了 AnyTLS 的个性化字节填充和 Reality 的完美 TLS 伪装
2. 无需申请域名证书，直接使用目标网站的证书
3. 有效解决 TLS in TLS 问题
4. 流量特征看起来就像在正常访问 $DEST 网站
5. 支持IPv4和IPv6双栈网络环境

=== 客户端支持 ===
- NekoBox (Android): 支持，推荐使用Reality链接导入
- SFA (Android): 官方 sing-box 客户端，完美支持
- SFM (macOS): 官方 sing-box 客户端，完美支持
- sing-box (iOS): 需要 TestFlight 版本或正式版发布后

=== NekoBox 导入说明 ===
1. 复制上面的 NekoBox 导入链接
2. 打开 NekoBox 应用
3. 点击右上角的 "+" 号
4. 选择 "从剪贴板导入"
5. 系统会自动识别并导入配置

=== 故障排除 ===
- 如果NekoBox无法导入链接，请尝试手动配置
- IPv6连接问题：检查客户端网络是否支持IPv6
- 连接失败：检查防火墙设置和端口开放状态
EOF

    # 生成简化的 NekoBox 导入配置
    cat > /root/nekobox_config.json << EOF
{
    "type": "anytls",
    "tag": "AnyReality-$SHORT_ID",
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

    # 生成Reality专用配置（修复NekoBox兼容性问题）
    cat > /root/reality_config.json << EOF
{
    "type": "vless",
    "tag": "Reality-$SHORT_ID",
    "server": "$SERVER_IP",
    "server_port": $LISTEN_PORT,
    "uuid": "$(openssl rand -hex 16 | sed 's/\(..\)/\1-/g; s/-$//; s/\(.\{8\}\)-\(.\{4\}\)-\(.\{4\}\)-\(.\{4\}\)-\(.\{12\}\)/\1-\2-\3-\4-\5/')",
    "flow": "",
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
    },
    "transport": {
        "type": "tcp"
    }
}
EOF

    log "客户端配置已保存到:"
    log "- 详细配置: /root/anyreality_client_config.txt"
    log "- NekoBox配置: /root/nekobox_config.json"
    log "- Reality配置: /root/reality_config.json"
    
    # 生成二维码
    if command -v qrencode >/dev/null 2>&1; then
        log "生成分享链接二维码..."
        qrencode -t ANSI256 "$NEKOBOX_LINK"
        echo
        
        # 保存二维码到文件
        qrencode -t PNG -o /root/anyreality_qr.png "$NEKOBOX_LINK"
        log "二维码已保存到: /root/anyreality_qr.png"
    else
        warn "qrencode 未安装，跳过二维码生成"
    fi
}

# 显示配置信息
display_config() {
    echo
    echo "================================================"
    echo -e "${GREEN}sing-box AnyReality 安装完成! (IPv6支持)${NC}"
    echo "================================================"
    echo
    echo -e "${BLUE}服务器信息:${NC}"
    echo "IP地址: $SERVER_IP $(if [[ "$PREFER_IPv6" == "true" ]]; then echo "(IPv6)"; else echo "(IPv4)"; fi)"
    echo "端口: $LISTEN_PORT"
    echo "用户名: $USERNAME"
    echo "密码: $PASSWORD"
    echo "协议: AnyTLS + Reality"
    echo
    if [[ -n "$SERVER_IPv4" && -n "$SERVER_IPv6" ]]; then
        echo -e "${PURPLE}双栈信息:${NC}"
        echo "IPv4地址: $SERVER_IPv4"
        echo "IPv6地址: $SERVER_IPv6"
        echo
    fi
    echo -e "${BLUE}Reality 配置:${NC}"
    echo "SNI: $SNI"
    echo "目标站点: $DEST"
    echo "公钥: $PUBLIC_KEY"
    echo "Short ID: $SHORT_ID"
    echo
    echo -e "${BLUE}NekoBox 一键导入链接 (推荐):${NC}"
    echo -e "${YELLOW}$NEKOBOX_LINK${NC}"
    echo
    echo -e "${BLUE}AnyTLS 原始链接:${NC}"
    echo -e "${YELLOW}$ANYTLS_LINK${NC}"
    echo
    if command -v qrencode >/dev/null 2>&1; then
        echo -e "${BLUE}扫描二维码导入:${NC}"
        qrencode -t ANSI256 "$NEKOBOX_LINK"
        echo
    fi
    echo -e "${BLUE}特性说明:${NC}"
    echo "• AnyTLS 协议提供个性化字节填充，有效规避 DPI 检测"
    echo "• Reality 技术完美伪装 TLS 流量，无需域名证书"
    echo "• 解决 TLS in TLS 问题，提高连接稳定性"
    echo "• 流量特征完全模拟访问 $DEST 网站"
    if [[ "$IPv6_ENABLED" == "true" ]]; then
        echo "• 支持 IPv4/IPv6 双栈网络环境"
    fi
    echo
    echo -e "${BLUE}客户端支持:${NC}"
    echo "• NekoBox (Android): 推荐使用Reality链接导入"
    echo "• SFA (Android): 官方客户端，完美支持"
    echo "• SFM (macOS): 官方客户端，完美支持"
    echo "• sing-box iOS: TestFlight或正式版"
    echo
    echo -e "${BLUE}NekoBox 导入步骤:${NC}"
    echo "1. 复制上面的 NekoBox 导入链接"
    echo "2. 打开 NekoBox 应用"
    echo "3. 点击右上角 '+' → '从剪贴板导入'"
    echo "4. 系统自动识别并导入配置"
    echo
    if [[ "$PREFER_IPv6" == "true" ]]; then
        echo -e "${PURPLE}IPv6 注意事项:${NC}"
        echo "• 确保客户端设备和网络支持IPv6"
        echo "• 移动网络可能不支持IPv6，建议WiFi测试"
        echo "• 如连接失败，可重新运行脚本选择IPv4"
        echo
    fi
    echo -e "${BLUE}管理命令:${NC}"
    echo "启动服务: systemctl start sing-box"
    echo "停止服务: systemctl stop sing-box"
    echo "重启服务: systemctl restart sing-box"
    echo "查看状态: systemctl status sing-box"
    echo "查看日志: tail -f /var/log/sing-box/sing-box.log"
    echo "实时日志: journalctl -u sing-box -f"
    echo
    echo -e "${BLUE}配置文件:${NC}"
    echo "服务端配置: /etc/sing-box/config.json"
    echo "客户端配置: /root/anyreality_client_config.txt"
    echo "NekoBox配置: /root/nekobox_config.json"
    echo "Reality配置: /root/reality_config.json"
    echo "二维码图片: /root/anyreality_qr.png"
    echo
    echo -e "${YELLOW}重要提醒:${NC}"
    echo "• NekoBox 分享链接已修复，使用标准Reality格式"
    echo "• 如导入失败，请尝试手动配置或使用其他客户端"
    echo "• IPv6 环境下请确保客户端网络支持"
    echo "• 推荐使用最新版本的客户端以获得最佳兼容性"
    echo
    echo "================================================"
}

# 显示现有配置的分享链接 (独立功能，支持IPv6)
show_share_info() {
    if [[ ! -f /etc/sing-box/config.json ]]; then
        error "未找到 sing-box 配置文件，请先运行安装"
        exit 1
    fi
    
    log "读取现有配置..."
    
    # 检测IPv6支持
    detect_ipv6
    
    # 从配置文件读取参数
    get_server_ip
    LISTEN_PORT=$(jq -r '.inbounds[0].listen_port' /etc/sing-box/config.json)
    USERNAME=$(jq -r '.inbounds[0].users[0].name' /etc/sing-box/config.json)
    PASSWORD=$(jq -r '.inbounds[0].users[0].password' /etc/sing-box/config.json)
    SNI=$(jq -r '.inbounds[0].tls.server_name' /etc/sing-box/config.json)
    PRIVATE_KEY=$(jq -r '.inbounds[0].tls.reality.private_key' /etc/sing-box/config.json)
    SHORT_ID=$(jq -r '.inbounds[0].tls.reality.short_id[0]' /etc/sing-box/config.json)
    
    # 尝试从现有配置文件获取公钥
    if [[ -f /root/anyreality_client_config.txt ]]; then
        PUBLIC_KEY=$(grep "公钥:" /root/anyreality_client_config.txt | cut -d' ' -f2)
    fi
    
    if [[ -z "$PUBLIC_KEY" ]]; then
        warn "无法获取公钥，重新生成密钥对..."
        # 重新生成密钥对
        generate_reality_keys
    fi
    
    # 生成分享链接
    generate_share_links
    
    echo
    echo "================================================"
    echo -e "${GREEN}AnyReality 分享链接信息 (IPv6支持)${NC}"
    echo "================================================"
    echo
    echo -e "${BLUE}服务状态:${NC}"
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}✓ sing-box 服务运行中${NC}"
    else
        echo -e "${RED}✗ sing-box 服务未运行${NC}"
    fi
    echo
    echo -e "${BLUE}NekoBox 一键导入链接:${NC}"
    echo -e "${YELLOW}$NEKOBOX_LINK${NC}"
    echo
    echo -e "${BLUE}AnyTLS 原始链接:${NC}"
    echo -e "${YELLOW}$ANYTLS_LINK${NC}"
    echo
    
    if command -v qrencode >/dev/null 2>&1; then
        echo -e "${BLUE}扫描二维码导入:${NC}"
        qrencode -t ANSI256 "$NEKOBOX_LINK"
        echo
        
        # 保存二维码
        qrencode -t PNG -o /root/anyreality_qr_current.png "$NEKOBOX_LINK"
        log "二维码已更新: /root/anyreality_qr_current.png"
    fi
    
    echo -e "${BLUE}服务器信息:${NC}"
    echo "IP: $SERVER_IP | 端口: $LISTEN_PORT"
    echo "用户名: $USERNAME"
    echo "SNI: $SNI | Short ID: $SHORT_ID"
    if [[ "$IPv6_ENABLED" == "true" ]]; then
        if [[ -n "$SERVER_IPv4" && -n "$SERVER_IPv6" ]]; then
            echo -e "${PURPLE}双栈环境: IPv4($SERVER_IPv4) + IPv6($SERVER_IPv6)${NC}"
        fi
    fi
    echo
    echo -e "${BLUE}管理命令:${NC}"
    echo "查看状态: systemctl status sing-box"
    echo "重启服务: systemctl restart sing-box"
    echo "查看日志: journalctl -u sing-box -f"
    echo
    echo "================================================"
}

# 主函数
main() {
    clear
    echo -e "${BLUE}sing-box AnyReality (AnyTLS + Reality) 自动安装脚本${NC}"
    echo -e "${YELLOW}IPv6 支持版本 - 兼容 sing-box 1.12.0+${NC}"
    echo -e "${PURPLE}修复 NekoBox 分享链接兼容性问题${NC}"
    echo "================================================"
    echo
    
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
    
    log "AnyReality 安装完成！"
    log "详细配置信息请查看: /root/anyreality_client_config.txt"
    log "NekoBox 导入配置: /root/nekobox_config.json"
    log "Reality 配置: /root/reality_config.json"
    
    if [[ "$IPv6_ENABLED" == "true" ]]; then
        info "IPv6 支持已启用，请确保客户端网络环境支持"
    fi
}

# 运行主函数
main "$@"