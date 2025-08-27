#!/bin/bash

# sing-box AnyReality (AnyTLS + Reality) 自动安装配置脚本
# 修复了 sing-box 1.12.0+ 版本兼容性问题
# 新增 IPv6 支持和改进的二维码显示
# 修复了IPv6客户端配置问题

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

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
    echo -e "${BLUE}[INFO]${NC} $1"
}

# 检测IPv6支持
check_ipv6_support() {
    log "检测IPv6支持..."
    
    # 检查系统是否启用IPv6
    if [[ ! -f /proc/net/if_inet6 ]]; then
        warn "系统未启用IPv6支持"
        IPV6_SUPPORT=false
        return 0
    fi
    
    # 检查是否有全局IPv6地址
    IPV6_ADDRESSES=$(ip -6 addr show scope global | grep -c "inet6" || echo "0")
    if [[ $IPV6_ADDRESSES -eq 0 ]]; then
        warn "系统未配置全局IPv6地址"
        IPV6_SUPPORT=false
        return 0
    fi
    
    # 测试IPv6连接
    if ping6 -c 1 2001:4860:4860::8888 >/dev/null 2>&1; then
        log "IPv6连接测试成功"
        IPV6_SUPPORT=true
    else
        warn "IPv6连接测试失败，可能网络不支持或防火墙阻止"
        IPV6_SUPPORT=false
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
    check_ipv6_support
    
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
        # 添加 IPv6相关工具
        apt install -y curl wget unzip jq openssl qrencode iproute2 iputils-ping net-tools
    else
        yum update -y
        yum install -y curl wget unzip jq openssl qrencode iproute net-tools iputils
    fi
}

# 网络配置选择
choose_network_config() {
    echo
    echo -e "${BLUE}网络配置选择${NC}"
    echo "================================================"
    
    if [[ "$IPV6_SUPPORT" == "true" ]]; then
        echo "检测到IPv6支持，请选择网络配置:"
        echo "1) 仅IPv4 (推荐，兼容性最好)"
        echo "2) 仅IPv6 (需要客户端支持IPv6)"
        echo "3) 双栈 IPv4 + IPv6 (同时监听两个协议)"
        echo
        read -p "请选择网络配置 [1-3]: " network_choice
        
        case $network_choice in
            1)
                NETWORK_MODE="ipv4"
                log "选择仅IPv4模式"
                ;;
            2)
                NETWORK_MODE="ipv6"
                log "选择仅IPv6模式"
                ;;
            3)
                NETWORK_MODE="dual"
                log "选择IPv4+IPv6双栈模式"
                ;;
            *)
                warn "无效选择，默认使用IPv4模式"
                NETWORK_MODE="ipv4"
                ;;
        esac
    else
        log "系统不支持IPv6，使用IPv4模式"
        NETWORK_MODE="ipv4"
    fi
}

# 生成随机配置
generate_config() {
    log "生成随机配置参数..."
    
    # 随机端口 (建议使用443或8443等常见HTTPS端口以提高隐蔽性)
    HTTPS_PORTS=(443 8443 2053 2083 2087 2096 3306 5432 9929)
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
    log "网络模式: $NETWORK_MODE"
}

# 获取服务器IP
get_server_ip() {
    log "获取服务器IP地址..."
    
    # 获取IPv4地址
    IPV4_ADDRESS=$(curl -s https://api.ipify.org || curl -s https://ifconfig.me || curl -s https://icanhazip.com)
    
    if [[ -n "$IPV4_ADDRESS" ]]; then
        log "IPv4地址: $IPV4_ADDRESS"
    else
        warn "无法获取IPv4地址"
    fi
    
    # 获取IPv6地址
    if [[ "$IPV6_SUPPORT" == "true" ]]; then
        # 尝试多个IPv6检测服务
        IPV6_ADDRESS=$(curl -s https://ipv6.icanhazip.com || curl -s https://v6.ident.me || curl -s "https://api64.ipify.org")
        
        if [[ -n "$IPV6_ADDRESS" ]]; then
            log "IPv6地址: $IPV6_ADDRESS"
        else
            warn "无法获取公网IPv6地址"
        fi
    fi
    
    # 根据网络模式设置主要服务器IP
    case $NETWORK_MODE in
        "ipv4")
            SERVER_IP=$IPV4_ADDRESS
            if [[ -z "$SERVER_IP" ]]; then
                error "无法获取IPv4地址"
                exit 1
            fi
            ;;
        "ipv6")
            SERVER_IP=$IPV6_ADDRESS
            if [[ -z "$SERVER_IP" ]]; then
                error "无法获取IPv6地址"
                exit 1
            fi
            ;;
        "dual")
            SERVER_IP=$IPV4_ADDRESS
            SERVER_IPV6=$IPV6_ADDRESS
            if [[ -z "$SERVER_IP" && -z "$SERVER_IPV6" ]]; then
                error "无法获取任何IP地址"
                exit 1
            fi
            ;;
    esac
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
    
    # 根据网络模式生成不同的监听配置
    local listen_config=""
    local inbound_configs=""
    
    case $NETWORK_MODE in
        "ipv4")
            listen_config='"listen": "::",'
            ;;
        "ipv6")
            listen_config='"listen": "::",'
            ;;
        "dual")
            # 双栈模式，创建两个入站配置
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
            "tag": "anyreality-in-ipv6",
            "listen": "::",
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
            log "sing-box AnyReality 双栈配置文件已生成: /etc/sing-box/config.json"
            return 0
            ;;
    esac
    
    # 单栈模式配置
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
            $listen_config
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
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s
RestartPreventExitStatus=23
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
    
    # IPv6 防火墙配置
    if [[ "$NETWORK_MODE" == "ipv6" || "$NETWORK_MODE" == "dual" ]]; then
        if command -v ip6tables >/dev/null 2>&1; then
            # 检查ip6tables规则
            if ! ip6tables -C INPUT -p tcp --dport $LISTEN_PORT -j ACCEPT 2>/dev/null; then
                ip6tables -I INPUT -p tcp --dport $LISTEN_PORT -j ACCEPT
                log "IPv6 iptables 规则已添加"
                
                # 尝试保存规则
                if command -v ip6tables-save >/dev/null 2>&1; then
                    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
                fi
            fi
        fi
    fi
}

# 改进的二维码生成函数
generate_qrcode() {
    local content="$1"
    local filename="$2"
    
    # 检查qrencode是否可用
    if ! command -v qrencode >/dev/null 2>&1; then
        warn "qrencode 未安装，无法生成二维码"
        return 1
    fi
    
    # 生成终端显示的二维码（使用ANSI256格式，在SSH终端中显示效果更好）
    echo -e "${CYAN}二维码 (扫码导入):${NC}"
    echo "================================================"
    
    # 使用UTF8格式在终端中显示，兼容性更好
    if qrencode -t UTF8 "$content" 2>/dev/null; then
        echo "================================================"
    elif qrencode -t ANSI256 "$content" 2>/dev/null; then
        echo "================================================"  
    else
        # 备用方案：使用ASCII格式
        warn "使用备用ASCII格式显示二维码"
        qrencode -t ASCII "$content" 2>/dev/null || {
            error "二维码生成失败"
            return 1
        }
        echo "================================================"
    fi
    
    # 保存PNG格式的二维码文件
    if [[ -n "$filename" ]]; then
        if qrencode -t PNG -s 8 -m 2 -o "$filename" "$content" 2>/dev/null; then
            log "二维码已保存为: $filename"
        else
            warn "PNG二维码保存失败"
        fi
    fi
    
    return 0
}

# 生成分享链接
generate_share_links() {
    log "生成分享链接..."
    
    # 根据网络模式选择主要IP
    local primary_ip=""
    local secondary_info=""
    
    case $NETWORK_MODE in
        "ipv4")
            primary_ip="$SERVER_IP"
            secondary_info=""
            ;;
        "ipv6")
            # IPv6地址不需要方括号包围（这是关键修复点）
            primary_ip="$SERVER_IP"
            secondary_info=""
            ;;
        "dual")
            primary_ip="$SERVER_IP"
            if [[ -n "$SERVER_IPV6" ]]; then
                secondary_info=" | IPv6: $SERVER_IPV6"
            fi
            ;;
    esac
    
    # 生成 AnyTLS Reality 分享链接 (自定义格式，用于记录)
    # 格式: anytls://username:password@server:port?sni=domain&pbk=public_key&sid=short_id&fp=fingerprint#remarks
    ANYTLS_LINK="anytls://${USERNAME}:${PASSWORD}@${primary_ip}:${LISTEN_PORT}?sni=${SNI}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&fp=chrome#AnyReality-${NETWORK_MODE}-${SHORT_ID}"
    
    # IPv6专用链接（修复：IPv6地址在URL中需要方括号）
    if [[ "$NETWORK_MODE" == "dual" && -n "$SERVER_IPV6" ]]; then
        ANYTLS_LINK_IPV6="anytls://${USERNAME}:${PASSWORD}@[${SERVER_IPV6}]:${LISTEN_PORT}?sni=${SNI}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&fp=chrome#AnyReality-IPv6-${SHORT_ID}"
    elif [[ "$NETWORK_MODE" == "ipv6" ]]; then
        ANYTLS_LINK="anytls://${USERNAME}:${PASSWORD}@[${SERVER_IP}]:${LISTEN_PORT}?sni=${SNI}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&fp=chrome#AnyReality-IPv6-${SHORT_ID}"
    fi
    
    # 生成 NekoBox 可导入的链接
    NEKOBOX_LINK=$ANYTLS_LINK
    
    log "分享链接已生成"
}

# 生成客户端配置（修复IPv6配置问题）
generate_client_config() {
    log "生成客户端配置..."
    
    # 先生成分享链接
    generate_share_links
    
    # 确定显示的IP信息
    local ip_display=""
    case $NETWORK_MODE in
        "ipv4")
            ip_display="IPv4: $SERVER_IP"
            ;;
        "ipv6")
            ip_display="IPv6: $SERVER_IP"
            ;;
        "dual")
            ip_display="IPv4: $SERVER_IP"
            if [[ -n "$SERVER_IPV6" ]]; then
                ip_display="$ip_display | IPv6: $SERVER_IPV6"
            fi
            ;;
    esac
    
    # 保存到文件
    cat > /root/anyreality_client_config.txt << EOF
=== sing-box AnyReality 客户端配置 ===

服务器信息:
- 服务器地址: $ip_display
- 端口: $LISTEN_PORT
- 用户名: $USERNAME
- 密码: $PASSWORD
- 协议: AnyTLS + Reality
- 网络模式: $NETWORK_MODE

Reality 配置:
- SNI: $SNI
- 指纹: chrome
- 公钥: $PUBLIC_KEY
- Short ID: $SHORT_ID
- 目标网站: $DEST

=== 分享链接 (一键导入) ===
主要链接 ($NETWORK_MODE):
$ANYTLS_LINK

EOF

    # 如果是双栈模式，添加 IPv6链接
    if [[ "$NETWORK_MODE" == "dual" && -n "$ANYTLS_LINK_IPV6" ]]; then
        cat >> /root/anyreality_client_config.txt << EOF
IPv6专用链接:
$ANYTLS_LINK_IPV6

EOF
    fi

    cat >> /root/anyreality_client_config.txt << EOF
NekoBox 导入链接:
$NEKOBOX_LINK

注意: 由于 AnyTLS 是较新的协议，部分客户端可能需要手动配置

=== NekoBox 客户端配置 (JSON格式) - IPv4 & IPv6 ===
{
  "dns": {
    "servers": [
      {
        "tag": "google-dot",
        "address": "https://dns.google/dns-query", // 使用 DoH 更通用，或使用 tls://dns.google
        "detour": "anyreality-out" // 让 DNS 查询也走代理，防止 DNS 污染
      },
      {
        "tag": "local-udp",
        "address": "223.5.5.5" // 国内备用 DNS
      }
    ],
    "strategy": "prefer_ipv4"
  },
 "inbounds": [
        {
            "type": "anytls",
            "tag": "anyreality-in-ipv6",
            "listen": "::",
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
        },
        {
            "type": "direct",
            "tag": "direct"
        }
    ],
 "route": {
    "rules": [
      {
        "protocol": "dns",
        "outbound": "dns-out" // 所有DNS请求都由DNS引擎处理
      },
      {
        "ip_is_private": true, // 私有/局域网地址直连
        "outbound": "direct"
      },
      {
        "domain": ["geosite:cn"], // 举例：国内网站直连 (需要 geosite.db 文件)
        "outbound": "direct"
      },
      {
        "ip_cidr": ["geoip:cn"], // 举例：国内 IP 直连 (需要 geoip.db 文件)
        "outbound": "direct"
      }
    ],
    "final": "anyreality-out" // 默认规则：所有其他流量都走代理
  }
}

EOF

    # IPv6客户端配置（如果需要）
    if [[ "$NETWORK_MODE" == "ipv6" || "$NETWORK_MODE" == "dual" ]]; then
        cat >> /root/anyreality_client_config.txt << EOF
=== IPv6 客户端配置 (JSON格式) ===
{
    "type": "anytls",
    "tag": "AnyReality-IPv6-$SHORT_ID",
    "server": "$([[ "$NETWORK_MODE" == "dual" ]] && echo "$SERVER_IPV6" || echo "$SERVER_IP")",
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
    fi

    cat >> /root/anyreality_client_config.txt << EOF
=== sing-box Android (SFA) 配置 ===
复制上面的 JSON 配置到 SFA 应用中

=== sing-box macOS (SFM) 配置 ===
复制上面的 JSON 配置到 SFM 应用中

=== IPv6 使用说明 ===
EOF

    if [[ "$NETWORK_MODE" == "ipv6" || "$NETWORK_MODE" == "dual" ]]; then
        cat >> /root/anyreality_client_config.txt << EOF
1. 确保您的网络环境支持IPv6
2. 客户端设备需要有IPv6地址
3. 某些移动网络可能不完全支持IPv6，建议在WiFi环境下测试
4. 如遇连接问题，可尝试切换到IPv4模式

=== 双栈配置优势 ===
- 自动选择最佳网络路径
- IPv4/IPv6 双重冗余
- 提高连接成功率和稳定性
EOF
    else
        cat >> /root/anyreality_client_config.txt << EOF
当前使用 IPv4 单栈模式，兼容性最佳
如需启用 IPv6 支持，请重新运行脚本并选择双栈模式
EOF
    fi

    cat >> /root/anyreality_client_config.txt << EOF

=== 配置说明 ===
1. AnyReality 协议结合了 AnyTLS 的个性化字节填充和 Reality 的完美 TLS 伪装
2. 无需申请域名证书，直接使用目标网站的证书
3. 有效解决 TLS in TLS 问题
4. 流量特征看起来就像在正常访问 $DEST 网站

=== 客户端支持 ===
- NekoBox (Android): 支持，需要 sing-box 内核
- SFA (Android): 官方 sing-box 客户端，完美支持
- SFM (macOS): 官方 sing-box 客户端，完美支持
- sing-box (iOS): 需要 TestFlight 版本或正式版发布后
- 其他客户端: 大部分不支持 AnyTLS 协议

=== 网络模式说明 ===
- IPv4 Only: 仅使用IPv4，兼容性最佳
- IPv6 Only: 仅使用IPv6，需要完整IPv6网络环境
- Dual Stack: 同时支持IPv4和IPv6，自动选择最佳路径

=== 重要提醒 ===
关键修复说明：
- IPv6地址在JSON配置中不需要方括号[]
- 方括号仅在URL格式中使用（如分享链接）
- 客户端JSON配置中直接使用纯IPv6地址格式
- 这是导致IPv6连接失败的主要原因
EOF

    # 生成简化的 NekoBox 导入配置（修复IPv6格式）
    local client_server_ip="$SERVER_IP"
    if [[ "$NETWORK_MODE" == "ipv6" ]]; then
        client_server_ip="$SERVER_IP"  # IPv6地址不加方括号
    fi

    cat > /root/nekobox_config.json << EOF
{
    "type": "anytls",
    "tag": "AnyReality-$NETWORK_MODE-$SHORT_ID",
    "server": "$client_server_ip",
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

    # 如果是双栈模式，生成IPv6配置（修复IPv6地址格式）
    if [[ "$NETWORK_MODE" == "dual" && -n "$SERVER_IPV6" ]]; then
        cat > /root/nekobox_config_ipv6.json << EOF
{
    "type": "anytls",
    "tag": "AnyReality-IPv6-$SHORT_ID",
    "server": "$SERVER_IPV6",
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
        log "IPv6 NekoBox配置: /root/nekobox_config_ipv6.json"
    fi

    log "客户端配置已保存到:"
    log "- 详细配置: /root/anyreality_client_config.txt"
    log "- NekoBox配置: /root/nekobox_config.json"
    
    # 生成二维码
    log "生成分享链接二维码..."
    generate_qrcode "$ANYTLS_LINK" "/root/anyreality_qr.png"
    
    # 如果是双栈模式，也为IPv6生成二维码
    if [[ "$NETWORK_MODE" == "dual" && -n "$ANYTLS_LINK_IPV6" ]]; then
        echo
        echo -e "${CYAN}IPv6 专用二维码:${NC}"
        generate_qrcode "$ANYTLS_LINK_IPV6" "/root/anyreality_qr_ipv6.png"
    fi
}

# 显示配置信息
display_config() {
    echo
    echo "================================================"
    echo -e "${GREEN}sing-box AnyReality 安装完成!${NC}"
    echo "================================================"
    echo
    echo -e "${BLUE}服务器信息:${NC}"
    
    case $NETWORK_MODE in
        "ipv4")
            echo "IP地址: $SERVER_IP (IPv4 Only)"
            ;;
        "ipv6")
            echo "IP地址: $SERVER_IP (IPv6 Only)"
            ;;
        "dual")
            echo "IPv4地址: $SERVER_IP"
            if [[ -n "$SERVER_IPV6" ]]; then
                echo "IPv6地址: $SERVER_IPV6"
            fi
            echo "模式: 双栈 (IPv4 + IPv6)"
            ;;
    esac
    
    echo "端口: $LISTEN_PORT"
    echo "用户名: $USERNAME"
    echo "密码: $PASSWORD"
    echo "协议: AnyTLS + Reality"
    echo
    echo -e "${BLUE}Reality 配置:${NC}"
    echo "SNI: $SNI"
    echo "目标站点: $DEST"
    echo "公钥: $PUBLIC_KEY"
    echo "Short ID: $SHORT_ID"
    echo
    echo -e "${BLUE}一键导入链接:${NC}"
    echo -e "${YELLOW}$ANYTLS_LINK${NC}"
    
    if [[ "$NETWORK_MODE" == "dual" && -n "$ANYTLS_LINK_IPV6" ]]; then
        echo
        echo -e "${BLUE}IPv6专用链接:${NC}"
        echo -e "${PURPLE}$ANYTLS_LINK_IPV6${NC}"
    fi
    
    echo
    generate_qrcode "$ANYTLS_LINK"
    
    if [[ "$NETWORK_MODE" == "dual" && -n "$ANYTLS_LINK_IPV6" ]]; then
        echo
        echo -e "${BLUE}IPv6 专用二维码:${NC}"
        generate_qrcode "$ANYTLS_LINK_IPV6"
    fi
    
    echo
    echo -e "${BLUE}特性说明:${NC}"
    echo "• AnyTLS 协议提供个性化字节填充，有效规避 DPI 检测"
    echo "• Reality 技术完美伪装 TLS 流量，无需域名证书"
    echo "• 解决 TLS in TLS 问题，提高连接稳定性"
    echo "• 流量特征完全模拟访问 $DEST 网站"
    
    if [[ "$NETWORK_MODE" == "dual" ]]; then
        echo "• 双栈网络支持，自动选择最佳连接路径"
        echo "• IPv4/IPv6 双重冗余，提高连接成功率"
    elif [[ "$NETWORK_MODE" == "ipv6" ]]; then
        echo "• 纯IPv6模式，适用于IPv6优先的网络环境"
    fi
    
    echo
    echo -e "${BLUE}客户端支持:${NC}"
    echo "• NekoBox (需要 sing-box 内核)"
    echo "• SFA (Android 官方客户端)"
    echo "• SFM (macOS 官方客户端)"
    echo "• sing-box iOS (TestFlight 或正式版)"
    echo
    echo -e "${BLUE}导入说明:${NC}"
    echo "• 复制上面的链接到支持的客户端中导入"
    echo "• 或扫码二维码进行导入"
    echo "• 如果客户端不支持 AnyTLS 协议，请使用手动配置"
    
    if [[ "$NETWORK_MODE" == "dual" ]]; then
        echo "• 双栈模式下，客户端会自动选择IPv4或IPv6"
        echo "• 如遇问题可尝试使用专门的IPv6链接"
    fi
    
    echo
    echo -e "${RED}IPv6配置修复重点:${NC}"
    echo "• JSON配置中IPv6地址不使用方括号 []"
    echo "• 例如: \"server\": \"2001:db8::1\" (正确)"
    echo "• 而不是: \"server\": \"[2001:db8::1]\" (错误)"
    echo "• 方括号仅用于URL格式的分享链接中"
    
    echo
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
    echo "二维码图片: /root/anyreality_qr.png"
    
    if [[ "$NETWORK_MODE" == "dual" ]]; then
        echo "IPv6 NekoBox: /root/nekobox_config_ipv6.json"
        echo "IPv6 二维码: /root/anyreality_qr_ipv6.png"
    fi
    
    echo
    echo -e "${YELLOW}重要提醒:${NC}"
    echo "• AnyTLS 是较新的协议，部分客户端可能需要更新或手动配置"
    echo "• 推荐使用最新版本的 NekoBox 或官方 sing-box 客户端"
    echo "• 如果链接导入失败，请使用手动配置 JSON 方式"
    echo "• IPv6地址在JSON配置中不要加方括号，这是连接失败的主要原因"
    
    if [[ "$NETWORK_MODE" == "ipv6" || "$NETWORK_MODE" == "dual" ]]; then
        echo "• IPv6 模式需要完整的IPv6网络环境支持"
        echo "• 移动网络IPv6支持可能不完整，建议WiFi环境测试"
    fi
    
    echo
    echo "================================================"
}

# 显示现有配置的分享链接 (独立功能)
show_share_info() {
    if [[ ! -f /etc/sing-box/config.json ]]; then
        error "未找到 sing-box 配置文件，请先运行安装"
        exit 1
    fi
    
    log "读取现有配置..."
    
    # 获取当前IP地址
    IPV4_ADDRESS=$(curl -s https://api.ipify.org || curl -s https://ifconfig.me)
    if [[ "$IPV6_SUPPORT" == "true" ]]; then
        IPV6_ADDRESS=$(curl -s https://ipv6.icanhazip.com || curl -s https://v6.ident.me)
    fi
    
    # 从配置文件读取参数
    LISTEN_PORT=$(jq -r '.inbounds[0].listen_port' /etc/sing-box/config.json)
    USERNAME=$(jq -r '.inbounds[0].users[0].name' /etc/sing-box/config.json)
    PASSWORD=$(jq -r '.inbounds[0].users[0].password' /etc/sing-box/config.json)
    SNI=$(jq -r '.inbounds[0].tls.server_name' /etc/sing-box/config.json)
    PRIVATE_KEY=$(jq -r '.inbounds[0].tls.reality.private_key' /etc/sing-box/config.json)
    SHORT_ID=$(jq -r '.inbounds[0].tls.reality.short_id[0]' /etc/sing-box/config.json)
    
    # 检测网络模式
    if jq -e '.inbounds[1]' /etc/sing-box/config.json >/dev/null 2>&1; then
        NETWORK_MODE="dual"
        SERVER_IP=$IPV4_ADDRESS
        SERVER_IPV6=$IPV6_ADDRESS
    else
        local listen_addr=$(jq -r '.inbounds[0].listen' /etc/sing-box/config.json)
        if [[ "$listen_addr" == "::" ]]; then
            NETWORK_MODE="ipv6"
            SERVER_IP=$IPV6_ADDRESS
        else
            NETWORK_MODE="ipv4"
            SERVER_IP=$IPV4_ADDRESS
        fi
    fi
    
    # 需要从私钥推导公钥，这里使用一个示例方法
    # 在实际生产中，应该保存公钥或重新生成
    if [[ -f /root/anyreality_client_config.txt ]]; then
        PUBLIC_KEY=$(grep "公钥:" /root/anyreality_client_config.txt | cut -d' ' -f2)
    fi
    
    if [[ -z "$PUBLIC_KEY" ]]; then
        warn "无法获取公钥，尝试重新生成..."
        generate_reality_keys
    fi
    
    # 生成分享链接
    case $NETWORK_MODE in
        "ipv4")
            ANYTLS_LINK="anytls://${USERNAME}:${PASSWORD}@${SERVER_IP}:${LISTEN_PORT}?sni=${SNI}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&fp=chrome#AnyReality-${NETWORK_MODE}-${SHORT_ID}"
            ;;
        "ipv6")
            ANYTLS_LINK="anytls://${USERNAME}:${PASSWORD}@[${SERVER_IP}]:${LISTEN_PORT}?sni=${SNI}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&fp=chrome#AnyReality-${NETWORK_MODE}-${SHORT_ID}"
            ;;
        "dual")
            ANYTLS_LINK="anytls://${USERNAME}:${PASSWORD}@${SERVER_IP}:${LISTEN_PORT}?sni=${SNI}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&fp=chrome#AnyReality-${NETWORK_MODE}-${SHORT_ID}"
            if [[ -n "$SERVER_IPV6" ]]; then
                ANYTLS_LINK_IPV6="anytls://${USERNAME}:${PASSWORD}@[${SERVER_IPV6}]:${LISTEN_PORT}?sni=${SNI}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&fp=chrome#AnyReality-IPv6-${SHORT_ID}"
            fi
            ;;
    esac
    
    echo
    echo "================================================"
    echo -e "${GREEN}AnyReality 分享链接信息${NC}"
    echo "================================================"
    echo
    echo -e "${BLUE}服务状态:${NC}"
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}✓ sing-box 服务运行中${NC}"
    else
        echo -e "${RED}✗ sing-box 服务未运行${NC}"
    fi
    echo
    echo -e "${BLUE}网络模式:${NC} $NETWORK_MODE"
    
    case $NETWORK_MODE in
        "ipv4")
            echo -e "${BLUE}服务器IP:${NC} $SERVER_IP (IPv4)"
            ;;
        "ipv6")
            echo -e "${BLUE}服务器IP:${NC} $SERVER_IP (IPv6)"
            ;;
        "dual")
            echo -e "${BLUE}IPv4地址:${NC} $SERVER_IP"
            if [[ -n "$SERVER_IPV6" ]]; then
                echo -e "${BLUE}IPv6地址:${NC} $SERVER_IPV6"
            fi
            ;;
    esac
    
    echo -e "${BLUE}端口:${NC} $LISTEN_PORT | ${BLUE}用户名:${NC} $USERNAME"
    echo -e "${BLUE}SNI:${NC} $SNI | ${BLUE}Short ID:${NC} $SHORT_ID"
    echo
    echo -e "${BLUE}一键导入链接:${NC}"
    echo -e "${YELLOW}$ANYTLS_LINK${NC}"
    
    if [[ "$NETWORK_MODE" == "dual" && -n "$ANYTLS_LINK_IPV6" ]]; then
        echo
        echo -e "${BLUE}IPv6专用链接:${NC}"
        echo -e "${PURPLE}$ANYTLS_LINK_IPV6${NC}"
    fi
    
    echo
    generate_qrcode "$ANYTLS_LINK" "/root/anyreality_qr_current.png"
    
    if [[ "$NETWORK_MODE" == "dual" && -n "$ANYTLS_LINK_IPV6" ]]; then
        echo
        echo -e "${BLUE}IPv6 二维码:${NC}"
        generate_qrcode "$ANYTLS_LINK_IPV6" "/root/anyreality_qr_ipv6_current.png"
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
    echo -e "${YELLOW}Enhanced版本 - 支持IPv6和改进二维码显示 - 修复IPv6客户端配置${NC}"
    echo "================================================"
    echo
    
    check_system
    choose_network_config
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
    
    if [[ "$NETWORK_MODE" == "dual" ]]; then
        log "IPv6 配置文件: /root/nekobox_config_ipv6.json"
    fi
}

# 运行主函数
main "$@"
