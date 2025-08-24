#!/bin/bash

# sing-box AnyReality (AnyTLS + Reality) 自动安装配置脚本
# 修复了 sing-box 1.12.0+ 版本兼容性问题

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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
        apt install -y curl wget unzip jq openssl qrencode
    else
        yum update -y
        yum install -y curl wget unzip jq openssl qrencode
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
    
    # 随机短ID (16位十六进制，符合文章中的示例)
    SHORT_ID=$(openssl rand -hex 8)
    
    # Reality目标网站列表 (基于文章中提到的yahoo.com等)
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
}

# 获取服务器IP
get_server_ip() {
    SERVER_IP=$(curl -s https://api.ipify.org)
    if [[ -z "$SERVER_IP" ]]; then
        SERVER_IP=$(curl -s https://ifconfig.me)
    fi
    
    if [[ -z "$SERVER_IP" ]]; then
        error "无法获取服务器IP地址"
        exit 1
    fi
    
    log "服务器IP: $SERVER_IP"
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
        # 使用文章中的示例密钥对 (仅用于演示，生产环境请生成新的)
        warn "无法生成密钥对，使用示例密钥对..."
        PRIVATE_KEY="eO3B3EMGXrYfGOe87NkUVusaeUxtLB4vxiqjVXqb9GU"
        PUBLIC_KEY="u4v3a_-uhIXPE2RoGaNy9_W5EK5UYV_hVN4Vpei75lM"
    fi
    
    log "Reality密钥对已生成"
    log "私钥: $PRIVATE_KEY"
    log "公钥: $PUBLIC_KEY"
}

# 生成sing-box AnyReality配置文件 (修复版本兼容性)
generate_singbox_config() {
    log "生成 sing-box AnyReality 配置文件..."
    
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

# 生成分享链接
generate_share_links() {
    log "生成分享链接..."
    
    # 生成 AnyTLS Reality 分享链接 (自定义格式，用于记录)
    # 格式: anytls://username:password@server:port?sni=domain&pbk=public_key&sid=short_id&fp=fingerprint#remarks
    ANYTLS_LINK="anytls://${USERNAME}:${PASSWORD}@${SERVER_IP}:${LISTEN_PORT}?sni=${SNI}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&fp=chrome#AnyReality-${SHORT_ID}"
    
    # 生成 NekoBox 可导入的链接 (使用 Reality 格式，NekoBox 支持)
    # 虽然 NekoBox 可能不直接支持 anytls://，但可以手动配置
    NEKOBOX_LINK=$ANYTLS_LINK
    
    log "分享链接已生成"
}

# 生成客户端配置
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

Reality 配置:
- SNI: $SNI
- 指纹: chrome
- 公钥: $PUBLIC_KEY
- Short ID: $SHORT_ID
- 目标网站: $DEST

=== 分享链接 (一键导入) ===
AnyTLS Reality 链接:
$ANYTLS_LINK

NekoBox 导入链接:
$NEKOBOX_LINK

注意: 由于 AnyTLS 是较新的协议，部分客户端可能需要手动配置

=== NekoBox 客户端配置 (JSON格式) ===
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
        "strategy": "ipv4_only"
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

    log "客户端配置已保存到:"
    log "- 详细配置: /root/anyreality_client_config.txt"
    log "- NekoBox配置: /root/nekobox_config.json"
    
    # 生成二维码
    if command -v qrencode >/dev/null 2>&1; then
        log "生成分享链接二维码..."
        qrencode -t ANSI256 "$ANYTLS_LINK"
        echo
        
        # 保存二维码到文件
        qrencode -t PNG -o /root/anyreality_qr.png "$ANYTLS_LINK"
        log "二维码已保存到: /root/anyreality_qr.png"
    else
        warn "qrencode 未安装，跳过二维码生成"
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
    echo "IP 地址: $SERVER_IP"
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
    echo
    if command -v qrencode >/dev/null 2>&1; then
        echo -e "${BLUE}扫描二维码导入:${NC}"
        qrencode -t ANSI256 "$ANYTLS_LINK"
        echo
    fi
    echo -e "${BLUE}特性说明:${NC}"
    echo "• AnyTLS 协议提供个性化字节填充，有效规避 DPI 检测"
    echo "• Reality 技术完美伪装 TLS 流量，无需域名证书"
    echo "• 解决 TLS in TLS 问题，提高连接稳定性"
    echo "• 流量特征完全模拟访问 $DEST 网站"
    echo
    echo -e "${BLUE}客户端支持:${NC}"
    echo "• NekoBox (需要 sing-box 内核)"
    echo "• SFA (Android 官方客户端)"
    echo "• SFM (macOS 官方客户端)"
    echo "• sing-box iOS (TestFlight 或正式版)"
    echo
    echo -e "${BLUE}导入说明:${NC}"
    echo "• 复制上面的链接到支持的客户端中导入"
    echo "• 或扫描二维码进行导入"
    echo "• 如果客户端不支持 AnyTLS 协议，请使用手动配置"
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
    echo
    echo -e "${YELLOW}重要提醒:${NC}"
    echo "• AnyTLS 是较新的协议，部分客户端可能需要更新或手动配置"
    echo "• 推荐使用最新版本的 NekoBox 或官方 sing-box 客户端"
    echo "• 如果链接导入失败，请使用手动配置 JSON 方式"
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
    
    # 从配置文件读取参数
    SERVER_IP=$(curl -s https://api.ipify.org || curl -s https://ifconfig.me)
    LISTEN_PORT=$(jq -r '.inbounds[0].listen_port' /etc/sing-box/config.json)
    USERNAME=$(jq -r '.inbounds[0].users[0].name' /etc/sing-box/config.json)
    PASSWORD=$(jq -r '.inbounds[0].users[0].password' /etc/sing-box/config.json)
    SNI=$(jq -r '.inbounds[0].tls.server_name' /etc/sing-box/config.json)
    PRIVATE_KEY=$(jq -r '.inbounds[0].tls.reality.private_key' /etc/sing-box/config.json)
    SHORT_ID=$(jq -r '.inbounds[0].tls.reality.short_id[0]' /etc/sing-box/config.json)
    
    # 需要从私钥推导公钥，这里使用一个示例方法
    # 在实际生产中，应该保存公钥或重新生成
    if [[ -f /root/anyreality_client_config.txt ]]; then
        PUBLIC_KEY=$(grep "公钥:" /root/anyreality_client_config.txt | cut -d' ' -f2)
    fi
    
    if [[ -z "$PUBLIC_KEY" ]]; then
        warn "无法获取公钥，使用配置中的私钥信息"
        PUBLIC_KEY="<需要从私钥推导>"
    fi
    
    # 生成分享链接
    ANYTLS_LINK="anytls://${USERNAME}:${PASSWORD}@${SERVER_IP}:${LISTEN_PORT}?sni=${SNI}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&fp=chrome#AnyReality-${SHORT_ID}"
    
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
    echo -e "${BLUE}一键导入链接:${NC}"
    echo -e "${YELLOW}$ANYTLS_LINK${NC}"
    echo
    
    if command -v qrencode >/dev/null 2>&1; then
        echo -e "${BLUE}扫描二维码导入:${NC}"
        qrencode -t ANSI256 "$ANYTLS_LINK"
        echo
        
        # 保存二维码
        qrencode -t PNG -o /root/anyreality_qr_current.png "$ANYTLS_LINK"
        log "二维码已更新: /root/anyreality_qr_current.png"
    fi
    
    echo -e "${BLUE}服务器信息:${NC}"
    echo "IP: $SERVER_IP | 端口: $LISTEN_PORT"
    echo "用户名: $USERNAME"
    echo "SNI: $SNI | Short ID: $SHORT_ID"
    echo
    echo -e "${BLUE}管理命令:${NC}"
    echo "查看状态: systemctl status sing-box"
    echo "重启服务: systemctl restart sing-box"
    echo "查看日志: journalctl -u sing-box -f"
    echo
    echo "================================================"
}
main() {
    clear
    echo -e "${BLUE}sing-box AnyReality (AnyTLS + Reality) 自动安装脚本${NC}"
    echo -e "${YELLOW}修复版本 - 兼容 sing-box 1.12.0+${NC}"
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
}

# 运行主函数
main "$@"
