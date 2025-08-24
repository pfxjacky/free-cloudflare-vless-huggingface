#!/bin/bash

# sing-box AnyReality 故障诊断和修复脚本
# 用于诊断和修复 AnyReality 配置问题

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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

# 诊断 sing-box 问题
diagnose_singbox() {
    echo "================================================"
    echo -e "${BLUE}sing-box 故障诊断${NC}"
    echo "================================================"
    
    # 1. 检查二进制文件
    log "检查 sing-box 二进制文件..."
    if [[ ! -f /usr/local/bin/sing-box ]]; then
        error "sing-box 二进制文件不存在"
        return 1
    fi
    
    if [[ ! -x /usr/local/bin/sing-box ]]; then
        warn "sing-box 文件没有执行权限，正在修复..."
        chmod +x /usr/local/bin/sing-box
    fi
    
    # 2. 检查版本和依赖
    log "检查 sing-box 版本..."
    if /usr/local/bin/sing-box version 2>/dev/null; then
        VERSION_INFO=$(/usr/local/bin/sing-box version)
        log "当前版本: $VERSION_INFO"
    else
        error "sing-box 二进制文件损坏或不兼容"
        return 1
    fi
    
    # 3. 检查配置文件
    log "检查配置文件..."
    if [[ ! -f /etc/sing-box/config.json ]]; then
        error "配置文件 /etc/sing-box/config.json 不存在"
        return 1
    fi
    
    # 4. 验证配置文件语法
    log "验证配置文件语法..."
    if ! /usr/local/bin/sing-box check -c /etc/sing-box/config.json; then
        error "配置文件语法错误"
        echo "配置文件内容："
        cat /etc/sing-box/config.json
        return 1
    fi
    
    # 5. 检查详细启动日志
    log "检查详细启动错误..."
    echo "=== 尝试手动启动并查看错误 ==="
    timeout 10s /usr/local/bin/sing-box run -c /etc/sing-box/config.json || {
        error "手动启动失败，可能是配置问题"
    }
    
    # 6. 检查系统日志
    log "检查系统日志..."
    echo "=== 最近的 systemd 日志 ==="
    journalctl -u sing-box -n 20 --no-pager
    
    # 7. 检查端口占用
    log "检查端口占用..."
    if [[ -f /etc/sing-box/config.json ]]; then
        LISTEN_PORT=$(jq -r '.inbounds[0].listen_port' /etc/sing-box/config.json 2>/dev/null || echo "")
        if [[ -n "$LISTEN_PORT" ]]; then
            if ss -tuln | grep ":$LISTEN_PORT " >/dev/null; then
                warn "端口 $LISTEN_PORT 被占用"
                ss -tulpn | grep ":$LISTEN_PORT "
            else
                log "端口 $LISTEN_PORT 未被占用"
            fi
        fi
    fi
    
    return 0
}

# 修复常见问题
fix_common_issues() {
    log "尝试修复常见问题..."
    
    # 1. 停止可能冲突的服务
    systemctl stop sing-box 2>/dev/null || true
    sleep 3
    
    # 2. 确保目录权限正确
    mkdir -p /var/log/sing-box
    chmod 755 /var/log/sing-box
    chown root:root /var/log/sing-box
    
    # 3. 确保配置目录权限正确
    chmod 755 /etc/sing-box
    chmod 644 /etc/sing-box/config.json
    chown -R root:root /etc/sing-box
    
    # 4. 重新生成 Reality 密钥对
    log "重新生成 Reality 密钥对..."
    generate_new_reality_keys
    
    # 5. 使用简化的配置重新生成
    log "生成新的简化配置..."
    generate_simple_config
    
    # 6. 重新创建 systemd 服务
    log "重新创建 systemd 服务..."
    create_fixed_systemd_service
    
    log "修复完成，尝试重新启动服务..."
}

# 生成新的 Reality 密钥对
generate_new_reality_keys() {
    log "生成新的 Reality 密钥对..."
    
    # 使用 sing-box 生成密钥对
    if command -v sing-box >/dev/null 2>&1; then
        REALITY_OUTPUT=$(sing-box generate reality-keypair 2>/dev/null || echo "")
        PRIVATE_KEY=$(echo "$REALITY_OUTPUT" | grep -oP 'PrivateKey: \K.*' || echo "")
        PUBLIC_KEY=$(echo "$REALITY_OUTPUT" | grep -oP 'PublicKey: \K.*' || echo "")
    fi
    
    # 如果生成失败，使用示例密钥对
    if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
        warn "无法生成密钥对，使用示例密钥对..."
        PRIVATE_KEY="eO3B3EMGXrYfGOe87NkUVusaeUxtLB4vxiqjVXqb9GU"
        PUBLIC_KEY="u4v3a_-uhIXPE2RoGaNy9_W5EK5UYV_hVN4Vpei75lM"
    fi
    
    log "私钥: $PRIVATE_KEY"
    log "公钥: $PUBLIC_KEY"
}

# 生成简化配置
generate_simple_config() {
    log "生成简化的 AnyReality 配置..."
    
    # 获取或生成基本参数
    if [[ -f /etc/sing-box/config.json ]]; then
        # 尝试从现有配置读取
        LISTEN_PORT=$(jq -r '.inbounds[0].listen_port' /etc/sing-box/config.json 2>/dev/null || echo "443")
        USERNAME=$(jq -r '.inbounds[0].users[0].name' /etc/sing-box/config.json 2>/dev/null || echo "")
        PASSWORD=$(jq -r '.inbounds[0].users[0].password' /etc/sing-box/config.json 2>/dev/null || echo "")
        SNI=$(jq -r '.inbounds[0].tls.server_name' /etc/sing-box/config.json 2>/dev/null || echo "")
        SHORT_ID=$(jq -r '.inbounds[0].tls.reality.short_id[0]' /etc/sing-box/config.json 2>/dev/null || echo "")
    fi
    
    # 如果参数为空或无效，生成新的
    if [[ -z "$LISTEN_PORT" || "$LISTEN_PORT" == "null" ]]; then
        LISTEN_PORT="443"
    fi
    if [[ -z "$USERNAME" || "$USERNAME" == "null" ]]; then
        USERNAME="user_$(openssl rand -hex 4)"
    fi
    if [[ -z "$PASSWORD" || "$PASSWORD" == "null" ]]; then
        PASSWORD=$(openssl rand -base64 16)
    fi
    if [[ -z "$SNI" || "$SNI" == "null" ]]; then
        SNI="yahoo.com"
    fi
    if [[ -z "$SHORT_ID" || "$SHORT_ID" == "null" ]]; then
        SHORT_ID=$(openssl rand -hex 8)
    fi
    
    DEST="yahoo.com"
    
    log "使用配置参数："
    log "端口: $LISTEN_PORT"
    log "用户名: $USERNAME"
    log "密码: $PASSWORD"
    log "SNI: $SNI"
    log "Short ID: $SHORT_ID"
    log "目标站点: $DEST"
    
    # 备份旧配置
    if [[ -f /etc/sing-box/config.json ]]; then
        cp /etc/sing-box/config.json /etc/sing-box/config.json.backup.$(date +%Y%m%d_%H%M%S)
    fi
    
    # 生成简化配置 (使用标准的 vless + reality 配置，因为 anytls 可能有兼容性问题)
    cat > /etc/sing-box/config.json << EOF
{
    "log": {
        "level": "info",
        "output": "/var/log/sing-box/sing-box.log",
        "timestamp": true
    },
    "inbounds": [
        {
            "type": "vless",
            "tag": "vless-in",
            "listen": "0.0.0.0",
            "listen_port": $LISTEN_PORT,
            "users": [
                {
                    "uuid": "$(uuidgen)",
                    "name": "$USERNAME",
                    "flow": ""
                }
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
            }
        ],
        "final": "direct",
        "auto_detect_interface": true
    }
}
EOF

    log "简化配置已生成"
    
    # 验证新配置
    if ! /usr/local/bin/sing-box check -c /etc/sing-box/config.json; then
        error "新配置验证失败，尝试生成更基础的配置..."
        generate_basic_config
    else
        log "新配置验证成功"
        # 保存配置信息到文件
        save_config_info
    fi
}

# 生成基础配置 (如果 VLESS + Reality 也失败)
generate_basic_config() {
    log "生成最基础的配置..."
    
    cat > /etc/sing-box/config.json << EOF
{
    "log": {
        "level": "info",
        "timestamp": true
    },
    "inbounds": [
        {
            "type": "shadowsocks",
            "tag": "ss-in",
            "listen": "0.0.0.0",
            "listen_port": $LISTEN_PORT,
            "method": "chacha20-ietf-poly1305",
            "password": "$PASSWORD"
        }
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        }
    ],
    "route": {
        "final": "direct"
    }
}
EOF

    warn "使用基础 Shadowsocks 配置作为备用方案"
    
    if ! /usr/local/bin/sing-box check -c /etc/sing-box/config.json; then
        error "基础配置也验证失败，可能是 sing-box 版本问题"
        return 1
    fi
}

# 保存配置信息
save_config_info() {
    # 获取服务器 IP
    IPV4_ADDRESS=$(curl -s https://api.ipify.org || curl -s https://ifconfig.me || echo "YOUR_SERVER_IP")
    
    # 从配置中读取 UUID (对于 VLESS)
    UUID=$(jq -r '.inbounds[0].users[0].uuid' /etc/sing-box/config.json 2>/dev/null || echo "")
    
    cat > /root/vless_reality_config.txt << EOF
=== sing-box VLESS + Reality 配置信息 ===

服务器信息:
- 服务器地址: $IPV4_ADDRESS
- 端口: $LISTEN_PORT
- 用户名: $USERNAME
- UUID: $UUID
- 协议: VLESS + Reality

Reality 配置:
- SNI: $SNI
- 指纹: chrome
- 公钥: $PUBLIC_KEY
- Short ID: $SHORT_ID
- 目标网站: $DEST

=== VLESS Reality 分享链接 ===
vless://$UUID@$IPV4_ADDRESS:$LISTEN_PORT?encryption=none&flow&security=reality&sni=$SNI&fp=chrome&pbk=$PUBLIC_KEY&sid=$SHORT_ID&type=tcp&headerType=none#VlessReality-$SHORT_ID

=== 客户端支持 ===
- v2rayN (Windows)
- v2rayNG (Android) 
- Shadowrocket (iOS)
- Clash Meta
- NekoBox
- sing-box 官方客户端

注意: 如果原来是 AnyTLS 配置失败，现已切换到更稳定的 VLESS + Reality 配置
EOF

    log "配置信息已保存到: /root/vless_reality_config.txt"
}

# 创建修复的 systemd 服务
create_fixed_systemd_service() {
    log "创建修复的 systemd 服务..."
    
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity
StandardOutput=journal
StandardError=journal
KillMode=mixed
KillSignal=SIGINT
TimeoutStopSec=10s

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable sing-box
    
    log "systemd 服务已重新创建"
}

# 重新安装 sing-box (如果版本有问题)
reinstall_singbox() {
    log "重新安装 sing-box..."
    
    # 停止服务
    systemctl stop sing-box 2>/dev/null || true
    
    # 删除旧的二进制文件
    rm -f /usr/local/bin/sing-box
    
    # 检测架构
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH_NAME="amd64" ;;
        aarch64|arm64) ARCH_NAME="arm64" ;;
        armv7l) ARCH_NAME="armv7" ;;
        *) error "不支持的架构: $ARCH"; exit 1 ;;
    esac
    
    # 下载最新稳定版本
    log "下载 sing-box 最新稳定版本..."
    cd /tmp
    rm -rf sing-box*
    
    # 尝试下载最新 release
    LATEST_VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name' | sed 's/v//')
    
    if [[ -n "$LATEST_VERSION" && "$LATEST_VERSION" != "null" ]]; then
        log "下载版本: v${LATEST_VERSION}"
        DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/v${LATEST_VERSION}/sing-box-${LATEST_VERSION}-linux-${ARCH_NAME}.tar.gz"
        
        if wget -O sing-box.tar.gz "$DOWNLOAD_URL" 2>/dev/null; then
            log "下载成功"
        else
            error "下载失败"
            return 1
        fi
    else
        error "无法获取版本信息"
        return 1
    fi
    
    tar -xzf sing-box.tar.gz
    SING_BOX_PATH=$(find /tmp -name "sing-box" -type f -executable | head -1)
    
    if [[ -z "$SING_BOX_PATH" ]]; then
        error "无法找到 sing-box 二进制文件"
        return 1
    fi
    
    cp "$SING_BOX_PATH" /usr/local/bin/
    chmod +x /usr/local/bin/sing-box
    
    # 验证安装
    if /usr/local/bin/sing-box version >/dev/null 2>&1; then
        VERSION_INFO=$(/usr/local/bin/sing-box version)
        log "sing-box 重新安装成功: $VERSION_INFO"
    else
        error "重新安装失败"
        return 1
    fi
    
    # 清理临时文件
    cd /
    rm -rf /tmp/sing-box*
    
    return 0
}

# 测试服务启动
test_service() {
    log "测试服务启动..."
    
    # 启动服务
    systemctl start sing-box
    
    # 等待启动
    sleep 5
    
    # 检查状态
    if systemctl is-active --quiet sing-box; then
        log "✓ 服务启动成功"
        
        # 检查端口监听
        LISTEN_PORT=$(jq -r '.inbounds[0].listen_port' /etc/sing-box/config.json 2>/dev/null || echo "")
        if [[ -n "$LISTEN_PORT" ]]; then
            if ss -tuln | grep ":$LISTEN_PORT " >/dev/null; then
                log "✓ 端口 $LISTEN_PORT 正在监听"
            else
                warn "端口 $LISTEN_PORT 未在监听"
            fi
        fi
        
        return 0
    else
        error "✗ 服务启动失败"
        echo "=== 最新错误日志 ==="
        journalctl -u sing-box -n 10 --no-pager
        return 1
    fi
}

# 显示修复结果
show_result() {
    echo
    echo "================================================"
    echo -e "${GREEN}sing-box 修复完成${NC}"
    echo "================================================"
    
    if systemctl is-active --quiet sing-box; then
        echo -e "${GREEN}✓ 服务状态: 运行中${NC}"
        
        # 显示配置信息
        if [[ -f /root/vless_reality_config.txt ]]; then
            echo
            echo -e "${BLUE}配置信息已保存到:${NC} /root/vless_reality_config.txt"
            echo
            echo -e "${BLUE}分享链接:${NC}"
            grep "vless://" /root/vless_reality_config.txt || echo "请查看配置文件获取完整信息"
            
            # 生成二维码
            if command -v qrencode >/dev/null 2>&1; then
                SHARE_LINK=$(grep "vless://" /root/vless_reality_config.txt)
                if [[ -n "$SHARE_LINK" ]]; then
                    echo
                    echo -e "${CYAN}二维码:${NC}"
                    qrencode -t UTF8 "$SHARE_LINK" 2>/dev/null || qrencode -t ASCII "$SHARE_LINK"
                fi
            fi
        fi
    else
        echo -e "${RED}✗ 服务状态: 未运行${NC}"
    fi
    
    echo
    echo -e "${BLUE}管理命令:${NC}"
    echo "查看状态: systemctl status sing-box"
    echo "重启服务: systemctl restart sing-box"
    echo "查看日志: journalctl -u sing-box -f"
    echo "查看配置: cat /etc/sing-box/config.json"
    echo
}

# 主修复流程
main() {
    echo "================================================"
    echo -e "${BLUE}sing-box AnyReality 故障诊断和修复${NC}"
    echo "================================================"
    echo
    
    # 检查是否为 root
    if [[ $EUID -ne 0 ]]; then
        error "请使用 root 权限运行此脚本"
        exit 1
    fi
    
    echo "选择操作:"
    echo "1) 诊断问题 (仅查看问题，不修改配置)"
    echo "2) 修复配置 (尝试修复现有配置)"
    echo "3) 重新安装 (重新下载 sing-box 并生成新配置)"
    echo "4) 一键修复 (自动诊断并修复)"
    echo
    read -p "请输入选项 [1-4]: " choice
    
    case $choice in
        1)
            log "开始诊断..."
            diagnose_singbox
            ;;
        2)
            log "开始修复配置..."
            diagnose_singbox
            fix_common_issues
            test_service
            show_result
            ;;
        3)
            log "开始重新安装..."
            reinstall_singbox
            fix_common_issues  
            test_service
            show_result
            ;;
        4)
            log "开始一键修复..."
            diagnose_singbox
            
            # 如果诊断失败，尝试重新安装
            if ! diagnose_singbox >/dev/null 2>&1; then
                warn "检测到严重问题，将重新安装 sing-box..."
                reinstall_singbox
            fi
            
            fix_common_issues
            test_service
            show_result
            ;;
        *)
            error "无效选项"
            exit 1
            ;;
    esac
    
    echo
    log "修复脚本执行完成"
}

# 运行主函数
main "$@"
