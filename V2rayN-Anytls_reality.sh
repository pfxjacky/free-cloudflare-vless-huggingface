#!/bin/bash

# Any-Reality独立安装脚本
# 基于Sing-box 1.12.6+ 支持AnyTLS协议
# 兼容v2rayN 7.14.4预览版客户端
# 支持Debian、CentOS、Ubuntu系统

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# 默认配置
REALITY_DOMAIN="www.amd.com"
UUID=""
PORT=""
NODE_NAME=""
WORK_DIR="$HOME/any-reality"
CONFIG_FILE="$WORK_DIR/config.json"

# 错误处理函数
handle_error() {
    local exit_code=$?
    local line_number=$1
    echo -e "${RED}错误: 脚本在第 $line_number 行执行失败 (退出码: $exit_code)${NC}"
    echo -e "${YELLOW}正在清理临时文件...${NC}"
    rm -f /tmp/any-reality.service
    echo -e "${YELLOW}如需重新安装，请重新运行脚本${NC}"
    exit $exit_code
}

# 设置错误陷阱
trap 'handle_error ${LINENO}' ERR

# 显示横幅
show_banner() {
    echo -e "${PURPLE}================================================================${NC}"
    echo -e "${PURPLE}            Any-Reality 独立安装脚本 v1.1${NC}"
    echo -e "${PURPLE}          基于 Sing-box 1.12.6+ AnyTLS协议${NC}"
    echo -e "${PURPLE}        兼容 v2rayN 7.14.4 预览版客户端${NC}"
    echo -e "${PURPLE}================================================================${NC}"
    echo ""
}

# 检测系统信息
detect_system() {
    echo -e "${BLUE}正在检测系统信息...${NC}"
    
    # 检测架构
    case $(uname -m) in
        aarch64) ARCH="arm64";;
        x86_64) ARCH="amd64";;
        armv7l) ARCH="armv7";;
        *) 
            echo -e "${RED}错误: 不支持的系统架构 $(uname -m)${NC}"
            exit 1
        ;;
    esac
    
    # 检测操作系统
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=${VERSION_ID:-"unknown"}
        OS_NAME=$PRETTY_NAME
    elif [ -f /etc/redhat-release ]; then
        OS="centos"
        OS_NAME=$(cat /etc/redhat-release)
        VERSION="unknown"
    else
        echo -e "${RED}错误: 无法检测操作系统${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}系统信息检测完成:${NC}"
    echo -e "  操作系统: ${CYAN}$OS_NAME${NC}"
    echo -e "  系统版本: ${CYAN}$VERSION${NC}"
    echo -e "  系统架构: ${CYAN}$ARCH${NC}"
    echo ""
}

# 检查网络连接
check_network() {
    echo -e "${BLUE}正在检查网络连接...${NC}"
    
    local test_urls=("www.google.com" "github.com" "api.github.com")
    local network_ok=false
    
    for url in "${test_urls[@]}"; do
        if curl -s --max-time 10 --head "$url" >/dev/null 2>&1; then
            echo -e "${GREEN}网络连接正常 (测试地址: $url)${NC}"
            network_ok=true
            break
        fi
    done
    
    if [ "$network_ok" = false ]; then
        echo -e "${RED}错误: 网络连接失败，请检查网络设置${NC}"
        echo -e "${YELLOW}提示: 确保服务器可以访问Github和相关下载源${NC}"
        exit 1
    fi
}

# 安装依赖
install_dependencies() {
    echo -e "${BLUE}正在安装系统依赖...${NC}"
    
    case $OS in
        ubuntu|debian)
            echo -e "${BLUE}更新软件包列表...${NC}"
            if ! apt-get update -qq; then
                echo -e "${RED}错误: 更新软件包列表失败${NC}"
                echo -e "${YELLOW}尝试修复...${NC}"
                apt-get update 2>&1 | tee /tmp/apt_update.log
                if [ ${PIPESTATUS[0]} -ne 0 ]; then
                    echo -e "${RED}APT更新失败，详细错误信息:${NC}"
                    cat /tmp/apt_update.log
                    exit 1
                fi
            fi
            
            echo -e "${BLUE}安装必要软件包...${NC}"
            local packages="curl wget tar gzip uuid-runtime systemctl"
            for package in $packages; do
                echo -e "${BLUE}正在安装: $package${NC}"
                if ! apt-get install -y "$package" >/dev/null 2>&1; then
                    echo -e "${YELLOW}警告: $package 安装失败，尝试单独安装...${NC}"
                    apt-get install -y "$package" 2>&1 | tee "/tmp/${package}_install.log"
                    if [ ${PIPESTATUS[0]} -ne 0 ]; then
                        echo -e "${YELLOW}$package 安装失败，但可能不影响主要功能${NC}"
                    fi
                fi
            done
            ;;
        centos|rhel|fedora|rocky|almalinux)
            if command -v dnf >/dev/null 2>&1; then
                echo -e "${BLUE}使用DNF安装依赖...${NC}"
                if ! dnf install -y curl wget tar gzip util-linux systemd; then
                    echo -e "${RED}DNF安装失败${NC}"
                    exit 1
                fi
            else
                echo -e "${BLUE}使用YUM安装依赖...${NC}"
                if ! yum install -y curl wget tar gzip util-linux systemd; then
                    echo -e "${RED}YUM安装失败${NC}"
                    exit 1
                fi
            fi
            ;;
        *)
            echo -e "${YELLOW}警告: 未知系统 ($OS)，尝试通用安装方式${NC}"
            ;;
    esac
    
    # 验证关键命令是否可用
    local required_commands="curl wget tar"
    for cmd in $required_commands; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo -e "${RED}错误: 必需命令 '$cmd' 不可用${NC}"
            exit 1
        fi
    done
    
    echo -e "${GREEN}系统依赖安装完成${NC}"
}

# 生成UUID
generate_uuid() {
    echo -e "${BLUE}正在生成UUID...${NC}"
    
    if [ -z "$UUID" ]; then
        if command -v uuidgen >/dev/null 2>&1; then
            UUID=$(uuidgen)
        elif [ -f /proc/sys/kernel/random/uuid ]; then
            UUID=$(cat /proc/sys/kernel/random/uuid)
        else
            # 备用方案：使用时间戳和随机数生成UUID格式
            UUID=$(printf "%08x-%04x-%04x-%04x-%012x" \
                $((RANDOM * RANDOM)) \
                $((RANDOM % 65536)) \
                $(((RANDOM % 4096) | 16384)) \
                $(((RANDOM % 16384) | 32768)) \
                $(date +%s)$((RANDOM % 1000000)))
        fi
        echo "$UUID" > "$WORK_DIR/uuid"
        echo -e "${GREEN}生成UUID: ${CYAN}$UUID${NC}"
    else
        echo "$UUID" > "$WORK_DIR/uuid"
        echo -e "${GREEN}使用指定UUID: ${CYAN}$UUID${NC}"
    fi
}

# 生成端口
generate_port() {
    echo -e "${BLUE}正在生成端口...${NC}"
    
    if [ -z "$PORT" ]; then
        # 生成10000-65535之间的随机端口
        if command -v shuf >/dev/null 2>&1; then
            PORT=$(shuf -i 10000-65535 -n 1)
        else
            PORT=$((RANDOM % 55536 + 10000))
        fi
        echo "$PORT" > "$WORK_DIR/port"
        echo -e "${GREEN}生成端口: ${CYAN}$PORT${NC}"
    else
        echo "$PORT" > "$WORK_DIR/port"
        echo -e "${GREEN}使用指定端口: ${CYAN}$PORT${NC}"
    fi
}

# 下载Sing-box
download_singbox() {
    echo -e "${BLUE}正在下载Sing-box最新版本...${NC}"
    
    # 获取最新版本号
    echo -e "${BLUE}正在获取最新版本信息...${NC}"
    local latest_version
    latest_version=$(curl -s --max-time 30 "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | sed 's/v//')
    
    if [ -z "$latest_version" ]; then
        echo -e "${YELLOW}警告: 无法获取最新版本，使用备用版本 1.12.6${NC}"
        latest_version="1.12.6"
    fi
    
    echo -e "${GREEN}目标版本: ${CYAN}v$latest_version${NC}"
    
    # 构建下载URL
    local download_url="https://github.com/SagerNet/sing-box/releases/download/v$latest_version/sing-box-$latest_version-linux-$ARCH.tar.gz"
    
    # 下载文件
    echo -e "${BLUE}正在下载: sing-box-$latest_version-linux-$ARCH.tar.gz${NC}"
    echo -e "${BLUE}下载地址: $download_url${NC}"
    
    if curl -L --progress-bar --max-time 300 -o "$WORK_DIR/sing-box.tar.gz" "$download_url"; then
        echo -e "${GREEN}下载完成${NC}"
    else
        echo -e "${RED}下载失败，尝试备用下载方式...${NC}"
        if wget --timeout=300 -O "$WORK_DIR/sing-box.tar.gz" "$download_url"; then
            echo -e "${GREEN}备用下载完成${NC}"
        else
            echo -e "${RED}所有下载方式都失败，请检查网络连接${NC}"
            exit 1
        fi
    fi
    
    # 验证下载文件
    if [ ! -f "$WORK_DIR/sing-box.tar.gz" ]; then
        echo -e "${RED}下载文件不存在${NC}"
        exit 1
    fi
    
    local file_size=$(ls -lh "$WORK_DIR/sing-box.tar.gz" | awk '{print $5}')
    echo -e "${GREEN}下载文件大小: ${CYAN}$file_size${NC}"
    
    # 解压文件
    echo -e "${BLUE}正在解压...${NC}"
    cd "$WORK_DIR"
    
    if tar -xzf sing-box.tar.gz; then
        echo -e "${GREEN}解压完成${NC}"
    else
        echo -e "${RED}解压失败${NC}"
        exit 1
    fi
    
    # 移动可执行文件
    local extracted_dir="sing-box-$latest_version-linux-$ARCH"
    if [ -d "$extracted_dir" ] && [ -f "$extracted_dir/sing-box" ]; then
        mv "$extracted_dir/sing-box" ./
        chmod +x sing-box
        rm -rf sing-box.tar.gz "$extracted_dir"
        echo -e "${GREEN}文件移动完成${NC}"
    else
        echo -e "${RED}解压文件结构异常${NC}"
        ls -la
        exit 1
    fi
    
    # 验证安装
    if [ -x "$WORK_DIR/sing-box" ]; then
        local version_info=$("$WORK_DIR/sing-box" version 2>/dev/null | head -1 || echo "版本信息获取失败")
        echo -e "${GREEN}Sing-box 安装成功: ${CYAN}$version_info${NC}"
    else
        echo -e "${RED}Sing-box 安装失败${NC}"
        exit 1
    fi
}

# 生成Reality密钥对
generate_reality_keys() {
    echo -e "${BLUE}正在生成Reality密钥对...${NC}"
    
    # 生成密钥对
    local keypair_output
    keypair_output=$("$WORK_DIR/sing-box" generate reality-keypair 2>/dev/null)
    
    if [ $? -eq 0 ] && [ -n "$keypair_output" ]; then
        PRIVATE_KEY=$(echo "$keypair_output" | grep "PrivateKey" | awk '{print $2}' | tr -d '"')
        PUBLIC_KEY=$(echo "$keypair_output" | grep "PublicKey" | awk '{print $2}' | tr -d '"')
        echo -e "${GREEN}Reality密钥对生成成功${NC}"
    else
        echo -e "${RED}Reality密钥对生成失败${NC}"
        exit 1
    fi
    
    # 生成短ID
    SHORT_ID=$("$WORK_DIR/sing-box" generate rand --hex 4 2>/dev/null)
    if [ -z "$SHORT_ID" ]; then
        # 备用方案：手动生成8位随机16进制
        if command -v openssl >/dev/null 2>&1; then
            SHORT_ID=$(openssl rand -hex 4 2>/dev/null)
        else
            SHORT_ID=$(printf "%08x" $((RANDOM * RANDOM)))
        fi
    fi
    
    # 验证生成的密钥
    if [ -z "$PRIVATE_KEY" ] || [ -z "$PUBLIC_KEY" ] || [ -z "$SHORT_ID" ]; then
        echo -e "${RED}密钥信息生成不完整${NC}"
        echo -e "私钥: $PRIVATE_KEY"
        echo -e "公钥: $PUBLIC_KEY"
        echo -e "短ID: $SHORT_ID"
        exit 1
    fi
    
    # 保存密钥信息
    echo "$PRIVATE_KEY" > "$WORK_DIR/private_key"
    echo "$PUBLIC_KEY" > "$WORK_DIR/public_key"
    echo "$SHORT_ID" > "$WORK_DIR/short_id"
    echo "$REALITY_DOMAIN" > "$WORK_DIR/reality_domain"
    
    echo -e "${GREEN}Reality密钥信息:${NC}"
    echo -e "  私钥: ${CYAN}${PRIVATE_KEY:0:16}...${NC}"
    echo -e "  公钥: ${CYAN}${PUBLIC_KEY:0:16}...${NC}"
    echo -e "  短ID: ${CYAN}$SHORT_ID${NC}"
    echo -e "  域名: ${CYAN}$REALITY_DOMAIN${NC}"
}

# 生成配置文件
generate_config() {
    echo -e "${BLUE}正在生成Sing-box配置文件...${NC}"
    
    cat > "$CONFIG_FILE" <<EOF
{
  "log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "anytls",
      "tag": "any-reality",
      "listen": "::",
      "listen_port": $PORT,
      "users": [
        {
          "password": "$UUID"
        }
      ],
      "padding_scheme": [],
      "tls": {
        "enabled": true,
        "server_name": "$REALITY_DOMAIN",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "$REALITY_DOMAIN",
            "server_port": 443
          },
          "private_key": "$PRIVATE_KEY",
          "short_id": ["$SHORT_ID"]
        }
      }
    }
  ],
  "outbounds": [
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
        "action": "resolve",
        "strategy": "prefer_ipv4"
      }
    ],
    "final": "direct"
  }
}
EOF

    if [ -f "$CONFIG_FILE" ]; then
        echo -e "${GREEN}配置文件生成完成: ${CYAN}$CONFIG_FILE${NC}"
        echo -e "${BLUE}配置文件大小: $(ls -lh "$CONFIG_FILE" | awk '{print $5}')${NC}"
    else
        echo -e "${RED}配置文件生成失败${NC}"
        exit 1
    fi
}

# 创建systemd服务
create_service() {
    echo -e "${BLUE}正在创建系统服务...${NC}"
    
    # 检查systemd是否可用
    if ! command -v systemctl >/dev/null 2>&1; then
        echo -e "${RED}错误: systemd不可用，无法创建系统服务${NC}"
        exit 1
    fi
    
    # 创建服务文件
    cat > /tmp/any-reality.service <<EOF
[Unit]
Description=Any-Reality Service (AnyTLS + Reality)
Documentation=https://github.com/SagerNet/sing-box
After=network.target network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$WORK_DIR
Environment=SING_BOX_CONFIG_PATH=$CONFIG_FILE
ExecStart=$WORK_DIR/sing-box run -c $CONFIG_FILE
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

    # 移动服务文件到系统目录
    if mv /tmp/any-reality.service /etc/systemd/system/; then
        echo -e "${GREEN}系统服务文件创建完成${NC}"
    else
        echo -e "${RED}系统服务文件创建失败，请检查权限${NC}"
        exit 1
    fi
    
    # 重新加载systemd
    systemctl daemon-reload
    
    # 启用服务
    if systemctl enable any-reality; then
        echo -e "${GREEN}服务已设置为开机自启${NC}"
    else
        echo -e "${YELLOW}警告: 设置开机自启失败${NC}"
    fi
}

# 启动服务
start_service() {
    echo -e "${BLUE}正在启动Any-Reality服务...${NC}"
    
    # 测试配置文件
    echo -e "${BLUE}正在验证配置文件...${NC}"
    if "$WORK_DIR/sing-box" check -c "$CONFIG_FILE"; then
        echo -e "${GREEN}配置文件验证通过${NC}"
    else
        echo -e "${RED}配置文件验证失败${NC}"
        exit 1
    fi
    
    # 启动服务
    if systemctl start any-reality; then
        echo -e "${GREEN}服务启动命令执行完成${NC}"
    else
        echo -e "${RED}服务启动失败${NC}"
        echo -e "${YELLOW}查看错误日志:${NC}"
        journalctl -u any-reality --no-pager -n 10
        exit 1
    fi
    
    # 等待服务启动
    echo -e "${BLUE}等待服务启动...${NC}"
    sleep 5
    
    # 检查服务状态
    if systemctl is-active --quiet any-reality; then
        echo -e "${GREEN}✅ Any-Reality服务启动成功！${NC}"
        return 0
    else
        echo -e "${RED}❌ 服务启动失败${NC}"
        echo -e "${YELLOW}服务状态信息:${NC}"
        systemctl status any-reality --no-pager
        echo ""
        echo -e "${YELLOW}最近日志:${NC}"
        journalctl -u any-reality --no-pager -n 20
        exit 1
    fi
}

# 获取服务器IP
get_server_ip() {
    echo -e "${BLUE}正在获取服务器IP地址...${NC}"
    
    # 尝试获取IPv4地址
    local ipv4
    ipv4=$(curl -s4 --max-time 10 https://icanhazip.com 2>/dev/null || curl -s4 --max-time 10 https://ipv4.icanhazip.com 2>/dev/null || curl -s4 --max-time 10 https://ipinfo.io/ip 2>/dev/null)
    
    # 尝试获取IPv6地址
    local ipv6
    ipv6=$(curl -s6 --max-time 10 https://icanhazip.com 2>/dev/null || curl -s6 --max-time 10 https://ipv6.icanhazip.com 2>/dev/null)
    
    # 确定使用的IP
    if [ -n "$ipv4" ]; then
        SERVER_IP="$ipv4"
        echo -e "${GREEN}检测到IPv4地址: ${CYAN}$SERVER_IP${NC}"
    elif [ -n "$ipv6" ]; then
        SERVER_IP="[$ipv6]"
        echo -e "${GREEN}检测到IPv6地址: ${CYAN}$SERVER_IP${NC}"
    else
        SERVER_IP="YOUR_SERVER_IP"
        echo -e "${YELLOW}⚠️  无法自动获取IP地址，请手动替换节点配置中的IP${NC}"
    fi
}

# 生成客户端配置
generate_client_config() {
    echo -e "${BLUE}正在生成客户端配置...${NC}"
    
    # 获取主机名
    local hostname
    hostname=$(hostname 2>/dev/null || echo "server")
    
    # 生成节点名称
    local node_name
    if [ -n "$NODE_NAME" ]; then
        node_name="${NODE_NAME}-any-reality-${hostname}"
    else
        node_name="any-reality-${hostname}"
    fi
    
    # 生成分享链接
    local share_link="anytls://${UUID}@${SERVER_IP}:${PORT}?security=reality&sni=${REALITY_DOMAIN}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#${node_name}"
    
    # 保存配置信息
    cat > "$WORK_DIR/client_config.txt" <<EOF
=== Any-Reality 客户端配置信息 ===

分享链接 (推荐):
$share_link

手动配置参数:
协议类型: AnyTLS
服务器地址: $SERVER_IP
服务器端口: $PORT
密码(Password): $UUID
传输层安全: TLS
Reality: 启用
SNI: $REALITY_DOMAIN
指纹: chrome
公钥: $PUBLIC_KEY
短ID: $SHORT_ID
传输协议: TCP

节点名称: $node_name
Reality域名: $REALITY_DOMAIN
EOF

    echo -e "${GREEN}客户端配置生成完成${NC}"
}

# 显示配置信息
show_config_info() {
    local hostname
    hostname=$(hostname 2>/dev/null || echo "server")
    
    echo ""
    echo -e "${PURPLE}================================================================${NC}"
    echo -e "${PURPLE}                    安装完成！${NC}"
    echo -e "${PURPLE}================================================================${NC}"
    echo ""
    echo -e "${GREEN}🎉 Any-Reality服务安装成功！${NC}"
    echo ""
    echo -e "${YELLOW}📊 服务信息:${NC}"
    echo -e "  服务状态: ${GREEN}$(systemctl is-active any-reality)${NC}"
    echo -e "  监听端口: ${CYAN}$PORT${NC}"
    echo -e "  Reality域名: ${CYAN}$REALITY_DOMAIN${NC}"
    echo -e "  UUID密码: ${CYAN}$UUID${NC}"
    echo -e "  服务器IP: ${CYAN}$SERVER_IP${NC}"
    echo ""
    
    # 显示分享链接
    local node_name
    if [ -n "$NODE_NAME" ]; then
        node_name="${NODE_NAME}-any-reality-${hostname}"
    else
        node_name="any-reality-${hostname}"
    fi
    
    local share_link="anytls://${UUID}@${SERVER_IP}:${PORT}?security=reality&sni=${REALITY_DOMAIN}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#${node_name}"
    
    echo -e "${YELLOW}📱 客户端配置:${NC}"
    echo -e "${BLUE}分享链接 (推荐):${NC}"
    echo -e "${CYAN}$share_link${NC}"
    echo ""
    
    echo -e "${BLUE}手动配置参数:${NC}"
    echo -e "  协议类型: AnyTLS"
    echo -e "  服务器地址: $SERVER_IP"
    echo -e "  服务器端口: $PORT"
    echo -e "  密码: $UUID"
    echo -e "  TLS: 启用"
    echo -e "  Reality: 启用"
    echo -e "  SNI: $REALITY_DOMAIN"
    echo -e "  指纹: chrome"
    echo -e "  公钥: $PUBLIC_KEY"
    echo -e "  短ID: $SHORT_ID"
    echo ""
    
    echo -e "${YELLOW}🔧 服务管理命令:${NC}"
    echo -e "  启动服务: ${GREEN}systemctl start any-reality${NC}"
    echo -e "  停止服务: ${GREEN}systemctl stop any-reality${NC}"
    echo -e "  重启服务: ${GREEN}systemctl restart any-reality${NC}"
    echo -e "  查看状态: ${GREEN}systemctl status any-reality${NC}"
    echo -e "  查看日志: ${GREEN}journalctl -u any-reality -f${NC}"
    echo -e "  开机自启: ${GREEN}systemctl enable any-reality${NC}"
    echo -e "  禁用自启: ${GREEN}systemctl disable any-reality${NC}"
    echo ""
    
    echo -e "${YELLOW}📂 重要文件:${NC}"
    echo -e "  配置文件: ${CYAN}$CONFIG_FILE${NC}"
    echo -e "  工作目录: ${CYAN}$WORK_DIR${NC}"
    echo -e "  服务文件: ${CYAN}/etc/systemd/system/any-reality.service${NC}"
    echo -e "  客户端配置: ${CYAN}$WORK_DIR/client_config.txt${NC}"
    echo ""
    
    echo -e "${GREEN}✨ 客户端推荐: v2rayN 7.14.4 预览版${NC}"
    echo -e "${GREEN}🌟 直接复制分享链接导入即可使用！${NC}"
    echo ""
    echo -e "${PURPLE}================================================================${NC}"
}

# 检查root权限
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}错误: 此脚本需要root权限运行${NC}"
        echo -e "${YELLOW}请使用: sudo $0${NC}"
        exit 1
    fi
}

# 解析命令行参数
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --port)
                PORT="$2"
                shift 2
                ;;
            --domain)
                REALITY_DOMAIN="$2"
                shift 2
                ;;
            --uuid)
                UUID="$2"
                shift 2
                ;;
            --name)
                NODE_NAME="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}未知参数: $1${NC}"
                show_help
                exit 1
                ;;
        esac
    done
}

# 显示帮助信息
show_help() {
    echo "Any-Reality 独立安装脚本"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  --port PORT        指定监听端口 (默认随机生成)"
    echo "  --domain DOMAIN    指定Reality伪装域名 (默认: www.amd.com)"
    echo "  --uuid UUID        指定UUID密码 (默认自动生成)"
    echo "  --name NAME        指定节点名称前缀"
    echo "  --help, -h         显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0                                    # 使用默认配置安装"
    echo "  $0 --port 8443 --domain www.bing.com # 指定端口和域名"
    echo "  $0 --uuid 550e8400-e29b-41d4-a716-446655440000 # 指定UUID"
}

# 主函数
main() {
    # 检查权限
    check_root
    
    # 解析参数
    parse_args "$@"
    
    # 显示横幅
    show_banner
    
    # 创建工作目录
    mkdir -p "$WORK_DIR"
    
    # 执行安装步骤
    detect_system
    check_network
    install_dependencies
    generate_uuid
    generate_port
    download_singbox
    generate_reality_keys
    generate_config
    create_service
    start_service
    get_server_ip
    generate_client_config
    show_config_info
    
    echo -e "${GREEN}🎉 Any-Reality安装完成！${NC}"
}

# 执行主函数
main "$@"
