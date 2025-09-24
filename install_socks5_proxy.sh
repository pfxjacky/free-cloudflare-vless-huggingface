#!/bin/bash

# SOCKS5代理服务器安装脚本（修复版）
# 支持IPv4/IPv6双栈检测和配置
# 修复了IPv4连接问题

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 默认配置
SOCKS5_PORT=1080
SOCKS5_USER=""
SOCKS5_PASS=""
INSTALL_PATH="/opt/socks5-proxy"
SERVICE_NAME="socks5-proxy"

# 打印带颜色的消息
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# 打印标题
print_title() {
    echo
    print_message $CYAN "======================================"
    print_message $CYAN "$1"
    print_message $CYAN "======================================"
    echo
}

# 检测系统信息
detect_system() {
    print_title "检测系统信息"
    
    # 检测操作系统
    if [[ -f /etc/redhat-release ]]; then
        OS="centos"
        print_message $GREEN "检测到 CentOS/RHEL 系统"
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"
        print_message $GREEN "检测到 Debian/Ubuntu 系统"
    else
        print_message $RED "不支持的操作系统！"
        exit 1
    fi
    
    # 检测架构
    ARCH=$(uname -m)
    print_message $GREEN "系统架构: $ARCH"
}

# 检测IPv4连通性
check_ipv4() {
    local ipv4_addr=""
    local ipv4_external=""
    
    # 检测本地IPv4地址
    ipv4_addr=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -1)
    
    # 检测外网IPv4连通性
    if curl -4 -s --max-time 10 ifconfig.me >/dev/null 2>&1; then
        ipv4_external=$(curl -4 -s --max-time 10 ifconfig.me)
        HAS_IPV4=true
        print_message $GREEN "✓ IPv4 连通性正常"
        print_message $BLUE "  本地IPv4: $ipv4_addr"
        print_message $BLUE "  外网IPv4: $ipv4_external"
        IPV4_ADDR=$ipv4_external
    else
        HAS_IPV4=false
        print_message $YELLOW "✗ IPv4 连通性异常或不可用"
    fi
}

# 检测IPv6连通性
check_ipv6() {
    local ipv6_addr=""
    local ipv6_external=""
    
    # 检测本地IPv6地址
    ipv6_addr=$(ip -6 addr show | grep -oP '(?<=inet6\s)[0-9a-f:]+' | grep -v '^::1' | grep -v '^fe80' | head -1)
    
    # 检测外网IPv6连通性
    if curl -6 -s --max-time 10 ifconfig.me >/dev/null 2>&1; then
        ipv6_external=$(curl -6 -s --max-time 10 ifconfig.me)
        HAS_IPV6=true
        print_message $GREEN "✓ IPv6 连通性正常"
        print_message $BLUE "  本地IPv6: $ipv6_addr"
        print_message $BLUE "  外网IPv6: $ipv6_external"
        IPV6_ADDR=$ipv6_external
    else
        HAS_IPV6=false
        print_message $YELLOW "✗ IPv6 连通性异常或不可用"
    fi
}

# 检测网络连通性
check_network() {
    print_title "检测网络连通性"
    
    HAS_IPV4=false
    HAS_IPV6=false
    IPV4_ADDR=""
    IPV6_ADDR=""
    
    check_ipv4
    check_ipv6
    
    if [[ $HAS_IPV4 == false && $HAS_IPV6 == false ]]; then
        print_message $RED "错误：IPv4和IPv6都不可用，无法继续安装！"
        exit 1
    fi
    
    # 确定网络类型
    if [[ $HAS_IPV4 == true && $HAS_IPV6 == true ]]; then
        NETWORK_TYPE="dual"
        print_message $GREEN "检测到双栈网络 (IPv4 + IPv6)"
    elif [[ $HAS_IPV4 == true ]]; then
        NETWORK_TYPE="ipv4"
        print_message $GREEN "检测到 IPv4 Only 网络"
    else
        NETWORK_TYPE="ipv6"
        print_message $GREEN "检测到 IPv6 Only 网络"
    fi
}

# 安装依赖
install_dependencies() {
    print_title "安装系统依赖"
    
    if [[ $OS == "centos" ]]; then
        print_message $BLUE "更新 CentOS/RHEL 软件包..."
        yum update -y
        yum install -y python3 python3-pip curl wget unzip net-tools
    else
        print_message $BLUE "更新 Debian/Ubuntu 软件包..."
        apt update -y
        apt install -y python3 python3-pip curl wget unzip net-tools
    fi
    
    # 安装Python依赖
    print_message $BLUE "安装 Python 依赖..."
    pip3 install asyncio --quiet
    
    print_message $GREEN "✓ 依赖安装完成"
}

# 生成用户名和密码
generate_credentials() {
    if [[ -z "$SOCKS5_USER" ]]; then
        SOCKS5_USER="user$(openssl rand -hex 4)"
    fi
    
    if [[ -z "$SOCKS5_PASS" ]]; then
        SOCKS5_PASS="pass$(openssl rand -hex 8)"
    fi
}

# 创建SOCKS5服务器代码（修复版）
create_socks5_server() {
    print_title "创建 SOCKS5 代理服务器"
    
    # 创建安装目录
    mkdir -p $INSTALL_PATH
    
    # 生成SOCKS5服务器Python代码（修复版）
    cat > $INSTALL_PATH/socks5_server.py << 'EOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOCKS5 代理服务器（修复版）
支持IPv4/IPv6双栈和用户名密码认证
修复了IPv4连接问题
"""

import asyncio
import socket
import struct
import logging
import argparse
import signal
import sys
import os
from typing import Optional, Tuple

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/socks5-proxy.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SOCKS5Server:
    def __init__(self, host: str = '0.0.0.0', port: int = 1080, username: str = None, password: str = None, enable_ipv6: bool = True):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.enable_ipv6 = enable_ipv6
        self.servers = []
        
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """处理客户端连接"""
        client_addr = writer.get_extra_info('peername')
        logger.info(f"新连接来自: {client_addr}")
        
        try:
            # SOCKS5握手
            if not await self._handle_handshake(reader, writer):
                return
                
            # 用户认证（如果需要）
            if self.username and self.password:
                if not await self._handle_authentication(reader, writer):
                    return
                    
            # 处理连接请求
            await self._handle_request(reader, writer)
            
        except Exception as e:
            logger.error(f"处理客户端 {client_addr} 时出错: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
            
    async def _handle_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        """处理SOCKS5握手"""
        try:
            # 读取客户端握手请求
            data = await reader.read(2)
            if len(data) != 2 or data[0] != 0x05:
                logger.warning("无效的SOCKS5握手请求")
                return False
                
            # 读取认证方法
            nmethods = data[1]
            methods = await reader.read(nmethods)
            
            # 确定认证方法
            if self.username and self.password:
                # 需要用户名密码认证
                if 0x02 in methods:
                    writer.write(b'\x05\x02')  # 选择用户名密码认证
                else:
                    writer.write(b'\x05\xFF')  # 无支持的认证方法
                    await writer.drain()
                    return False
            else:
                # 无需认证
                if 0x00 in methods:
                    writer.write(b'\x05\x00')  # 选择无认证
                else:
                    writer.write(b'\x05\xFF')  # 无支持的认证方法
                    await writer.drain()
                    return False
                    
            await writer.drain()
            return True
            
        except Exception as e:
            logger.error(f"握手过程出错: {e}")
            return False
            
    async def _handle_authentication(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        """处理用户名密码认证"""
        try:
            # 读取认证请求
            data = await reader.read(1)
            if not data or data[0] != 0x01:
                writer.write(b'\x01\x01')  # 认证失败
                await writer.drain()
                return False
                
            # 读取用户名长度和用户名
            ulen_data = await reader.read(1)
            if not ulen_data:
                return False
            ulen = ulen_data[0]
            username = await reader.read(ulen)
            
            # 读取密码长度和密码
            plen_data = await reader.read(1)
            if not plen_data:
                return False
            plen = plen_data[0]
            password = await reader.read(plen)
            
            # 验证用户名密码
            if (username.decode('utf-8') == self.username and 
                password.decode('utf-8') == self.password):
                writer.write(b'\x01\x00')  # 认证成功
                await writer.drain()
                logger.info(f"用户 {self.username} 认证成功")
                return True
            else:
                writer.write(b'\x01\x01')  # 认证失败
                await writer.drain()
                logger.warning(f"用户认证失败: {username.decode('utf-8', errors='ignore')}")
                return False
                
        except Exception as e:
            logger.error(f"认证过程出错: {e}")
            return False
            
    async def _handle_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """处理连接请求"""
        try:
            # 读取请求头
            data = await reader.read(4)
            if len(data) != 4 or data[0] != 0x05:
                return
                
            cmd, _, atyp = data[1], data[2], data[3]
            
            # 只支持CONNECT命令
            if cmd != 0x01:
                writer.write(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')  # 不支持的命令
                await writer.drain()
                return
                
            # 解析目标地址
            target_addr = None
            target_port = None
            bind_addr = b'\x00\x00\x00\x00'
            
            if atyp == 0x01:  # IPv4
                addr_data = await reader.read(4)
                target_addr = socket.inet_ntoa(addr_data)
                bind_addr = addr_data
            elif atyp == 0x03:  # 域名
                addr_len = (await reader.read(1))[0]
                target_addr = (await reader.read(addr_len)).decode('utf-8')
                # 解析域名为IP（优先IPv4）
                try:
                    resolved = socket.getaddrinfo(target_addr, None, socket.AF_UNSPEC)
                    # 优先使用IPv4地址
                    for family, _, _, _, sockaddr in resolved:
                        if family == socket.AF_INET:
                            bind_addr = socket.inet_aton(sockaddr[0])
                            break
                    else:
                        # 如果没有IPv4，使用第一个地址
                        if resolved:
                            bind_addr = b'\x00\x00\x00\x00'
                except:
                    bind_addr = b'\x00\x00\x00\x00'
            elif atyp == 0x04:  # IPv6
                addr_data = await reader.read(16)
                target_addr = socket.inet_ntop(socket.AF_INET6, addr_data)
            else:
                writer.write(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')  # 不支持的地址类型
                await writer.drain()
                return
                
            # 读取目标端口
            port_data = await reader.read(2)
            target_port = struct.unpack('>H', port_data)[0]
            
            logger.info(f"连接请求: {target_addr}:{target_port}")
            
            # 建立到目标服务器的连接
            try:
                target_reader, target_writer = await asyncio.wait_for(
                    asyncio.open_connection(target_addr, target_port),
                    timeout=10.0
                )
                
                # 发送成功响应（修复：使用正确的响应格式）
                response = b'\x05\x00\x00\x01'  # VER, REP, RSV, ATYP
                response += bind_addr  # 绑定地址（4字节IPv4）
                response += struct.pack('>H', target_port)  # 绑定端口
                
                writer.write(response)
                await writer.drain()
                
                # 开始数据转发
                await self._relay_data(reader, writer, target_reader, target_writer)
                
            except asyncio.TimeoutError:
                logger.error(f"连接超时: {target_addr}:{target_port}")
                writer.write(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')  # Host unreachable
                await writer.drain()
            except Exception as e:
                logger.error(f"连接目标服务器失败 {target_addr}:{target_port} - {e}")
                writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')  # 一般性SOCKS服务器错误
                await writer.drain()
                
        except Exception as e:
            logger.error(f"处理请求时出错: {e}")
            
    async def _relay_data(self, client_reader, client_writer, target_reader, target_writer):
        """数据转发"""
        async def transfer(reader, writer, direction):
            try:
                while True:
                    data = await reader.read(8192)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            except Exception as e:
                logger.debug(f"数据传输 {direction} 结束: {e}")
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except:
                    pass
                    
        # 创建双向数据转发任务
        task1 = asyncio.create_task(transfer(client_reader, target_writer, "客户端->目标"))
        task2 = asyncio.create_task(transfer(target_reader, client_writer, "目标->客户端"))
        
        # 等待任何一个方向的传输结束
        try:
            await asyncio.gather(task1, task2, return_exceptions=True)
        except Exception as e:
            logger.debug(f"数据转发结束: {e}")
        finally:
            # 确保所有连接都关闭
            for task in [task1, task2]:
                if not task.done():
                    task.cancel()
                    
            for writer in [client_writer, target_writer]:
                try:
                    writer.close()
                    await writer.wait_closed()
                except:
                    pass
                    
    async def start(self):
        """启动服务器"""
        try:
            # 创建IPv4服务器
            if self.host in ['0.0.0.0', '::']:
                # 双栈监听
                try:
                    # IPv4服务器
                    server_v4 = await asyncio.start_server(
                        self.handle_client,
                        '0.0.0.0',
                        self.port,
                        family=socket.AF_INET
                    )
                    self.servers.append(server_v4)
                    logger.info(f"IPv4 SOCKS5 服务器已启动: 0.0.0.0:{self.port}")
                except Exception as e:
                    logger.warning(f"无法启动IPv4服务器: {e}")
                
                # IPv6服务器（如果启用）
                if self.enable_ipv6:
                    try:
                        server_v6 = await asyncio.start_server(
                            self.handle_client,
                            '::',
                            self.port,
                            family=socket.AF_INET6
                        )
                        self.servers.append(server_v6)
                        logger.info(f"IPv6 SOCKS5 服务器已启动: [::]:{self.port}")
                    except Exception as e:
                        logger.warning(f"无法启动IPv6服务器: {e}")
            else:
                # 单地址监听
                server = await asyncio.start_server(
                    self.handle_client,
                    self.host,
                    self.port
                )
                self.servers.append(server)
                logger.info(f"SOCKS5 服务器已启动: {self.host}:{self.port}")
            
            if not self.servers:
                raise Exception("无法启动任何服务器")
            
            if self.username and self.password:
                logger.info(f"认证: {self.username}:{self.password}")
            else:
                logger.info("认证: 无需认证")
                
            # 保持服务运行
            await asyncio.gather(*[server.serve_forever() for server in self.servers])
                
        except Exception as e:
            logger.error(f"启动服务器失败: {e}")
            sys.exit(1)
            
    async def stop(self):
        """停止服务器"""
        for server in self.servers:
            server.close()
            await server.wait_closed()
        logger.info("SOCKS5 代理服务器已停止")

def signal_handler(signum, frame):
    """信号处理器"""
    logger.info(f"收到信号 {signum}，正在关闭服务器...")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='SOCKS5 代理服务器')
    parser.add_argument('--host', default='0.0.0.0', help='监听地址 (默认: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=1080, help='监听端口 (默认: 1080)')
    parser.add_argument('--username', help='用户名')
    parser.add_argument('--password', help='密码')
    parser.add_argument('--enable-ipv6', action='store_true', default=True, help='启用IPv6支持')
    
    args = parser.parse_args()
    
    # 设置信号处理
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 创建并启动服务器
    server = SOCKS5Server(
        host=args.host,
        port=args.port,
        username=args.username,
        password=args.password,
        enable_ipv6=args.enable_ipv6
    )
    
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        logger.info("服务器已停止")
    except Exception as e:
        logger.error(f"服务器运行时出错: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
EOF
    
    chmod +x $INSTALL_PATH/socks5_server.py
    print_message $GREEN "✓ SOCKS5 服务器代码创建完成"
}

# 创建配置文件
create_config() {
    print_title "创建配置文件"
    
    # 生成用户凭据
    generate_credentials
    
    # 确定监听地址
    if [[ $NETWORK_TYPE == "ipv6" ]]; then
        LISTEN_HOST="::"
    else
        LISTEN_HOST="0.0.0.0"
    fi
    
    # 创建配置文件
    cat > $INSTALL_PATH/config.json << EOF
{
    "host": "$LISTEN_HOST",
    "port": $SOCKS5_PORT,
    "username": "$SOCKS5_USER",
    "password": "$SOCKS5_PASS",
    "network_type": "$NETWORK_TYPE"
}
EOF
    
    # 创建启动脚本
    cat > $INSTALL_PATH/start.sh << EOF
#!/bin/bash
cd $INSTALL_PATH
python3 socks5_server.py --host $LISTEN_HOST --port $SOCKS5_PORT --username "$SOCKS5_USER" --password "$SOCKS5_PASS"
EOF
    
    chmod +x $INSTALL_PATH/start.sh
    
    print_message $GREEN "✓ 配置文件创建完成"
}

# 创建系统服务
create_service() {
    print_title "创建系统服务"
    
    # 确定监听地址
    if [[ $NETWORK_TYPE == "ipv6" ]]; then
        LISTEN_HOST="::"
    else
        LISTEN_HOST="0.0.0.0"
    fi
    
    cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=SOCKS5 Proxy Server (Fixed Version)
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_PATH
ExecStart=/usr/bin/python3 $INSTALL_PATH/socks5_server.py --host $LISTEN_HOST --port $SOCKS5_PORT --username "$SOCKS5_USER" --password "$SOCKS5_PASS"
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # 重载systemd配置
    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    
    print_message $GREEN "✓ 系统服务创建完成"
}

# 启动服务
start_service() {
    print_title "启动 SOCKS5 代理服务"
    
    systemctl start $SERVICE_NAME
    sleep 2
    
    if systemctl is-active --quiet $SERVICE_NAME; then
        print_message $GREEN "✓ SOCKS5 代理服务启动成功"
    else
        print_message $RED "✗ SOCKS5 代理服务启动失败"
        print_message $YELLOW "查看错误日志: journalctl -u $SERVICE_NAME --no-pager"
        exit 1
    fi
}

# 配置防火墙
configure_firewall() {
    print_title "配置防火墙"
    
    # 检测防火墙类型
    if command -v ufw >/dev/null 2>&1; then
        # Ubuntu UFW
        ufw allow $SOCKS5_PORT/tcp
        print_message $GREEN "✓ UFW 防火墙规则已添加"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        # CentOS firewalld
        firewall-cmd --permanent --add-port=$SOCKS5_PORT/tcp
        firewall-cmd --reload
        print_message $GREEN "✓ Firewalld 防火墙规则已添加"
    elif command -v iptables >/dev/null 2>&1; then
        # iptables
        iptables -I INPUT -p tcp --dport $SOCKS5_PORT -j ACCEPT
        if [[ $HAS_IPV6 == true ]]; then
            ip6tables -I INPUT -p tcp --dport $SOCKS5_PORT -j ACCEPT
        fi
        print_message $GREEN "✓ Iptables 防火墙规则已添加"
    else
        print_message $YELLOW "! 未检测到防火墙，请手动开放端口 $SOCKS5_PORT"
    fi
}

# 测试连接
test_connection() {
    print_title "测试 SOCKS5 代理连接"
    
    # 等待服务完全启动
    sleep 3
    
    # 测试本地连接
    if nc -zv 127.0.0.1 $SOCKS5_PORT 2>&1 | grep -q succeeded; then
        print_message $GREEN "✓ 本地连接测试成功"
    else
        print_message $YELLOW "! 本地连接测试失败"
    fi
    
    # 测试IPv4连接（如果可用）
    if [[ $HAS_IPV4 == true ]]; then
        if timeout 5 curl -4 --socks5 127.0.0.1:$SOCKS5_PORT --socks5-hostname 127.0.0.1:$SOCKS5_PORT -s http://ifconfig.me >/dev/null 2>&1; then
            print_message $GREEN "✓ IPv4 代理测试成功"
        else
            print_message $YELLOW "! IPv4 代理测试失败"
        fi
    fi
    
    # 测试IPv6连接（如果可用）
    if [[ $HAS_IPV6 == true ]]; then
        if timeout 5 curl -6 --socks5 [::1]:$SOCKS5_PORT --socks5-hostname [::1]:$SOCKS5_PORT -s http://ifconfig.me >/dev/null 2>&1; then
            print_message $GREEN "✓ IPv6 代理测试成功"
        else
            print_message $YELLOW "! IPv6 代理测试失败"
        fi
    fi
}

# 显示连接信息
show_connection_info() {
    print_title "SOCKS5 代理服务器安装完成"
    
    print_message $GREEN "服务状态: $(systemctl is-active $SERVICE_NAME)"
    print_message $BLUE "监听端口: $SOCKS5_PORT"
    print_message $BLUE "用户名: $SOCKS5_USER"
    print_message $BLUE "密码: $SOCKS5_PASS"
    echo
    
    print_message $CYAN "连接信息:"
    echo
    
    if [[ $HAS_IPV4 == true ]]; then
        print_message $GREEN "IPv4 连接:"
        print_message $YELLOW "  socks5://$SOCKS5_USER:$SOCKS5_PASS@$IPV4_ADDR:$SOCKS5_PORT"
        echo
    fi
    
    if [[ $HAS_IPV6 == true ]]; then
        print_message $GREEN "IPv6 连接:"
        print_message $YELLOW "  socks5://$SOCKS5_USER:$SOCKS5_PASS@[$IPV6_ADDR]:$SOCKS5_PORT"
        echo
    fi
    
    print_message $CYAN "管理命令:"
    print_message $BLUE "  启动服务: systemctl start $SERVICE_NAME"
    print_message $BLUE "  停止服务: systemctl stop $SERVICE_NAME"
    print_message $BLUE "  重启服务: systemctl restart $SERVICE_NAME"
    print_message $BLUE "  查看状态: systemctl status $SERVICE_NAME"
    print_message $BLUE "  查看日志: journalctl -u $SERVICE_NAME -f"
    echo
    
    print_message $CYAN "配置文件位置:"
    print_message $BLUE "  安装目录: $INSTALL_PATH"
    print_message $BLUE "  配置文件: $INSTALL_PATH/config.json"
    print_message $BLUE "  日志文件: /var/log/socks5-proxy.log"
    echo
    
    print_message $CYAN "客户端配置示例:"
    print_message $BLUE "  Curl测试: curl --socks5-hostname $SOCKS5_USER:$SOCKS5_PASS@127.0.0.1:$SOCKS5_PORT http://ifconfig.me"
    print_message $BLUE "  浏览器配置: SOCKS5代理 服务器:端口 认证:用户名/密码"
}

# 用户输入配置
user_config() {
    print_title "配置 SOCKS5 代理服务器"
    
    # 端口配置
    read -p "请输入SOCKS5端口 (默认: 1080): " input_port
    if [[ -n "$input_port" && "$input_port" =~ ^[0-9]+$ && $input_port -ge 1 && $input_port -le 65535 ]]; then
        SOCKS5_PORT=$input_port
    fi
    
    # 用户名配置
    read -p "请输入用户名 (留空自动生成): " input_user
    if [[ -n "$input_user" ]]; then
        SOCKS5_USER=$input_user
    fi
    
    # 密码配置
    read -p "请输入密码 (留空自动生成): " input_pass
    if [[ -n "$input_pass" ]]; then
        SOCKS5_PASS=$input_pass
    fi
    
    echo
    print_message $GREEN "配置信息:"
    print_message $BLUE "  端口: $SOCKS5_PORT"
    print_message $BLUE "  用户名: ${SOCKS5_USER:-自动生成}"
    print_message $BLUE "  密码: ${SOCKS5_PASS:-自动生成}"
    echo
    
    read -p "确认安装? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_message $YELLOW "安装已取消"
        exit 0
    fi
}

# 检查端口占用
check_port() {
    if ss -tlnp | grep ":$SOCKS5_PORT " >/dev/null 2>&1; then
        print_message $RED "错误: 端口 $SOCKS5_PORT 已被占用"
        print_message $YELLOW "请选择其他端口或停止占用该端口的服务"
        exit 1
    fi
}

# 卸载功能
uninstall() {
    print_title "卸载 SOCKS5 代理服务器"
    
    # 停止并禁用服务
    systemctl stop $SERVICE_NAME 2>/dev/null
    systemctl disable $SERVICE_NAME 2>/dev/null
    
    # 删除服务文件
    rm -f /etc/systemd/system/$SERVICE_NAME.service
    systemctl daemon-reload
    
    # 删除安装目录
    rm -rf $INSTALL_PATH
    
    # 删除日志文件
    rm -f /var/log/socks5-proxy.log
    
    print_message $GREEN "✓ SOCKS5 代理服务器已卸载"
}

# 主函数
main() {
    # 检查root权限
    if [[ $EUID -ne 0 ]]; then
        print_message $RED "错误: 请使用root权限运行此脚本"
        exit 1
    fi
    
    # 处理命令行参数
    case "${1:-}" in
        "uninstall"|"remove")
            uninstall
            exit 0
            ;;
        "status")
            systemctl status $SERVICE_NAME
            exit 0
            ;;
        "--help"|"-h")
            echo "使用方法:"
            echo "  $0                 # 安装SOCKS5代理服务器"
            echo "  $0 uninstall       # 卸载SOCKS5代理服务器"
            echo "  $0 status          # 查看服务状态"
            exit 0
            ;;
    esac
    
    print_title "SOCKS5 代理服务器安装脚本（修复版）"
    print_message $BLUE "支持IPv4/IPv6双栈，Python3实现"
    print_message $YELLOW "修复了IPv4连接问题"
    
    # 执行安装流程
    detect_system
    check_network
    user_config
    check_port
    install_dependencies
    create_socks5_server
    create_config
    create_service
    start_service
    configure_firewall
    test_connection
    show_connection_info
    
    print_message $GREEN "🎉 SOCKS5 代理服务器安装完成！"
}

# 脚本入口
main "$@"