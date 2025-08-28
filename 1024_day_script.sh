#!/bin/sh
# forum: https://1024.day

if [[ $EUID -ne 0 ]]; then
    clear
    echo "Error: This script must be run as root!" 1>&2
    exit 1
fi

timedatectl set-timezone Asia/Shanghai
v2path=$(cat /dev/urandom | head -1 | md5sum | head -c 6)
v2uuid=$(cat /proc/sys/kernel/random/uuid)
ssport=$(shuf -i 2000-65000 -n 1)
socks5port=$(shuf -i 1080-65000 -n 1)
socks5_username="user$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1)"
socks5_password="pass$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)"

getIP(){
    local serverIP=
    serverIP=$(curl -s -4 http://www.cloudflare.com/cdn-cgi/trace | grep "ip" | awk -F "[=]" '{print $2}')
    if [[ -z "${serverIP}" ]]; then
        serverIP=$(curl -s -6 http://www.cloudflare.com/cdn-cgi/trace | grep "ip" | awk -F "[=]" '{print $2}')
    fi
    echo "${serverIP}"
}

install_precheck(){
    echo "====输入已经DNS解析好的域名===="
    read domain

    read -t 15 -p "回车或等待15秒为默认端口443，或者自定义端口请输入(1-65535)："  getPort
    if [ -z $getPort ];then
        getPort=443
    fi
    
    if [ -f "/usr/bin/apt-get" ]; then
        apt-get update -y && apt-get upgrade -y
        apt-get install -y net-tools curl
    else
        yum update -y && yum upgrade -y
        yum install -y epel-release
        yum install -y net-tools curl
    fi

    sleep 3
    isPort=`netstat -ntlp| grep -E ':80 |:443 '`
    if [ "$isPort" != "" ];then
        clear
        echo " ================================================== "
        echo " 80或443端口被占用，请先释放端口再运行此脚本"
        echo
        echo " 端口占用信息如下："
        echo $isPort
        echo " ================================================== "
        exit 1
    fi
}

install_go_socks5(){
    echo "正在安装Go语言SOCKS5代理..."
    
    # 安装Go语言
    if ! command -v go &> /dev/null; then
        echo "正在安装Go语言..."
        GO_VERSION="1.21.5"
        if [ "$(uname -m)" = "x86_64" ]; then
            GO_ARCH="amd64"
        else
            GO_ARCH="386"
        fi
        
        wget -q "https://golang.org/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz
        if [ $? -ne 0 ]; then
            echo "Go下载失败，使用备用方案..."
            create_python_socks5
            return 0
        fi
        
        tar -C /usr/local -xzf /tmp/go.tar.gz
        export PATH="/usr/local/go/bin:$PATH"
        echo 'export PATH="/usr/local/go/bin:$PATH"' >> ~/.bashrc
        rm /tmp/go.tar.gz
        
        if ! command -v go &> /dev/null; then
            export PATH="/usr/local/go/bin:$PATH"
        fi
    fi
    
    # 创建Go版本的SOCKS5代理
    mkdir -p /opt/go-socks5
    cd /opt/go-socks5
    
    cat > main.go << 'EOF'
package main

import (
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "strconv"
)

var (
    bind     = flag.String("bind", "0.0.0.0:1080", "Bind address")
    username = flag.String("username", "", "Username for authentication")
    password = flag.String("password", "", "Password for authentication")
)

func main() {
    flag.Parse()
    
    listener, err := net.Listen("tcp", *bind)
    if err != nil {
        log.Fatal("Failed to listen:", err)
    }
    defer listener.Close()
    
    log.Printf("SOCKS5 proxy listening on %s", *bind)
    
    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Printf("Failed to accept connection: %v", err)
            continue
        }
        
        go handleConnection(conn)
    }
}

func handleConnection(conn net.Conn) {
    defer conn.Close()
    
    // SOCKS5 握手
    buf := make([]byte, 1024)
    n, err := conn.Read(buf)
    if err != nil || n < 2 || buf[0] != 5 {
        return
    }
    
    // 发送握手响应（无认证）
    _, err = conn.Write([]byte{5, 0})
    if err != nil {
        return
    }
    
    // 读取连接请求
    n, err = conn.Read(buf)
    if err != nil || n < 4 || buf[0] != 5 || buf[1] != 1 {
        return
    }
    
    var target string
    switch buf[3] {
    case 1: // IPv4
        if n < 10 {
            return
        }
        ip := net.IPv4(buf[4], buf[5], buf[6], buf[7])
        port := (int(buf[8]) << 8) | int(buf[9])
        target = net.JoinHostPort(ip.String(), strconv.Itoa(port))
    case 3: // 域名
        if n < 5 {
            return
        }
        domainLen := int(buf[4])
        if n < 5+domainLen+2 {
            return
        }
        domain := string(buf[5 : 5+domainLen])
        port := (int(buf[5+domainLen]) << 8) | int(buf[6+domainLen])
        target = net.JoinHostPort(domain, strconv.Itoa(port))
    default:
        return
    }
    
    // 连接到目标
    targetConn, err := net.Dial("tcp", target)
    if err != nil {
        conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
        return
    }
    defer targetConn.Close()
    
    // 发送成功响应
    _, err = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
    if err != nil {
        return
    }
    
    // 转发数据
    go io.Copy(targetConn, conn)
    io.Copy(conn, targetConn)
}
EOF

    # 编译Go程序
    echo "正在编译Go SOCKS5代理..."
    if command -v go &> /dev/null; then
        go build -o socks5-proxy main.go
        if [ $? -eq 0 ] && [ -f "socks5-proxy" ]; then
            cp socks5-proxy /usr/local/bin/
            chmod +x /usr/local/bin/socks5-proxy
            echo "Go SOCKS5代理编译成功"
            return 0
        fi
    fi
    
    echo "Go编译失败，使用Python备用方案..."
    create_python_socks5
}

create_python_socks5(){
    echo "创建Python版本的SOCKS5代理..."
    
    # 安装Python3和必要模块
    if [ -f "/usr/bin/apt-get" ]; then
        apt-get install -y python3 python3-pip
    else
        yum install -y python3 python3-pip
    fi
    
    # 创建Python SOCKS5代理
    cat > /usr/local/bin/socks5-proxy << 'EOF'
#!/usr/bin/env python3
import socket
import threading
import struct
import sys

class SOCKS5Proxy:
    def __init__(self, bind_ip='0.0.0.0', bind_port=1080):
        self.bind_ip = bind_ip
        self.bind_port = bind_port
    
    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.bind_ip, self.bind_port))
        server.listen(5)
        print(f"SOCKS5 proxy listening on {self.bind_ip}:{self.bind_port}")
        
        while True:
            try:
                client_socket, addr = server.accept()
                print(f"Connection from {addr}")
                thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                thread.start()
            except Exception as e:
                print(f"Error accepting connection: {e}")
    
    def handle_client(self, client_socket):
        try:
            # SOCKS5 握手
            data = client_socket.recv(1024)
            if len(data) < 2 or data[0] != 5:
                client_socket.close()
                return
            
            # 发送握手响应（无认证）
            client_socket.send(b'\x05\x00')
            
            # 读取连接请求
            data = client_socket.recv(1024)
            if len(data) < 4 or data[0] != 5 or data[1] != 1:
                client_socket.close()
                return
            
            # 解析目标地址
            atyp = data[3]
            if atyp == 1:  # IPv4
                if len(data) < 10:
                    client_socket.close()
                    return
                target_ip = socket.inet_ntoa(data[4:8])
                target_port = struct.unpack('!H', data[8:10])[0]
                target_addr = (target_ip, target_port)
            elif atyp == 3:  # 域名
                if len(data) < 5:
                    client_socket.close()
                    return
                domain_len = data[4]
                if len(data) < 5 + domain_len + 2:
                    client_socket.close()
                    return
                target_ip = data[5:5+domain_len].decode('utf-8')
                target_port = struct.unpack('!H', data[5+domain_len:7+domain_len])[0]
                target_addr = (target_ip, target_port)
            else:
                client_socket.close()
                return
            
            # 连接到目标服务器
            try:
                target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target_socket.connect(target_addr)
                
                # 发送成功响应
                client_socket.send(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
                
                # 开始转发数据
                self.forward_data(client_socket, target_socket)
            except Exception as e:
                # 发送连接失败响应
                client_socket.send(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                client_socket.close()
        except Exception as e:
            print(f"Error handling client: {e}")
            client_socket.close()
    
    def forward_data(self, client_socket, target_socket):
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.send(data)
            except:
                pass
            finally:
                src.close()
                dst.close()
        
        thread1 = threading.Thread(target=forward, args=(client_socket, target_socket))
        thread2 = threading.Thread(target=forward, args=(target_socket, client_socket))
        thread1.start()
        thread2.start()
        thread1.join()
        thread2.join()

if __name__ == '__main__':
    if len(sys.argv) >= 3 and sys.argv[1] == '--bind':
        bind_addr = sys.argv[2]
        if ':' in bind_addr:
            ip, port = bind_addr.rsplit(':', 1)
            proxy = SOCKS5Proxy(ip, int(port))
        else:
            proxy = SOCKS5Proxy('0.0.0.0', int(bind_addr))
    else:
        proxy = SOCKS5Proxy()
    
    proxy.start()
EOF
    
    chmod +x /usr/local/bin/socks5-proxy
    echo "Python SOCKS5代理创建成功"
}

create_service(){
    # 创建systemd服务文件
    cat > /etc/systemd/system/socks5-proxy.service << EOF
[Unit]
Description=SOCKS5 Proxy Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/socks5-proxy --bind 0.0.0.0:${socks5port}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
}

install_socks5(){
    echo "正在安装SOCKS5代理服务器..."
    
    # 检查并安装必要的依赖
    if [ -f "/usr/bin/apt-get" ]; then
        apt-get update -y
        apt-get install -y build-essential curl wget
    else
        yum groupinstall -y "Development Tools"
        yum install -y curl wget
    fi
    
    # 尝试Go语言方案
    install_go_socks5
    
    # 创建服务
    create_service
    
    # 启动服务
    systemctl daemon-reload
    systemctl enable socks5-proxy.service
    systemctl start socks5-proxy.service
    
    # 等待服务启动
    sleep 3
    
    # 检查服务状态
    if systemctl is-active --quiet socks5-proxy.service; then
        echo "SOCKS5代理服务启动成功"
        return 0
    else
        echo "SOCKS5代理服务启动失败，查看详细信息："
        systemctl status socks5-proxy.service
        echo ""
        echo "查看服务日志："
        journalctl -u socks5-proxy.service --no-pager -n 10
        return 1
    fi
}

client_socks5(){
    local serverIP=$(getIP)
    
    clear
    echo "SOCKS5代理安装完成！"
    echo
    echo "=========SOCKS5代理配置信息========="
    echo "服务器地址: ${serverIP}"
    echo "端口: ${socks5port}"
    echo "协议: SOCKS5 (无认证)"
    echo "================================="
    echo
    echo "客户端配置示例："
    echo "curl --socks5 ${serverIP}:${socks5port} https://httpbin.org/ip"
    echo
    echo "浏览器配置："
    echo "SOCKS主机: ${serverIP}"
    echo "端口: ${socks5port}"
    echo "认证: 无需认证"
    echo
    echo "服务管理命令："
    echo "启动: systemctl start socks5-proxy"
    echo "停止: systemctl stop socks5-proxy"
    echo "重启: systemctl restart socks5-proxy"
    echo "状态: systemctl status socks5-proxy"
    echo "日志: journalctl -u socks5-proxy -f"
    echo
}

install_nginx(){
    if [ -f "/usr/bin/apt-get" ];then
        apt-get install -y nginx cron socat
    else
        yum install -y nginx cronie socat
    fi

cat >/etc/nginx/nginx.conf<<EOF
pid /var/run/nginx.pid;
worker_processes auto;
worker_rlimit_nofile 51200;
events {
    worker_connections 1024;
    multi_accept on;
    use epoll;
}
http {
    server_tokens off;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 120s;
    keepalive_requests 10000;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    access_log off;
    error_log /dev/null;

    server {
        listen 80;
        listen [::]:80;
        server_name $domain;
        location / {
            return 301 https://\$server_name\$request_uri;
        }
    }
    
    server {
        listen $getPort ssl http2;
        listen [::]:$getPort ssl http2;
        server_name $domain;
        ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4:!DHE;
        ssl_prefer_server_ciphers on;
        ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;        
        location / {
            default_type text/plain;
            return 200 "Hello World !";
        }        
        location /$v2path {
            proxy_redirect off;
            proxy_pass http://127.0.0.1:8080;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$http_host;
        }
    }
}
EOF
}

acme_ssl(){    
    curl https://get.acme.sh | sh -s email=my@example.com
    mkdir -p /etc/letsencrypt/live/$domain
    ~/.acme.sh/acme.sh --issue -d $domain --standalone --keylength ec-256 --pre-hook "systemctl stop nginx" --post-hook "~/.acme.sh/acme.sh --installcert -d $domain --ecc --fullchain-file /etc/letsencrypt/live/$domain/fullchain.pem --key-file /etc/letsencrypt/live/$domain/privkey.pem --reloadcmd \"systemctl start nginx\""
}

install_v2ray(){    
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
    
cat >/usr/local/etc/v2ray/config.json<<EOF
{
  "inbounds": [
    {
      "port": 8080,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$v2uuid"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
        "path": "/$v2path"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF

    systemctl enable v2ray.service && systemctl restart v2ray.service && systemctl restart nginx.service
    rm -f tcp-wss.sh install-release.sh

cat >/usr/local/etc/v2ray/client.json<<EOF
{
===========配置参数=============
协议：VMess
地址：${domain}
端口：${getPort}
UUID：${v2uuid}
加密方式：aes-128-gcm
传输协议：ws
路径：/${v2path}
底层传输：tls
注意：8080是免流端口不需要打开tls
}
EOF

    clear
}

install_ssrust(){
    wget https://raw.githubusercontent.com/yeahwu/v2ray-wss/main/ss-rust.sh && bash ss-rust.sh
}

install_reality(){
    wget https://raw.githubusercontent.com/yeahwu/v2ray-wss/main/reality.sh && bash reality.sh
}

install_hy2(){
    wget https://raw.githubusercontent.com/yeahwu/v2ray-wss/main/hy2.sh && bash hy2.sh
}

install_https(){
    wget https://raw.githubusercontent.com/yeahwu/v2ray-wss/main/https.sh && bash https.sh
}

client_v2ray(){
    wslink=$(echo -n "{\"port\":${getPort},\"ps\":\"1024-wss\",\"tls\":\"tls\",\"id\":\"${v2uuid}\",\"aid\":0,\"v\":2,\"host\":\"${domain}\",\"type\":\"none\",\"path\":\"/${v2path}\",\"net\":\"ws\",\"add\":\"${domain}\",\"allowInsecure\":0,\"method\":\"none\",\"peer\":\"${domain}\",\"sni\":\"${domain}\"}" | base64 -w 0)

    echo
    echo "安装已经完成"
    echo
    echo "===========v2ray配置参数============"
    echo "协议：VMess"
    echo "地址：${domain}"
    echo "端口：${getPort}"
    echo "UUID：${v2uuid}"
    echo "加密方式：aes-128-gcm"
    echo "传输协议：ws"
    echo "路径：/${v2path}"
    echo "底层传输：tls"
    echo "注意：8080是免流端口不需要打开tls"
    echo "===================================="
    echo "vmess://${wslink}"
    echo
}

start_menu(){
    clear
    echo " ================================================== "
    echo " 论坛：https://1024.day                              "
    echo " 介绍：一键安装SS-Rust，v2ray+wss，Reality，Hysteria2，SOCKS5代理"
    echo " 系统：Ubuntu、Debian、CentOS                        "
    echo " ================================================== "
    echo
    echo " 1. 安装 Shadowsocks-rust(用于落地)"
    echo " 2. 安装 v2ray+ws+tls"
    echo " 3. 安装 Reality"
    echo " 4. 安装 Hysteria2"
    echo " 5. 安装 Https正向代理"
    echo " 6. 安装 SOCKS5代理 (多语言版本)"
    echo " 0. 退出脚本"
    echo
    read -p "请输入数字:" num
    case "$num" in
    1)
    install_ssrust
    ;;
    2)
    install_precheck
    install_nginx
    acme_ssl
    install_v2ray
    client_v2ray
    ;;
    3)
    install_reality
    ;;
    4)
    install_hy2
    ;;
    5)
    install_https
    ;;
    6)
    install_socks5
    client_socks5
    ;;
    0)
    exit 1
    ;;
    *)
    clear
    echo "请输入正确数字"
    sleep 2s
    start_menu
    ;;
    esac
}

start_menu