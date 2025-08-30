#!/bin/bash
# SOCKS5 Proxy Server Installation Script
# Fixed version with improved error handling and security

set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Global variables
SOCKS5_PORT=""
SOCKS5_USERNAME=""
SOCKS5_PASSWORD=""
SOCKS5_AUTH_ENABLED=1
SERVER_IP=""
INSTALL_DIR="/opt/socks5-proxy"
SERVICE_NAME="socks5-proxy"

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root!"
        exit 1
    fi
}

# Detect network environment
detect_network() {
    local ipv4_available=0
    local ipv6_available=0
    
    if timeout 10 curl -s -4 --connect-timeout 5 http://ipv4.icanhazip.com > /dev/null 2>&1; then
        ipv4_available=1
    fi
    
    if timeout 10 curl -s -6 --connect-timeout 5 http://ipv6.icanhazip.com > /dev/null 2>&1; then
        ipv6_available=1
    fi
    
    if [[ $ipv4_available -eq 1 ]] && [[ $ipv6_available -eq 1 ]]; then
        echo "dual"
    elif [[ $ipv4_available -eq 1 ]]; then
        echo "ipv4"
    elif [[ $ipv6_available -eq 1 ]]; then
        echo "ipv6"
    else
        echo "none"
    fi
}

# Get server IP address
get_server_ip() {
    local network_type=$(detect_network)
    local server_ip=""
    
    case $network_type in
        "dual")
            server_ip=$(timeout 10 curl -s -4 --connect-timeout 10 http://ipv4.icanhazip.com 2>/dev/null || echo "")
            if [[ -z "${server_ip}" ]]; then
                server_ip=$(timeout 10 curl -s -6 --connect-timeout 10 http://ipv6.icanhazip.com 2>/dev/null || echo "")
            fi
            ;;
        "ipv4")
            server_ip=$(timeout 10 curl -s -4 --connect-timeout 10 http://ipv4.icanhazip.com 2>/dev/null || echo "")
            ;;
        "ipv6")
            server_ip=$(timeout 10 curl -s -6 --connect-timeout 10 http://ipv6.icanhazip.com 2>/dev/null || echo "")
            ;;
        "none")
            error "No internet connection available!"
            exit 1
            ;;
    esac
    
    if [[ -z "${server_ip}" ]]; then
        case $network_type in
            "dual"|"ipv4")
                server_ip=$(timeout 10 curl -s -4 ifconfig.me 2>/dev/null || echo "")
                [[ -z "${server_ip}" ]] && server_ip=$(timeout 10 curl -s -4 icanhazip.com 2>/dev/null || echo "")
                ;;
            "ipv6")
                server_ip=$(timeout 10 curl -s -6 ifconfig.me 2>/dev/null || echo "")
                [[ -z "${server_ip}" ]] && server_ip=$(timeout 10 curl -s -6 icanhazip.com 2>/dev/null || echo "")
                ;;
        esac
    fi
    
    if [[ -z "${server_ip}" ]]; then
        error "Failed to get server IP address!"
        exit 1
    fi
    
    echo "${server_ip}"
}

# Check if port is in use
check_port() {
    local port=$1
    if ss -tuln 2>/dev/null | grep -q ":${port} " || netstat -tuln 2>/dev/null | grep -q ":${port} "; then
        return 0
    else
        return 1
    fi
}

# Generate random port
generate_random_port() {
    local port
    for i in {1..10}; do
        port=$(shuf -i 1080-65000 -n 1)
        if ! check_port "$port"; then
            echo "$port"
            return 0
        fi
    done
    error "Failed to find available port after 10 attempts"
    exit 1
}

# Get SOCKS5 configuration
get_socks5_config() {
    echo "====== SOCKS5 Proxy Configuration ======"
    
    read -p "Enter SOCKS5 port (default: random): " user_port
    if [[ -n "$user_port" ]]; then
        if [[ "$user_port" =~ ^[0-9]+$ ]] && [[ "$user_port" -ge 1 ]] && [[ "$user_port" -le 65535 ]]; then
            if check_port "$user_port"; then
                error "Port $user_port is already in use!"
                SOCKS5_PORT=$(generate_random_port)
                warning "Using random port: $SOCKS5_PORT"
            else
                SOCKS5_PORT="$user_port"
            fi
        else
            error "Invalid port number!"
            SOCKS5_PORT=$(generate_random_port)
            warning "Using random port: $SOCKS5_PORT"
        fi
    else
        SOCKS5_PORT=$(generate_random_port)
    fi
    
    echo ""
    echo "Authentication options:"
    echo "1. Use random generated username/password"
    echo "2. Custom username/password"
    echo "3. No authentication (NOT recommended)"
    
    read -p "Choose authentication method (1-3, default: 1): " auth_choice
    
    case "$auth_choice" in
        2)
            read -p "Enter username: " custom_username
            read -p "Enter password: " custom_password
            if [[ -n "$custom_username" ]] && [[ -n "$custom_password" ]]; then
                SOCKS5_USERNAME="$custom_username"
                SOCKS5_PASSWORD="$custom_password"
                SOCKS5_AUTH_ENABLED=1
            else
                warning "Empty username or password, using random generated credentials"
                SOCKS5_USERNAME="user$(openssl rand -hex 4 2>/dev/null || echo $(date +%s | tail -c 8))"
                SOCKS5_PASSWORD="pass$(openssl rand -hex 6 2>/dev/null || echo $(date +%s | tail -c 12))"
                SOCKS5_AUTH_ENABLED=1
            fi
            ;;
        3)
            SOCKS5_AUTH_ENABLED=0
            warning "No authentication mode selected (security risk!)"
            ;;
        *)
            SOCKS5_USERNAME="user$(openssl rand -hex 4 2>/dev/null || echo $(date +%s | tail -c 8))"
            SOCKS5_PASSWORD="pass$(openssl rand -hex 6 2>/dev/null || echo $(date +%s | tail -c 12))"
            SOCKS5_AUTH_ENABLED=1
            info "Using random generated credentials"
            ;;
    esac
}

# Install system dependencies
install_dependencies() {
    log "Installing system dependencies..."
    
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y
        apt-get install -y python3 python3-pip curl net-tools openssl ufw iproute2
    elif command -v yum >/dev/null 2>&1; then
        yum update -y
        yum install -y python3 python3-pip curl net-tools openssl firewalld iproute
    elif command -v dnf >/dev/null 2>&1; then
        dnf update -y
        dnf install -y python3 python3-pip curl net-tools openssl firewalld iproute
    else
        error "Unsupported package manager!"
        exit 1
    fi
}

# Create improved Python SOCKS5 proxy
create_python_socks5() {
    log "Creating Python SOCKS5 proxy server..."
    
    mkdir -p "$INSTALL_DIR"
    
    cat > "$INSTALL_DIR/socks5_server.py" << 'EOF'
#!/usr/bin/env python3
import socket
import threading
import struct
import sys
import argparse
import logging
import signal
import time
from socketserver import ThreadingTCPServer, BaseRequestHandler

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

logger = logging.getLogger(__name__)

class SOCKS5Handler(BaseRequestHandler):
    def __init__(self, request, client_address, server):
        self.username = getattr(server, 'username', None)
        self.password = getattr(server, 'password', None)
        self.auth_enabled = self.username is not None and self.password is not None
        super().__init__(request, client_address, server)

    def handle(self):
        try:
            if not self.handle_handshake():
                return
            
            if self.auth_enabled:
                if not self.handle_authentication():
                    return
            
            if not self.handle_connection_request():
                return
                
        except Exception as e:
            logger.error(f"Error handling client {self.client_address}: {e}")
        finally:
            try:
                self.request.close()
            except:
                pass

    def handle_handshake(self):
        try:
            data = self.request.recv(1024)
            if len(data) < 2 or data[0] != 5:
                logger.warning(f"Invalid SOCKS version from {self.client_address}")
                return False

            nmethods = data[1]
            if len(data) < 2 + nmethods:
                logger.warning(f"Invalid handshake data from {self.client_address}")
                return False

            methods = data[2:2+nmethods]
            
            if self.auth_enabled:
                if 2 in methods:
                    self.request.send(b'\x05\x02')
                    return True
                else:
                    self.request.send(b'\x05\xff')
                    return False
            else:
                if 0 in methods:
                    self.request.send(b'\x05\x00')
                    return True
                else:
                    self.request.send(b'\x05\xff')
                    return False
                    
        except Exception as e:
            logger.error(f"Handshake error with {self.client_address}: {e}")
            return False

    def handle_authentication(self):
        try:
            data = self.request.recv(1024)
            if len(data) < 2 or data[0] != 1:
                logger.warning(f"Invalid auth version from {self.client_address}")
                return False

            username_len = data[1]
            if len(data) < 2 + username_len + 1:
                logger.warning(f"Invalid auth data from {self.client_address}")
                return False

            username = data[2:2+username_len].decode('utf-8')
            password_len = data[2+username_len]
            
            if len(data) < 2 + username_len + 1 + password_len:
                logger.warning(f"Incomplete auth data from {self.client_address}")
                return False

            password = data[2+username_len+1:2+username_len+1+password_len].decode('utf-8')

            if username == self.username and password == self.password:
                self.request.send(b'\x01\x00')
                logger.info(f"Authentication successful for {self.client_address}")
                return True
            else:
                self.request.send(b'\x01\x01')
                logger.warning(f"Authentication failed for {self.client_address}")
                return False
                
        except Exception as e:
            logger.error(f"Authentication error with {self.client_address}: {e}")
            return False

    def handle_connection_request(self):
        try:
            data = self.request.recv(1024)
            if len(data) < 4 or data[0] != 5 or data[1] != 1:
                logger.warning(f"Invalid connection request from {self.client_address}")
                return False

            atyp = data[3]
            
            if atyp == 1:
                if len(data) < 10:
                    self.send_error_response(1)
                    return False
                target_ip = socket.inet_ntoa(data[4:8])
                target_port = struct.unpack('!H', data[8:10])[0]
                target_addr = (target_ip, target_port)
                family = socket.AF_INET
                
            elif atyp == 3:
                if len(data) < 5:
                    self.send_error_response(1)
                    return False
                domain_len = data[4]
                if len(data) < 5 + domain_len + 2:
                    self.send_error_response(1)
                    return False
                target_ip = data[5:5+domain_len].decode('utf-8')
                target_port = struct.unpack('!H', data[5+domain_len:7+domain_len])[0]
                target_addr = (target_ip, target_port)
                family = socket.AF_INET
                
            elif atyp == 4:
                if len(data) < 22:
                    self.send_error_response(1)
                    return False
                target_ip = socket.inet_ntop(socket.AF_INET6, data[4:20])
                target_port = struct.unpack('!H', data[20:22])[0]
                target_addr = (target_ip, target_port)
                family = socket.AF_INET6
                
            else:
                self.send_error_response(8)
                return False

            try:
                if atyp == 3:
                    target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    target_socket.settimeout(10)
                    target_socket.connect(target_addr)
                else:
                    target_socket = socket.socket(family, socket.SOCK_STREAM)
                    target_socket.settimeout(10)
                    target_socket.connect(target_addr)

                self.request.send(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
                logger.info(f"Connected {self.client_address} -> {target_addr}")

                self.forward_data(target_socket)
                
            except Exception as e:
                logger.warning(f"Failed to connect to {target_addr}: {e}")
                self.send_error_response(5)
                return False

        except Exception as e:
            logger.error(f"Connection request error with {self.client_address}: {e}")
            return False

    def send_error_response(self, error_code):
        response = struct.pack('!BBBBIH', 5, error_code, 0, 1, 0, 0)
        try:
            self.request.send(response)
        except:
            pass

    def forward_data(self, target_socket):
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
                try:
                    src.close()
                    dst.close()
                except:
                    pass

        thread1 = threading.Thread(target=forward, args=(self.request, target_socket))
        thread2 = threading.Thread(target=forward, args=(target_socket, self.request))
        
        thread1.daemon = True
        thread2.daemon = True
        
        thread1.start()
        thread2.start()
        
        thread1.join()
        thread2.join()

class SOCKS5Server(ThreadingTCPServer):
    allow_reuse_address = True
    
    def __init__(self, server_address, handler_class, username=None, password=None):
        self.username = username
        self.password = password
        super().__init__(server_address, handler_class)

def signal_handler(signum, frame):
    logger.info("Shutting down SOCKS5 proxy server...")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='SOCKS5 Proxy Server')
    parser.add_argument('--bind', default='0.0.0.0:1080', help='Bind address')
    parser.add_argument('--username', help='Username for authentication')
    parser.add_argument('--password', help='Password for authentication')
    
    args = parser.parse_args()
    
    if ':' in args.bind:
        host, port = args.bind.rsplit(':', 1)
        port = int(port)
    else:
        host = '0.0.0.0'
        port = int(args.bind)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        server = SOCKS5Server((host, port), SOCKS5Handler, args.username, args.password)
        
        auth_status = "with authentication" if args.username and args.password else "without authentication"
        logger.info(f"SOCKS5 proxy server listening on {host}:{port} ({auth_status})")
        
        server.serve_forever()
        
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
EOF

    chmod +x "$INSTALL_DIR/socks5_server.py"
    
    cat > "/usr/local/bin/socks5-proxy" << EOF
#!/bin/bash
cd "$INSTALL_DIR"
exec python3 socks5_server.py "\$@"
EOF
    
    chmod +x "/usr/local/bin/socks5-proxy"
    log "Python SOCKS5 proxy created successfully"
}

# Configure firewall
configure_firewall() {
    log "Configuring firewall for port $SOCKS5_PORT..."
    
    if command -v ufw >/dev/null 2>&1; then
        ufw allow "$SOCKS5_PORT"/tcp
        if ! ufw status | grep -q "Status: active"; then
            warning "UFW is not active. Activating now..."
            echo "y" | ufw enable
        fi
    elif command -v firewall-cmd >/dev/null 2>&1; then
        if systemctl is-active --quiet firewalld; then
            firewall-cmd --permanent --add-port="$SOCKS5_PORT"/tcp
            firewall-cmd --reload
        else
            warning "firewalld is not active"
        fi
    elif command -v iptables >/dev/null 2>&1; then
        iptables -I INPUT -p tcp --dport "$SOCKS5_PORT" -j ACCEPT
        if command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
    else
        warning "No firewall management tool found. Please manually open port $SOCKS5_PORT"
    fi
}

# Create systemd service
create_systemd_service() {
    log "Creating systemd service..."
    
    local auth_params=""
    if [[ $SOCKS5_AUTH_ENABLED -eq 1 ]]; then
        auth_params="--username '$SOCKS5_USERNAME' --password '$SOCKS5_PASSWORD'"
    fi
    
    cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=SOCKS5 Proxy Server
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/local/bin/socks5-proxy --bind 0.0.0.0:$SOCKS5_PORT $auth_params
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
KillMode=mixed
TimeoutStopSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
}

# Start and test service
start_and_test_service() {
    log "Starting SOCKS5 proxy service..."
    
    systemctl start "$SERVICE_NAME"
    
    sleep 3
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "SOCKS5 proxy service started successfully"
        
        if ss -tuln 2>/dev/null | grep -q ":$SOCKS5_PORT " || netstat -tuln 2>/dev/null | grep -q ":$SOCKS5_PORT "; then
            log "Port $SOCKS5_PORT is listening"
            return 0
        else
            error "Port $SOCKS5_PORT is not listening"
            return 1
        fi
    else
        error "SOCKS5 proxy service failed to start"
        echo "Service status:"
        systemctl status "$SERVICE_NAME" --no-pager
        echo ""
        echo "Service logs:"
        journalctl -u "$SERVICE_NAME" --no-pager -n 20
        return 1
    fi
}

# Display client configuration
show_client_config() {
    local network_type=$(detect_network)
    
    clear
    echo "========================================"
    echo "SOCKS5 Proxy Installation Complete!"
    echo "========================================"
    echo ""
    echo "Network Environment:"
    case $network_type in
        "dual")
            echo "  Type: Dual Stack (IPv4 + IPv6)"
            ;;
        "ipv4")
            echo "  Type: IPv4 Only"
            ;;
        "ipv6")
            echo "  Type: IPv6 Only"
            ;;
    esac
    echo "  Server IP: $SERVER_IP"
    echo ""
    echo "SOCKS5 Configuration:"
    echo "  Server: $SERVER_IP"
    echo "  Port: $SOCKS5_PORT"
    echo "  Protocol: SOCKS5"
    
    if [[ $SOCKS5_AUTH_ENABLED -eq 1 ]]; then
        echo "  Authentication: Username/Password"
        echo "  Username: $SOCKS5_USERNAME"
        echo "  Password: $SOCKS5_PASSWORD"
        echo ""
        echo "Client Test Commands:"
        echo "  curl --socks5-hostname $SOCKS5_USERNAME:$SOCKS5_PASSWORD@$SERVER_IP:$SOCKS5_PORT https://httpbin.org/ip"
    else
        echo "  Authentication: None"
        echo ""
        echo "Client Test Commands:"
        echo "  curl --socks5 $SERVER_IP:$SOCKS5_PORT https://httpbin.org/ip"
    fi
    
    echo ""
    echo "Service Management:"
    echo "  Start:   systemctl start $SERVICE_NAME"
    echo "  Stop:    systemctl stop $SERVICE_NAME"
    echo "  Restart: systemctl restart $SERVICE_NAME"
    echo "  Status:  systemctl status $SERVICE_NAME"
    echo "  Logs:    journalctl -u $SERVICE_NAME -f"
    echo ""
    echo "Installation Directory: $INSTALL_DIR"
    echo "========================================"
    
    cat > "$INSTALL_DIR/client_config.txt" << EOF
SOCKS5 Proxy Configuration
==========================
Server: $SERVER_IP
Port: $SOCKS5_PORT
Protocol: SOCKS5
EOF

    if [[ $SOCKS5_AUTH_ENABLED -eq 1 ]]; then
        cat >> "$INSTALL_DIR/client_config.txt" << EOF
Authentication: Username/Password
Username: $SOCKS5_USERNAME
Password: $SOCKS5_PASSWORD

Test Commands:
curl --socks5-hostname $SOCKS5_USERNAME:$SOCKS5_PASSWORD@$SERVER_IP:$SOCKS5_PORT https://httpbin.org/ip
EOF
    else
        cat >> "$INSTALL_DIR/client_config.txt" << EOF
Authentication: None

Test Commands:
curl --socks5 $SERVER_IP:$SOCKS5_PORT https://httpbin.org/ip
EOF
    fi
    
    info "Configuration saved to: $INSTALL_DIR/client_config.txt"
}

# Uninstall function
uninstall_socks5() {
    echo "Uninstalling SOCKS5 proxy..."
    
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    
    rm -f "/etc/systemd/system/$SERVICE_NAME.service"
    systemctl daemon-reload
    
    rm -rf "$INSTALL_DIR"
    rm -f "/usr/local/bin/socks5-proxy"
    
    log "SOCKS5 proxy uninstalled successfully"
}

# Main installation function
main() {
    echo "========================================"
    echo "SOCKS5 Proxy Server Installation Script"
    echo "========================================"
    echo ""
    
    if [[ "$1" == "uninstall" ]]; then
        uninstall_socks5
        exit 0
    fi
    
    check_root
    
    info "Detecting server IP address..."
    SERVER_IP=$(get_server_ip)
    log "Server IP detected: $SERVER_IP"
    
    get_socks5_config
    
    install_dependencies
    
    create_python_socks5
    
    configure_firewall
    
    create_systemd_service
    
    if start_and_test_service; then
        show_client_config
        log "SOCKS5 proxy installation completed successfully!"
    else
        error "SOCKS5 proxy installation failed!"
        exit 1
    fi
}

# Script usage
if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
    echo "Usage: $0 [uninstall]"
    echo ""
    echo "Options:"
    echo "  uninstall    Remove SOCKS5 proxy server"
    echo "  --help, -h   Show this help message"
    echo ""
    echo "This script installs a SOCKS5 proxy server with:"
    echo "  - IPv4/IPv6 support"
    echo "  - Username/password authentication"
    echo "  - Automatic firewall configuration"
    echo "  - Systemd service integration"
    exit 0
fi

main "$@"