#!/bin/bash
# SOCKS5 Proxy Server Installation Script
# Complete version with enhanced IPv6 support and full uninstall

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
        apt-get install -y python3 python3-pip curl net-tools openssl ufw iproute2 netcat-openbsd
    elif command -v yum >/dev/null 2>&1; then
        yum update -y
        yum install -y python3 python3-pip curl net-tools openssl firewalld iproute nc
    elif command -v dnf >/dev/null 2>&1; then
        dnf update -y
        dnf install -y python3 python3-pip curl net-tools openssl firewalld iproute nc
    else
        error "Unsupported package manager!"
        exit 1
    fi
    
    # Enable IPv6 if available
    if [[ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]]; then
        echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6
        echo 0 > /proc/sys/net/ipv6/conf/default/disable_ipv6
    fi
}

# Create improved Python SOCKS5 proxy with IPv6 support
create_python_socks5() {
    log "Creating Python SOCKS5 proxy server with IPv6 support..."
    
    mkdir -p "$INSTALL_DIR"
    
    cat > "$INSTALL_DIR/socks5_server.py" << 'EOF'
#!/usr/bin/env python3
"""
Enhanced SOCKS5 Proxy Server with IPv6 Support
Fixes IPv6 connectivity issues and improves dual-stack handling
"""

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

    def create_connection_smart(self, target_addr, target_port):
        """Smart connection creation with IPv4/IPv6 fallback"""
        try:
            # Get all possible addresses
            addr_info = socket.getaddrinfo(
                target_addr, target_port, 
                socket.AF_UNSPEC, socket.SOCK_STREAM
            )
            
            # Determine client's IP version preference
            client_is_ipv6 = ':' in str(self.client_address[0])
            
            # Sort addresses: prefer same IP version as client, then IPv4
            def sort_key(info):
                family = info[0]
                if client_is_ipv6:
                    return (0 if family == socket.AF_INET6 else 1, family)
                else:
                    return (0 if family == socket.AF_INET else 1, family)
            
            addr_info.sort(key=sort_key)
            
            last_error = None
            for family, socktype, proto, canonname, sockaddr in addr_info:
                try:
                    target_socket = socket.socket(family, socktype)
                    target_socket.settimeout(10)
                    
                    # For IPv6, handle scope ID properly
                    if family == socket.AF_INET6 and len(sockaddr) > 2:
                        # Ensure proper IPv6 address handling
                        if sockaddr[3] == 0:  # No scope ID set
                            sockaddr = (sockaddr[0], sockaddr[1], sockaddr[2], 0)
                    
                    target_socket.connect(sockaddr)
                    
                    family_name = "IPv6" if family == socket.AF_INET6 else "IPv4"
                    logger.info(f"Connected via {family_name} to {sockaddr}")
                    return target_socket
                    
                except Exception as e:
                    last_error = e
                    family_name = "IPv6" if family == socket.AF_INET6 else "IPv4"
                    logger.debug(f"Failed to connect via {family_name} to {sockaddr}: {e}")
                    try:
                        target_socket.close()
                    except:
                        pass
                    continue
            
            if last_error:
                raise last_error
            else:
                raise Exception("No address info available")
                
        except Exception as e:
            logger.warning(f"Failed to create connection to {target_addr}:{target_port}: {e}")
            raise

    def handle_connection_request(self):
        try:
            data = self.request.recv(1024)
            if len(data) < 4 or data[0] != 5 or data[1] != 1:
                logger.warning(f"Invalid connection request from {self.client_address}")
                return False

            atyp = data[3]
            
            if atyp == 1:  # IPv4
                if len(data) < 10:
                    self.send_error_response(1)
                    return False
                target_ip = socket.inet_ntoa(data[4:8])
                target_port = struct.unpack('!H', data[8:10])[0]
                
            elif atyp == 3:  # Domain name
                if len(data) < 5:
                    self.send_error_response(1)
                    return False
                domain_len = data[4]
                if len(data) < 5 + domain_len + 2:
                    self.send_error_response(1)
                    return False
                target_ip = data[5:5+domain_len].decode('utf-8')
                target_port = struct.unpack('!H', data[5+domain_len:7+domain_len])[0]
                
            elif atyp == 4:  # IPv6
                if len(data) < 22:
                    self.send_error_response(1)
                    return False
                target_ip = socket.inet_ntop(socket.AF_INET6, data[4:20])
                target_port = struct.unpack('!H', data[20:22])[0]
                
            else:
                self.send_error_response(8)  # Address type not supported
                return False

            try:
                # Use smart connection creation
                target_socket = self.create_connection_smart(target_ip, target_port)

                # Send success response
                self.request.send(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
                logger.info(f"Proxying {self.client_address} -> {target_ip}:{target_port}")

                # Start data forwarding
                self.forward_data(target_socket)
                
            except Exception as e:
                logger.warning(f"Failed to connect to {target_ip}:{target_port}: {e}")
                self.send_error_response(5)  # Connection refused
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
        def forward(src, dst, direction):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.send(data)
            except Exception as e:
                logger.debug(f"Forward {direction} stopped: {e}")
            finally:
                try:
                    src.close()
                    dst.close()
                except:
                    pass

        thread1 = threading.Thread(target=forward, args=(self.request, target_socket, "client->target"))
        thread2 = threading.Thread(target=forward, args=(target_socket, self.request, "target->client"))
        
        thread1.daemon = True
        thread2.daemon = True
        
        thread1.start()
        thread2.start()
        
        thread1.join()
        thread2.join()

class DualStackTCPServer(ThreadingTCPServer):
    """Enhanced TCP Server with proper IPv4/IPv6 dual-stack support"""
    
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True, username=None, password=None):
        self.username = username
        self.password = password
        self.allow_reuse_address = True
        
        # Determine address family and setup
        host, port = server_address
        
        if host == '0.0.0.0' or host == '::':
            # Try to bind to both IPv4 and IPv6
            self.address_family = socket.AF_INET6
            if socket.has_ipv6:
                server_address = ('::', port)
                logger.info("Attempting dual-stack IPv4/IPv6 binding")
            else:
                self.address_family = socket.AF_INET
                server_address = ('0.0.0.0', port)
                logger.info("IPv6 not available, using IPv4 only")
        elif ':' in host and not host.startswith('['):
            # IPv6 address
            self.address_family = socket.AF_INET6
            logger.info(f"Binding to IPv6 address: {host}")
        else:
            # IPv4 address
            self.address_family = socket.AF_INET
            logger.info(f"Binding to IPv4 address: {host}")
            
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            try:
                # Enable dual stack (accept IPv4 connections on IPv6 socket)
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                logger.info("Dual stack (IPv4/IPv6) binding enabled")
            except (AttributeError, socket.error) as e:
                logger.warning(f"Could not enable dual stack: {e}")
                
        super().server_bind()
        
        # Log the actual binding address
        actual_addr = self.socket.getsockname()
        if self.address_family == socket.AF_INET6:
            logger.info(f"Server bound to [{actual_addr[0]}]:{actual_addr[1]}")
        else:
            logger.info(f"Server bound to {actual_addr[0]}:{actual_addr[1]}")

def signal_handler(signum, frame):
    logger.info("Shutting down SOCKS5 proxy server...")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='SOCKS5 Proxy Server with enhanced IPv4/IPv6 support')
    parser.add_argument('--bind', default='0.0.0.0:1080', help='Bind address (default: 0.0.0.0:1080 for dual-stack)')
    parser.add_argument('--username', help='Username for authentication')
    parser.add_argument('--password', help='Password for authentication')
    parser.add_argument('--ipv6-only', action='store_true', help='Bind to IPv6 only')
    parser.add_argument('--ipv4-only', action='store_true', help='Bind to IPv4 only')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Parse bind address
    if ':' in args.bind and not args.bind.startswith('['):
        if args.bind.count(':') == 1:  # IPv4 host:port
            host, port = args.bind.rsplit(':', 1)
        else:  # IPv6 address
            if args.bind.rfind(':') > args.bind.rfind(']') if ']' in args.bind else True:
                host, port = args.bind.rsplit(':', 1)
            else:
                host = args.bind
                port = '1080'
    elif args.bind.startswith('[') and ']:' in args.bind:
        # IPv6 [host]:port format
        bracket_end = args.bind.rfind(']:')
        host = args.bind[1:bracket_end]
        port = args.bind[bracket_end+2:]
    else:
        if args.bind.isdigit():
            host = '0.0.0.0'
            port = args.bind
        else:
            host = args.bind
            port = '1080'
    
    port = int(port)
    
    # Override host based on command line options
    if args.ipv6_only:
        host = '::' if host == '0.0.0.0' else host
    elif args.ipv4_only:
        host = '0.0.0.0' if host == '::' else host
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        server = DualStackTCPServer((host, port), SOCKS5Handler, username=args.username, password=args.password)
        
        auth_status = "with authentication" if args.username and args.password else "without authentication"
        
        if server.address_family == socket.AF_INET6 and not args.ipv6_only:
            family_info = "IPv4/IPv6 dual-stack"
        elif server.address_family == socket.AF_INET6:
            family_info = "IPv6"
        else:
            family_info = "IPv4"
        
        logger.info(f"SOCKS5 proxy server ready ({family_info}, {auth_status})")
        server.serve_forever()
        
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        import traceback
        traceback.print_exc()
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
    log "Enhanced Python SOCKS5 proxy with IPv6 support created successfully"
}

# Configure firewall for IPv6
configure_firewall() {
    log "Configuring firewall for port $SOCKS5_PORT (IPv4 and IPv6)..."
    
    if command -v ufw >/dev/null 2>&1; then
        # Ubuntu/Debian with UFW
        ufw allow "$SOCKS5_PORT"/tcp
        # Explicitly allow IPv6
        ufw --force enable
        if ufw status | grep -q "Status: active"; then
            log "UFW firewall configured for IPv4/IPv6"
        fi
    elif command -v firewall-cmd >/dev/null 2>&1; then
        # CentOS/RHEL with firewalld
        if systemctl is-active --quiet firewalld; then
            firewall-cmd --permanent --add-port="$SOCKS5_PORT"/tcp
            firewall-cmd --reload
            log "Firewalld configured for IPv4/IPv6"
        else
            warning "firewalld is not active"
        fi
    elif command -v iptables >/dev/null 2>&1; then
        # Fallback to iptables
        iptables -I INPUT -p tcp --dport "$SOCKS5_PORT" -j ACCEPT
        # Add IPv6 rule if ip6tables exists
        if command -v ip6tables >/dev/null 2>&1; then
            ip6tables -I INPUT -p tcp --dport "$SOCKS5_PORT" -j ACCEPT
            log "iptables/ip6tables rules added"
        fi
        # Try to save rules
        if command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
        if command -v ip6tables-save >/dev/null 2>&1; then
            ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
        fi
    else
        warning "No firewall management tool found. Please manually open port $SOCKS5_PORT for both IPv4 and IPv6"
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
Description=SOCKS5 Proxy Server with IPv4/IPv6 Support
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

# Improved start and test service function
start_and_test_service() {
    log "Starting SOCKS5 proxy service..."
    
    systemctl start "$SERVICE_NAME"
    
    # Wait for service to start properly
    sleep 5
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "SOCKS5 proxy service started successfully"
        
        # Multiple methods to verify the service is working
        local port_listening=false
        local connection_test=false
        
        # Method 1: Check with ss
        if ss -tuln 2>/dev/null | grep -q ":$SOCKS5_PORT "; then
            port_listening=true
            info "✓ Port $SOCKS5_PORT detected with ss command"
        fi
        
        # Method 2: Check with netstat if ss failed
        if [[ "$port_listening" == false ]] && netstat -tuln 2>/dev/null | grep -q ":$SOCKS5_PORT "; then
            port_listening=true
            info "✓ Port $SOCKS5_PORT detected with netstat command"
        fi
        
        # Method 3: Direct connection test
        if command -v nc >/dev/null 2>&1; then
            if timeout 5 nc -z localhost "$SOCKS5_PORT" 2>/dev/null; then
                connection_test=true
                info "✓ Port $SOCKS5_PORT connection test successful"
            elif timeout 5 nc -z 127.0.0.1 "$SOCKS5_PORT" 2>/dev/null; then
                connection_test=true
                info "✓ Port $SOCKS5_PORT IPv4 connection test successful"
            elif timeout 5 nc -z ::1 "$SOCKS5_PORT" 2>/dev/null; then
                connection_test=true
                info "✓ Port $SOCKS5_PORT IPv6 connection test successful"
            fi
        fi
        
        # If either method succeeds, consider it working
        if [[ "$port_listening" == true ]] || [[ "$connection_test" == true ]]; then
            log "SOCKS5 proxy service is working correctly"
            
            # Show current listening status for information
            info "Current listening ports for SOCKS5:"
            ss -tuln 2>/dev/null | grep ":$SOCKS5_PORT " || netstat -tuln 2>/dev/null | grep ":$SOCKS5_PORT " || echo "  Port detection methods may vary"
            
            return 0
        else
            warning "Port verification failed, but service is running. Checking service logs..."
            
            echo ""
            echo "=== Service Status ==="
            systemctl status "$SERVICE_NAME" --no-pager -l
            echo ""
            echo "=== Recent Service Logs ==="
            journalctl -u "$SERVICE_NAME" --no-pager -n 20
            echo ""
            
            # Try manual functional test if no auth
            if [[ $SOCKS5_AUTH_ENABLED -eq 0 ]]; then
                info "Attempting functional test without authentication..."
                if timeout 10 curl --socks5 127.0.0.1:$SOCKS5_PORT http://httpbin.org/ip 2>/dev/null | grep -q "origin"; then
                    log "✓ SOCKS5 functional test passed - service is working!"
                    return 0
                fi
            fi
            
            error "Could not verify SOCKS5 service functionality"
            return 1
        fi
    else
        error "SOCKS5 proxy service failed to start"
        echo "Service status:"
        systemctl status "$SERVICE_NAME" --no-pager -l
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
    echo "  IPv6 Support: ✓ Enhanced"
    
    if [[ $SOCKS5_AUTH_ENABLED -eq 1 ]]; then
        echo "  Authentication: Username/Password"
        echo "  Username: $SOCKS5_USERNAME"
        echo "  Password: $SOCKS5_PASSWORD"
        echo ""
        echo "Client Test Commands:"
        if [[ "$SERVER_IP" =~ : ]]; then
            echo "  IPv6: curl --socks5-hostname $SOCKS5_USERNAME:$SOCKS5_PASSWORD@[$SERVER_IP]:$SOCKS5_PORT https://httpbin.org/ip"
        else
            echo "  IPv4: curl --socks5-hostname $SOCKS5_USERNAME:$SOCKS5_PASSWORD@$SERVER_IP:$SOCKS5_PORT https://httpbin.org/ip"
        fi
        echo "  Test IPv6: curl --socks5-hostname $SOCKS5_USERNAME:$SOCKS5_PASSWORD@$SERVER_IP:$SOCKS5_PORT -6 https://ipv6.icanhazip.com"
    else
        echo "  Authentication: None"
        echo ""
        echo "Client Test Commands:"
        if [[ "$SERVER_IP" =~ : ]]; then
            echo "  IPv6: curl --socks5 [$SERVER_IP]:$SOCKS5_PORT https://httpbin.org/ip"
        else
            echo "  IPv4: curl --socks5 $SERVER_IP:$SOCKS5_PORT https://httpbin.org/ip"
        fi
        echo "  Test IPv6: curl --socks5 $SERVER_IP:$SOCKS5_PORT -6 https://ipv6.icanhazip.com"
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
IPv6 Support: Enhanced
EOF

    if [[ $SOCKS5_AUTH_ENABLED -eq 1 ]]; then
        cat >> "$INSTALL_DIR/client_config.txt" << EOF
Authentication: Username/Password
Username: $SOCKS5_USERNAME
Password: $SOCKS5_PASSWORD

Test Commands:
curl --socks5-hostname $SOCKS5_USERNAME:$SOCKS5_PASSWORD@$SERVER_IP:$SOCKS5_PORT https://httpbin.org/ip
curl --socks5-hostname $SOCKS5_USERNAME:$SOCKS5_PASSWORD@$SERVER_IP:$SOCKS5_PORT -6 https://ipv6.icanhazip.com
EOF
    else
        cat >> "$INSTALL_DIR/client_config.txt" << EOF
Authentication: None

Test Commands:
curl --socks5 $SERVER_IP:$SOCKS5_PORT https://httpbin.org/ip
curl --socks5 $SERVER_IP:$SOCKS5_PORT -6 https://ipv6.icanhazip.com
EOF
    fi
    
    info "Configuration saved to: $INSTALL_DIR/client_config.txt"
}

# Complete uninstall function
complete_uninstall() {
    echo "========================================"
    echo "SOCKS5 Proxy Complete Uninstall"
    echo "========================================"
    echo ""
    
    warning "This will completely remove SOCKS5 proxy and all related files!"
    read -p "Are you sure you want to proceed? (y/N): " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        info "Uninstall cancelled"
        exit 0
    fi
    
    log "Starting complete uninstall..."
    
    # Stop and disable service
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "Stopping SOCKS5 service..."
        systemctl stop "$SERVICE_NAME"
    fi
    
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        log "Disabling SOCKS5 service..."
        systemctl disable "$SERVICE_NAME"
    fi
    
    # Remove service file
    if [[ -f "/etc/systemd/system/$SERVICE_NAME.service" ]]; then
        log "Removing systemd service file..."
        rm -f "/etc/systemd/system/$SERVICE_NAME.service"
        systemctl daemon-reload
    fi
    
    # Remove installation directory
    if [[ -d "$INSTALL_DIR" ]]; then
        log "Removing installation directory..."
        rm -rf "$INSTALL_DIR"
    fi
    
    # Remove wrapper script
    if [[ -f "/usr/local/bin/socks5-proxy" ]]; then
        log "Removing wrapper script..."
        rm -f "/usr/local/bin/socks5-proxy"
    fi
    
    # Remove firewall rules (attempt to clean up)
    if command -v ufw >/dev/null 2>&1; then
        log "Attempting to remove firewall rules..."
        # Get port from service file if it still exists, or try to find it
        if [[ -f "$INSTALL_DIR/client_config.txt" ]]; then
            local port=$(grep "Port:" "$INSTALL_DIR/client_config.txt" 2>/dev/null | awk '{print $2}')
            if [[ -n "$port" ]]; then
                ufw delete allow "$port"/tcp 2>/dev/null || true
                log "Removed UFW rule for port $port"
            fi
        fi
    elif command -v firewall-cmd >/dev/null 2>&1; then
        if systemctl is-active --quiet firewalld; then
            log "Note: Please manually remove firewall rules if needed"
            info "Use: firewall-cmd --permanent --remove-port=PORT/tcp && firewall-cmd --reload"
        fi
    fi
    
    # Clean up any remaining processes
    local remaining_processes=$(pgrep -f "socks5_server.py" 2>/dev/null || echo "")
    if [[ -n "$remaining_processes" ]]; then
        log "Terminating remaining SOCKS5 processes..."
        pkill -f "socks5_server.py" 2>/dev/null || true
        sleep 2
        pkill -9 -f "socks5_server.py" 2>/dev/null || true
    fi
    
    # Remove any leftover configuration files
    for config_dir in "/etc/socks5" "/opt/socks5" "/var/lib/socks5"; do
        if [[ -d "$config_dir" ]]; then
            log "Removing configuration directory: $config_dir"
            rm -rf "$config_dir"
        fi
    done
    
    # Clean up logs
    if [[ -d "/var/log/socks5" ]]; then
        log "Removing log directory..."
        rm -rf "/var/log/socks5"
    fi
    
    # Remove any cron jobs (if any were created)
    if crontab -l 2>/dev/null | grep -q "socks5"; then
        log "Found SOCKS5 related cron jobs, please remove manually:"
        crontab -l | grep "socks5"
    fi
    
    log "Complete uninstall finished successfully!"
    echo ""
    echo "========================================"
    echo "SOCKS5 Proxy has been completely removed"
    echo "========================================"
    echo ""
    echo "Removed items:"
    echo "  ✓ Systemd service"
    echo "  ✓ Installation directory ($INSTALL_DIR)"
    echo "  ✓ Wrapper script (/usr/local/bin/socks5-proxy)"
    echo "  ✓ Service processes"
    echo "  ✓ Configuration files"
    echo ""
    echo "Note: Firewall rules and system packages were left intact"
    echo "      Remove them manually if no longer needed"
}

# Main installation function
main() {
    echo "========================================"
    echo "SOCKS5 Proxy Server Installation Script"
    echo "Enhanced IPv6 Support Version"
    echo "========================================"
    echo ""
    
    if [[ "$1" == "uninstall" ]] || [[ "$1" == "remove" ]] || [[ "$1" == "clean" ]]; then
        complete_uninstall
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
        log "SOCKS5 proxy installation completed successfully with enhanced IPv6 support!"
    else
        error "SOCKS5 proxy installation failed!"
        echo ""
        echo "You can try these troubleshooting steps:"
        echo "1. Check service logs: journalctl -u $SERVICE_NAME -f"
        echo "2. Test manually: cd $INSTALL_DIR && python3 socks5_server.py --bind 0.0.0.0:$SOCKS5_PORT"
        echo "3. Check firewall: ufw status"
        echo "4. Restart service: systemctl restart $SERVICE_NAME"
        exit 1
    fi
}

# Script usage and help
show_help() {
    echo "SOCKS5 Proxy Server Installation Script"
    echo "========================================"
    echo ""
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  install          Install SOCKS5 proxy server (default)"
    echo "  uninstall        Completely remove SOCKS5 proxy server"
    echo "  remove           Same as uninstall"
    echo "  clean            Same as uninstall"
    echo "  --help, -h       Show this help message"
    echo ""
    echo "Features:"
    echo "  ✓ Enhanced IPv4/IPv6 dual-stack support"
    echo "  ✓ Smart connection routing and fallback"
    echo "  ✓ Username/password authentication"
    echo "  ✓ Automatic firewall configuration"
    echo "  ✓ Systemd service integration"
    echo "  ✓ Complete uninstall functionality"
    echo "  ✓ Comprehensive error handling and logging"
    echo ""
    echo "Examples:"
    echo "  $0                    # Install SOCKS5 proxy"
    echo "  $0 install           # Install SOCKS5 proxy"
    echo "  $0 uninstall         # Remove everything"
    echo ""
    echo "After installation, manage the service with:"
    echo "  systemctl start/stop/restart/status socks5-proxy"
    echo "  journalctl -u socks5-proxy -f"
}

# Handle command line arguments
case "${1:-install}" in
    install|"")
        main "$@"
        ;;
    uninstall|remove|clean)
        main "$@"
        ;;
    --help|-h|help)
        show_help
        ;;
    *)
        echo "Unknown option: $1"
        echo "Use '$0 --help' for usage information"
        exit 1
        ;;
esac
