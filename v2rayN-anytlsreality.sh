#!/usr/bin/env bash
# AnyTLS + Reality (sing-box) 一键部署 - 修复版
# 兼容：Debian/Ubuntu，建议 root 运行
# 版本：2025-09-27（修复：配置格式和客户端兼容性）

set -euo pipefail

# ===== 彩色输出 =====
C0="\033[0m"; C1="\033[1;32m"; C2="\033[1;34m"; C3="\033[1;33m"; C4="\033[1;31m"
log(){ echo -e "${C2}[INFO]${C0} $*"; }
ok(){  echo -e "${C1}[OK]${C0}   $*"; }
wr(){  echo -e "${C3}[WARN]${C0} $*"; }
er(){  echo -e "${C4}[ERROR]${C0} $*"; }

# ===== 路径 =====
SB_BIN="/usr/local/bin/sing-box"
SB_ETC="/etc/sing-box"
SB_CFG="$SB_ETC/config.json"
SB_LOG_DIR="/var/log/sing-box"
SB_LOG="$SB_LOG_DIR/sing-box.log"
SERVICE_FILE="/etc/systemd/system/sing-box.service"
QR_DIR="/root"
V2RAYN_QR="$QR_DIR/v2rayn_anyreality.png"
CLIENT_INFO="$QR_DIR/client_info.txt"
PBK_FILE="$SB_ETC/reality_public.key"
PRV_FILE="$SB_ETC/reality_private.key"

need_root(){ [[ $EUID -eq 0 ]] || { er "请用 root 运行"; exit 1; }; }

detect_os(){
  if [[ -f /etc/debian_version ]]; then OS="debian"
  elif [[ -f /etc/lsb-release ]]; then OS="ubuntu"
  else er "仅支持 Debian/Ubuntu"; exit 1; fi
  ok "检测到系统: $OS"
}

install_deps(){
  log "安装系统依赖..."
  apt-get update -y >/dev/null 2>&1
  apt-get install -y --no-install-recommends \
    curl wget jq unzip ca-certificates openssl qrencode \
    iproute2 iputils-ping net-tools python3 >/dev/null 2>&1
  ok "依赖安装完成"
}

arch_tag(){
  case "$(uname -m)" in
    x86_64|amd64) echo "linux-amd64";;
    aarch64|arm64) echo "linux-arm64";;
    *) er "不支持的架构: $(uname -m)"; exit 1;;
  esac
}

rand_port(){ 
  while :; do 
    p=$(( (RANDOM % 64000) + 1024 ))
    ss -lnt "( sport = :$p )" 2>/dev/null | grep -q :$p || { echo "$p"; return; }
  done
}

urlenc(){ 
  python3 - "$1" <<'PY' 2>/dev/null || printf '%s' "$1" | jq -sRr @uri
import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=''))
PY
}

get_ipv4(){ 
  curl -fsSL4 --max-time 6 ifconfig.me 2>/dev/null || \
  curl -fsSL4 --max-time 6 ip.sb 2>/dev/null || \
  curl -fsSL4 --max-time 6 icanhazip.com 2>/dev/null || \
  ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v 127.0.0.1 | head -n1
}

# ===== 安装 sing-box =====
fetch_singbox(){
  local arch ver url tmp=/tmp/sb.tar.gz
  arch="$(arch_tag)"
  log "安装 sing-box..."
  
  # 获取最新版本
  ver=$(curl -fsSL "https://api.github.com/repos/SagerNet/sing-box/releases/latest" 2>/dev/null | \
        jq -r '.tag_name' || echo "")
  
  if [[ -z "$ver" ]]; then
    wr "无法获取最新版本，使用默认版本 v1.10.0"
    ver="v1.10.0"
  fi
  
  nov="${ver#v}"
  url="https://github.com/SagerNet/sing-box/releases/download/${ver}/sing-box-${nov}-${arch}.tar.gz"
  
  log "下载 sing-box ${ver}..."
  if ! curl -fL --retry 3 --connect-timeout 10 -o "$tmp" "$url"; then
    er "下载失败，请检查网络"
    exit 1
  fi
  
  rm -rf /tmp/sb && mkdir -p /tmp/sb
  tar -xzf "$tmp" -C /tmp/sb
  install -m0755 /tmp/sb/sing-box*/sing-box "$SB_BIN"
  rm -rf /tmp/sb "$tmp"
  
  "$SB_BIN" version && ok "sing-box 安装成功"
}

# ===== 生成参数/密钥 =====
generate_materials(){
  PORT="${PORT:-$(rand_port)}"
  USER="user_$(openssl rand -hex 4)"
  PASS_B64="$(openssl rand -base64 16)"
  PASS_ENC="$(urlenc "$PASS_B64")"
  SHORT_ID="$(openssl rand -hex 8)"
  SNI="${ANYTLS_SNI:-addons.mozilla.org}"
  
  # 生成 Reality 密钥对
  log "生成 Reality 密钥对..."
  local out
  out="$("$SB_BIN" generate reality-keypair 2>/dev/null)" || {
    er "生成密钥对失败"
    exit 1
  }
  
  REALITY_PRIV="$(echo "$out" | awk '/PrivateKey/{print $2}')"
  REALITY_PUB="$(echo "$out" | awk '/PublicKey/{print $2}')"
  
  # 保存密钥
  echo -n "$REALITY_PUB" > "$PBK_FILE"
  echo -n "$REALITY_PRIV" > "$PRV_FILE"
  chmod 600 "$PBK_FILE" "$PRV_FILE"
  
  # 获取公网 IP
  IP4="$(get_ipv4)"
  if [[ -z "$IP4" ]]; then
    er "无法获取公网 IP"
    exit 1
  fi
  
  log "生成的参数："
  echo "  公网IP: $IP4"
  echo "  端口: $PORT"
  echo "  用户: $USER"
  echo "  密码: $PASS_B64"
  echo "  SNI: $SNI"
  echo "  PublicKey: $REALITY_PUB"
  echo "  ShortID: $SHORT_ID"
}

# ===== 写入服务端配置 =====
write_config(){
  mkdir -p "$SB_ETC" "$SB_LOG_DIR"
  
  log "写入服务端配置..."
  cat >"$SB_CFG" <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true,
    "output": "$SB_LOG"
  },
  "inbounds": [
    {
      "type": "anytls",
      "tag": "anytls-in",
      "listen": "::",
      "listen_port": $PORT,
      "users": [
        {
          "name": "$USER",
          "password": "$PASS_B64"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$SNI",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "$SNI",
            "server_port": 443
          },
          "private_key": "$REALITY_PRIV",
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
  ]
}
EOF

  # 验证配置
  if ! "$SB_BIN" check -c "$SB_CFG" 2>/dev/null; then
    er "配置验证失败"
    cat "$SB_CFG"
    exit 1
  fi
  ok "配置验证通过"
}

# ===== 安装 systemd 服务 =====
install_service(){
  log "配置 systemd 服务..."
  cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$SB_ETC
ExecStart=$SB_BIN run -c $SB_CFG
Restart=on-failure
RestartSec=5s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable sing-box >/dev/null 2>&1
  systemctl restart sing-box
  
  sleep 2
  if systemctl is-active --quiet sing-box; then
    ok "服务启动成功"
  else
    er "服务启动失败，查看日志："
    journalctl -u sing-box --no-pager -n 50
    exit 1
  fi
}

# ===== 配置防火墙 =====
open_firewall(){
  log "配置防火墙..."
  
  # UFW
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "$PORT/tcp" 2>/dev/null || true
    ok "UFW 防火墙已配置"
  fi
  
  # iptables
  if command -v iptables >/dev/null 2>&1; then
    iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p udp --dport "$PORT" -j ACCEPT 2>/dev/null || true
    ok "iptables 防火墙已配置"
  fi
  
  # firewalld
  if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$PORT/tcp" 2>/dev/null || true
    firewall-cmd --permanent --add-port="$PORT/udp" 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    ok "firewalld 防火墙已配置"
  fi
  
  wr "请确保云服务商安全组已放行 TCP/UDP $PORT 端口"
}

# ===== 生成客户端配置 =====
print_client_info(){
  local pbk sid pass_enc ip4 name
  
  pbk="$REALITY_PUB"
  sid="$SHORT_ID"
  ip4="$IP4"
  pass_enc="$PASS_ENC"
  name="AnyTLS-Reality-${sid:0:6}"
  
  # 生成 v2rayN 链接
  V2RAYN_LINK="anytls://${pass_enc}@${ip4}:${PORT}?security=reality&sni=${SNI}&pbk=${pbk}&sid=${sid}&fp=chrome#${name}"
  
  # 保存配置信息
  cat >"$CLIENT_INFO" <<EOF
========== AnyTLS + Reality 客户端配置 ==========

服务器地址: $ip4
端口: $PORT
用户名: $USER
密码: $PASS_B64
SNI: $SNI
PublicKey: $pbk
ShortID: $sid
指纹: chrome

---------- v2rayN 配置 ----------
协议类型: anytls
地址: $ip4
端口: $PORT
密码: $PASS_B64
SNI: $SNI
PublicKey: $pbk
ShortID: $sid
指纹: chrome

---------- 一键导入链接 ----------
$V2RAYN_LINK

---------- NekoBox 客户端配置 ----------
{
  "log": {
    "level": "warn"
  },
  "inbounds": [
    {
      "type": "mixed",
      "listen": "127.0.0.1",
      "listen_port": 10808
    }
  ],
  "outbounds": [
    {
      "type": "anytls",
      "server": "$ip4",
      "server_port": $PORT,
      "password": "$PASS_B64",
      "tls": {
        "enabled": true,
        "server_name": "$SNI",
        "reality": {
          "enabled": true,
          "public_key": "$pbk",
          "short_id": "$sid"
        },
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
      }
    }
  ]
}
================================================
EOF

  # 生成二维码
  qrencode -o "$V2RAYN_QR" -s 8 -m 2 "$V2RAYN_LINK" 2>/dev/null || true
  
  # 打印信息
  echo
  cat "$CLIENT_INFO"
  echo
  ok "配置信息已保存到: $CLIENT_INFO"
  [[ -f "$V2RAYN_QR" ]] && ok "二维码已保存到: $V2RAYN_QR"
}

# ===== 诊断功能 =====
diag(){
  echo
  log "===== 诊断信息 ====="
  
  # 服务状态
  echo
  log "服务状态："
  systemctl status sing-box --no-pager -l 2>/dev/null || true
  
  # 端口监听
  echo
  log "端口监听："
  ss -lntp | grep -E ":$(jq -r '.inbounds[0].listen_port' "$SB_CFG" 2>/dev/null)" 2>/dev/null || true
  
  # 最新日志
  echo
  log "最新日志："
  if [[ -f "$SB_LOG" ]]; then
    tail -n 50 "$SB_LOG"
  else
    journalctl -u sing-box -n 50 --no-pager 2>/dev/null || true
  fi
  
  # 配置信息
  echo
  if [[ -f "$SB_CFG" ]]; then
    log "当前配置："
    jq -r '.inbounds[0] | {
      port: .listen_port,
      user: .users[0].name,
      pass: .users[0].password,
      sni: .tls.server_name,
      reality: .tls.reality.enabled
    }' "$SB_CFG" 2>/dev/null || true
  fi
  
  # 网络连通性
  echo
  log "网络连通性测试："
  local sni=$(jq -r '.inbounds[0].tls.server_name' "$SB_CFG" 2>/dev/null)
  if [[ -n "$sni" ]]; then
    echo "测试 SNI ($sni)..."
    curl -I -m 5 "https://$sni" 2>&1 | head -n 3 || true
  fi
}

# ===== 卸载功能 =====
uninstall_all(){
  log "开始卸载 sing-box..."
  
  systemctl stop sing-box 2>/dev/null || true
  systemctl disable sing-box 2>/dev/null || true
  
  rm -f "$SERVICE_FILE"
  systemctl daemon-reload
  
  rm -rf "$SB_ETC" "$SB_LOG_DIR"
  rm -f "$SB_BIN"
  rm -f "$V2RAYN_QR" "$CLIENT_INFO"
  rm -f "$QR_DIR"/nekobox_*.json "$QR_DIR"/nekobox_*.png
  
  ok "卸载完成"
}

# ===== 显示现有配置 =====
show_config(){
  if [[ ! -f "$SB_CFG" ]]; then
    er "未找到配置文件"
    exit 1
  fi
  
  if [[ -f "$CLIENT_INFO" ]]; then
    cat "$CLIENT_INFO"
  else
    log "重新生成客户端配置..."
    IP4="$(get_ipv4)"
    PORT="$(jq -r '.inbounds[0].listen_port' "$SB_CFG")"
    SNI="$(jq -r '.inbounds[0].tls.server_name' "$SB_CFG")"
    SHORT_ID="$(jq -r '.inbounds[0].tls.reality.short_id[0]' "$SB_CFG")"
    PASS_B64="$(jq -r '.inbounds[0].users[0].password' "$SB_CFG")"
    PASS_ENC="$(urlenc "$PASS_B64")"
    USER="$(jq -r '.inbounds[0].users[0].name' "$SB_CFG")"
    REALITY_PUB="$(cat "$PBK_FILE" 2>/dev/null)"
    
    if [[ -z "$REALITY_PUB" ]]; then
      er "无法找到 PublicKey"
      exit 1
    fi
    
    print_client_info
  fi
}

# ===== 主安装流程 =====
main_install(){
  log "开始安装 AnyTLS + Reality..."
  
  need_root
  detect_os
  install_deps
  fetch_singbox
  generate_materials
  write_config
  install_service
  open_firewall
  print_client_info
  
  echo
  ok "===== 安装完成 ====="
  echo
  log "v2rayN 使用说明："
  echo "  1. 添加自定义服务器"
  echo "  2. 选择协议: anytls"
  echo "  3. 核心类型: sing_box"
  echo "  4. 填入上述配置信息"
  echo "  5. 密码只填 $PASS_B64 (不要用户名)"
  echo
  log "如遇问题，运行: $0 --diag"
}

# ===== 命令行参数处理 =====
case "${1:-}" in
  --uninstall|-u)
    uninstall_all
    ;;
  --show|-s)
    show_config
    ;;
  --diag|-d)
    diag
    ;;
  --help|-h)
    echo "使用方法："
    echo "  $0           # 安装"
    echo "  $0 --show    # 显示配置"
    echo "  $0 --diag    # 诊断"
    echo "  $0 --uninstall # 卸载"
    ;;
  *)
    main_install
    ;;
esac