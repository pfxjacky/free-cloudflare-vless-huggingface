import { connect } from 'cloudflare:sockets';

/**
 * 验证地址格式（支持IPv4、IPv6和域名）
 * @param {string} addr
 */
function testAddr(addr){
  // 分离地址和端口
  let host, port;
  
  // 检查是否是IPv6格式 [host]:port
  if (addr.startsWith('[')) {
    const match = addr.match(/^\[([^\]]+)\]:(\d+)$/);
    if (!match) return false;
    host = match[1];
    port = parseInt(match[2]);
  } else {
    // IPv4或域名格式 host:port
    const lastColon = addr.lastIndexOf(':');
    if (lastColon === -1) return false;
    host = addr.substring(0, lastColon);
    port = parseInt(addr.substring(lastColon + 1));
  }
  
  // 验证端口范围
  if (isNaN(port) || port < 1 || port > 65535) {
    return false;
  }
  
  // 验证主机地址
  // IPv4地址
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(host)) {
    const parts = host.split('.');
    return parts.every(part => parseInt(part) >= 0 && parseInt(part) <= 255);
  }
  
  // IPv6地址（简化验证）
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  if (ipv6Regex.test(host)) {
    return true;
  }
  
  // 域名
  const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
  if (domainRegex.test(host) || host === 'localhost') {
    return true;
  }
  
  return false;
}

/**
 * 解析地址为主机和端口
 * @param {string} addr
 */
function parseAddress(addr) {
  let host, port;
  
  // 检查是否是IPv6格式 [host]:port
  if (addr.startsWith('[')) {
    const match = addr.match(/^\[([^\]]+)\]:(\d+)$/);
    if (!match) throw new Error("Invalid IPv6 address format");
    host = match[1];
    port = parseInt(match[2]);
  } else {
    // IPv4或域名格式 host:port
    const lastColon = addr.lastIndexOf(':');
    if (lastColon === -1) throw new Error("Port not specified");
    host = addr.substring(0, lastColon);
    port = parseInt(addr.substring(lastColon + 1));
  }
  
  return { host, port };
}

// 解析 socks5 代理配置（格式: 用户名:密码@IP:端口）
function parseSocks5Proxy(proxyStr) {
  /**
   * 解析 socks5 代理配置
   *
   * 支持以下几种格式：
   * - username:password@host:port
   * - username@host:port
   * - host:port
   * - host （默认为端口 1080）
   *
   * 其中 host 可以是域名、IPv4，或 IPv6（形如 [2001:db8::1]:1080）。
   */
  let user = "";
  let pass = "";
  let hostPort = proxyStr;
  // 提取凭据部分（若存在）
  const atIndex = proxyStr.lastIndexOf("@");
  if (atIndex !== -1) {
    const credPart = proxyStr.substring(0, atIndex);
    hostPort = proxyStr.substring(atIndex + 1);
    // 用户名与密码以冒号分隔，可只提供用户名
    const colonIndex = credPart.indexOf(":");
    if (colonIndex !== -1) {
      user = credPart.substring(0, colonIndex);
      pass = credPart.substring(colonIndex + 1);
    } else {
      user = credPart;
    }
  }
  let host;
  let port;
  // IPv6 代理地址形式 [host]:port
  if (hostPort.startsWith("[")) {
    const match = hostPort.match(/^\[([^\]]+)\](?::(\d+))?$/);
    if (!match) throw new Error("Invalid socks5 proxy address format");
    host = match[1];
    port = match[2] ? parseInt(match[2]) : 1080;
    // 如果是压缩格式的IPv6（包含 ::），需要展开为完整8组地址
    if (host.includes("::")) {
      host = expandIPv6Address(host);
    }
  } else {
    // IPv4 或域名
    const lastColon = hostPort.lastIndexOf(":");
    if (lastColon === -1) {
      // 未指定端口，使用默认端口 1080
      host = hostPort;
      port = 1080;
    } else {
      host = hostPort.substring(0, lastColon);
      const portStr = hostPort.substring(lastColon + 1);
      port = portStr ? parseInt(portStr) : 1080;
    }
  }
  // 如果地址看起来是IPv6（包含冒号，但不是域名），尝试展开压缩格式
  // 例如 2602:f93b:131:c001::1054 -> 2602:f93b:0131:c001:0000:0000:0000:1054
  if (host && host.includes(':') && !host.match(/^[0-9A-Za-z\-]+\.[0-9A-Za-z\.-]+$/)) {
    if (host.includes('::')) {
      host = expandIPv6Address(host);
    }
  }
  return { username: user, password: pass, host: host, port: port };
}

/**
 * 检查字符串是否为IPv6地址
 * @param {string} str
 */
function isIPv6(str) {
  // 非域名且包含冒号认为是IPv6
  return str.includes(':') && !/^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(str);
}

/**
 * 展开IPv6地址的简写形式
 * @param {string} addr
 * @returns {string}
 */
function expandIPv6Address(addr) {
  // 如果已经是完整的 IPv6，则返回原始值
  if (!addr.includes('::')) {
    // 规范每个分段为4位
    return addr.split(':').map(part => part.padStart(4, '0')).join(':');
  }
  const parts = addr.split('::');
  const left = parts[0] ? parts[0].split(':') : [];
  const right = parts[1] ? parts[1].split(':') : [];
  const missing = 8 - (left.length + right.length);
  const zeros = new Array(missing).fill('0');
  const fullParts = [...left, ...zeros, ...right].map(part => part.padStart(4, '0'));
  return fullParts.join(':');
}

// 将 IPv6 地址转换为 16 字节数组，用于 SOCKS5 IPv6 地址类型
function ipv6ToBytes(ipv6) {
  // 移除可能的方括号
  ipv6 = ipv6.replace(/^\[|\]$/g, '');
  // 如果是压缩格式则展开
  const full = ipv6.includes('::') ? expandIPv6Address(ipv6) : ipv6;
  const parts = full.split(':');
  if (parts.length !== 8) {
    throw new Error('Invalid IPv6 address');
  }
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const value = parseInt(parts[i], 16);
    if (isNaN(value) || value < 0 || value > 0xffff) {
      throw new Error('Invalid IPv6 segment');
    }
    bytes[i * 2] = (value >> 8) & 0xff;
    bytes[i * 2 + 1] = value & 0xff;
  }
  return bytes;
}

// 简单的 IPv4 判断
function isIPv4(str) {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  return ipv4Regex.test(str);
}

// 将 IPv4 地址转换为 NAT64 IPv6 地址
// 通过指定前缀（默认为标准 NAT64 前缀 64:ff9b::），将 IPv4 嵌入 IPv6
// 返回结果默认包含方括号，例如 [64:ff9b::c000:0221]
function convertIPv4ToNAT64IPv6(ipv4Address, options = {}) {
  const {
    prefix = '64:ff9b::',
    withBrackets = true,
  } = options;
  // 拆分 IPv4 并转换为十六进制
  const parts = ipv4Address.trim().split('.');
  if (parts.length !== 4) {
    throw new Error('Invalid IPv4 address');
  }
  const hexParts = parts.map(part => {
    const num = Number(part);
    if (!/^\d+$/.test(part) || isNaN(num) || num < 0 || num > 255) {
      throw new Error(`Invalid IPv4 segment: ${part}`);
    }
    return num.toString(16).padStart(2, '0');
  });
  const ipv6Tail = `${hexParts[0]}${hexParts[1]}:${hexParts[2]}${hexParts[3]}`.toLowerCase();
  const fullIPv6 = `${prefix}${ipv6Tail}`;
  return withBrackets ? `[${fullIPv6}]` : fullIPv6;
}

// 解析域名为 NAT64 IPv6 地址：
// 通过 DNS-over-HTTPS 获取域名的 A 记录（IPv4），
// 然后转换为 NAT64 IPv6。若获取失败则抛出异常。
async function resolveDomainToNAT64IPv6(domain) {
  // 使用公共 DNS-over-HTTPS 接口解析 A 记录
  const dnsUrl = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`;
  const resp = await fetch(dnsUrl, { headers: { accept: 'application/dns-json' } });
  if (!resp.ok) {
    throw new Error(`DNS request failed with status code: ${resp.status}`);
  }
  const data = await resp.json();
  const answer = data && data.Answer ? data.Answer.find(r => r.type === 1 && r.data) : null;
  if (!answer) {
    throw new Error(`No valid A record found for ${domain}`);
  }
  const ipv4 = answer.data;
  return convertIPv4ToNAT64IPv6(ipv4);
}

// 建立 socks5 代理连接，通过代理连接目标地址
async function connectViaSocks5(proxyConf, targetHost, targetPort) {
  // 通过 Cloudflare connect API 连接 socks5 代理
  // 当代理主机为 IPv6 地址时，需使用方括号包围，避免解析错误
  let connectHost = proxyConf.host;
  try {
    if (connectHost && isIPv6(connectHost)) {
      // 如果未包含方括号，则添加，以确保 Cloudflare 正确解析 IPv6
      if (!connectHost.startsWith('[') && !connectHost.endsWith(']')) {
        connectHost = `[${connectHost}]`;
      }
    }
  } catch (_) {
    // 忽略 isIPv6 检测错误，直接使用原始 host
  }
  const sock = connect({ hostname: connectHost, port: proxyConf.port, secureTransport: "off" });
  // 获取写入器和读取器
  const writer = sock.writable.getWriter();
  const reader = sock.readable.getReader();

  try {
    // 1. 发送握手，支持用户名/密码或无认证
    // 根据是否提供用户名/密码决定认证方法
    // 当提供了用户名或密码时，只声明用户名密码认证（0x02）
    // 否则声明不认证（0x00）。这样可避免服务端选择不期望的方式。
    let methods;
    if (proxyConf.username || proxyConf.password) {
      methods = [0x02];
    } else {
      methods = [0x00];
    }
    const greeting = new Uint8Array(2 + methods.length);
    greeting[0] = 0x05; // socks version
    greeting[1] = methods.length;
    for (let i = 0; i < methods.length; i++) {
      greeting[2 + i] = methods[i];
    }
    await writer.write(greeting);

    // 读取服务器选择的认证方法
    const methodResp = await reader.read();
    if (!methodResp || !methodResp.value || methodResp.value.length < 2) {
      throw new Error("SOCKS5: no response to greeting");
    }
    const chosenMethod = methodResp.value[1];
    if (chosenMethod === 0xFF) {
      throw new Error("SOCKS5: no acceptable authentication methods");
    }

    // 2. 如果选择用户名密码认证，发送认证包
    if (chosenMethod === 0x02) {
      const enc = new TextEncoder();
      const uBytes = enc.encode(proxyConf.username || "");
      const pBytes = enc.encode(proxyConf.password || "");
      const authReq = new Uint8Array(3 + uBytes.length + pBytes.length);
      authReq[0] = 0x01; // subnegotiation version
      authReq[1] = uBytes.length;
      authReq.set(uBytes, 2);
      authReq[2 + uBytes.length] = pBytes.length;
      authReq.set(pBytes, 3 + uBytes.length);
      await writer.write(authReq);
      const authResp = await reader.read();
      if (!authResp || !authResp.value || authResp.value.length < 2 || authResp.value[1] !== 0x00) {
        throw new Error("SOCKS5: authentication failed");
      }
    }

    // 3. 发送 CONNECT 请求
    let req;
    if (isIPv4(targetHost)) {
      // IPv4: ATYP 0x01
      const parts = targetHost.split(".").map((p) => parseInt(p));
      req = new Uint8Array(4 + 4 + 2);
      req[0] = 0x05; // SOCKS version
      req[1] = 0x01; // CONNECT
      req[2] = 0x00; // reserved
      req[3] = 0x01; // IPv4 type
      req.set(parts, 4);
      req[8] = (targetPort >> 8) & 0xff;
      req[9] = targetPort & 0xff;
    } else if (isIPv6(targetHost)) {
      // IPv6: ATYP 0x04
      const ipv6Bytes = ipv6ToBytes(targetHost);
      req = new Uint8Array(4 + 16 + 2);
      req[0] = 0x05;
      req[1] = 0x01;
      req[2] = 0x00;
      req[3] = 0x04; // IPv6 type
      req.set(ipv6Bytes, 4);
      req[20] = (targetPort >> 8) & 0xff;
      req[21] = targetPort & 0xff;
    } else {
      // Domain name: ATYP 0x03
      const enc = new TextEncoder();
      const hostBytes = enc.encode(targetHost);
      req = new Uint8Array(5 + hostBytes.length + 2);
      req[0] = 0x05;
      req[1] = 0x01;
      req[2] = 0x00;
      req[3] = 0x03; // domain
      req[4] = hostBytes.length;
      req.set(hostBytes, 5);
      req[5 + hostBytes.length] = (targetPort >> 8) & 0xff;
      req[6 + hostBytes.length] = targetPort & 0xff;
    }
    await writer.write(req);

    // 读取 CONNECT 响应头部并解析回复码与地址类型
    const resp1 = await reader.read();
    if (!resp1 || !resp1.value || resp1.value.length < 4) {
      throw new Error("SOCKS5: connect response too short");
    }
    const respVal1 = resp1.value;
    const replyCode = respVal1[1];
    if (replyCode !== 0x00) {
      throw new Error("SOCKS5: connect request failed, code " + replyCode);
    }
    const addrType = respVal1[3];
    let addrLen; // bytes of address + port to skip
    // Determine how many address bytes to skip based on address type
    if (addrType === 0x01) {
      // IPv4: 4 bytes address + 2 bytes port
      addrLen = 4 + 2;
    } else if (addrType === 0x03) {
      // domain: first byte is length of domain, followed by domain and 2 bytes port
      let respBytes = respVal1;
      if (respBytes.length < 5) {
        // need to read at least one more byte for domain length
        const extra = await reader.read();
        if (!extra || !extra.value || extra.value.length < 1) {
          throw new Error("SOCKS5: unable to read domain length");
        }
        // combine existing bytes and extra bytes
        respBytes = new Uint8Array([...respBytes, ...extra.value]);
      }
      const domainLen = respBytes[4];
      addrLen = 1 + domainLen + 2;
    } else if (addrType === 0x04) {
      // IPv6: 16 bytes address + 2 bytes port
      addrLen = 16 + 2;
    } else {
      throw new Error("SOCKS5: unknown address type " + addrType);
    }
    // 已经读取的响应字节中，除了前4个字节，还有一部分地址内容
    let consumed = respVal1.length - 4;
    let toSkip = addrLen - consumed;
    while (toSkip > 0) {
      const chunk = await reader.read();
      if (!chunk || !chunk.value) {
        throw new Error("SOCKS5: unable to read full connect response");
      }
      toSkip -= chunk.value.length;
    }

    // 完成 SOCKS5 握手，释放读取器和写入器锁
    reader.releaseLock();
    writer.releaseLock();
    return sock;
  } catch (err) {
    // 出现错误时关闭连接
    try { reader.releaseLock(); } catch (_) {}
    try { writer.releaseLock(); } catch (_) {}
    try { await sock.close(); } catch (_) {}
    throw err;
  }
}

export default {

  /**
   * @param {{ headers: { get: (arg0: string) => any; }; }} request
   * @param {{ }} env
   * @param {{ waitUntil: (arg0: Promise<void>) => void; }} ctx
   */
  async fetch(request, env, ctx) {
    try {

      // 密码：优先从环境变量 PASSWORD 读取，否则使用默认值
      const passwd = (env && env.PASSWORD) ? env.PASSWORD : "testPASSword"

      // 从 header 读取密码并验证
      const pwd = request.headers.get("X-Password")
      if (passwd !== "" && passwd != pwd) {
        return new Response("密码错误", { status: 400 })
      }

      // 从 header 读取目标地址
      const targetAddr = request.headers.get("X-Target")
      
      if (!targetAddr || !testAddr(targetAddr)) {
        return new Response("访问目标错误", { status: 400 })
      }

      const upgrade = request.headers.get('Upgrade')?.toLowerCase();
      if (upgrade !== 'websocket') {
        return new Response("不支持websocket", { status: 400 });
      }

      const [client, ws] = Object.values(new WebSocketPair());

      // 解析地址
      const { host, port } = parseAddress(targetAddr);

      // 接受WebSocket连接
      ws.accept();

      // 建立 TCP 连接
      let socket;
      // 如果存在 socks5 环境变量，则通过代理连接目标地址
      if (env && env.socks5) {
        try {
          const proxyConf = parseSocks5Proxy(env.socks5);
          // 如果 socks5 主机是域名（既不是 IPv4 也不是 IPv6），尝试使用 NAT64 解析为 IPv6
          if (proxyConf.host && !isIPv4(proxyConf.host) && !isIPv6(proxyConf.host)) {
            try {
              const nat64IPv6 = await resolveDomainToNAT64IPv6(proxyConf.host);
              // 移除方括号，供 connectViaSocks5 使用
              proxyConf.host = nat64IPv6.replace(/^\[|\]$/g, '');
            } catch (e) {
              console.error(`NAT64 resolution failed for SOCKS5 host ${proxyConf.host}:`, e);
            }
          }
          socket = await connectViaSocks5(proxyConf, host, port);
        } catch (err) {
          console.error("SOCKS5 proxy connect failed:", err);
          return new Response("SOCKS5 proxy connect failed: " + (err && err.message ? err.message : err), { status: 500 });
        }
      } else {
        socket = connect({ hostname: host, port: port });
      }

      // 处理错误
      let hasError = false;

      // TCP -> WebSocket
      const tcpToWs = socket.readable.pipeTo(
        new WritableStream({
          write(chunk) {
            try {
              ws.send(chunk);
            } catch (error) {
              console.error("发送到WebSocket失败:", error);
              hasError = true;
            }
          },
          close() {
            if (!hasError) {
              try {
                ws.close(1000, "TCP connection closed");
              } catch {}
            }
          },
          abort(err) {
            console.error("TCP读取中止:", err);
            hasError = true;
            try {
              ws.close(1011, "TCP error");
            } catch {}
          }
        })
      ).catch((err) => {
        console.error("TCP到WebSocket管道错误:", err);
        if (!hasError) {
          try {
            ws.close(1011, "Pipe error");
          } catch {}
        }
      });

      // WebSocket -> TCP
      const wsToTcp = new ReadableStream({
        start(controller) {
          ws.addEventListener("message", (event) => {
            try {
              if (event.data instanceof ArrayBuffer) {
                controller.enqueue(new Uint8Array(event.data));
              }
            } catch (err) {
              console.error("处理WebSocket消息失败:", err);
              controller.error(err);
            }
          });
          
          ws.addEventListener("close", () => {
            try {
              controller.close();
            } catch {}
          });
          
          ws.addEventListener("error", (err) => {
            console.error("WebSocket错误:", err);
            controller.error(new Error("WebSocket error"));
          });
        }
      }).pipeTo(socket.writable).catch((err) => {
        console.error("WebSocket到TCP管道错误:", err);
        hasError = true;
        try {
          ws.close(1011, "Write error");
        } catch {}
      });

      // 确保两个管道都完成
      ctx.waitUntil(Promise.all([tcpToWs, wsToTcp]).catch(() => {}));

      return new Response(null, {
        status: 101,
        webSocket: client
      });

    } catch (error) {
      console.error("处理请求失败:", error);
      return new Response(error.message || "Internal Server Error", { status: 500 });
    }
  }
}