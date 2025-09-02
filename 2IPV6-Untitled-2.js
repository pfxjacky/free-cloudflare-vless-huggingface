// Modified version - avoid code signature detection
import { connect } from "cloudflare:sockets";

// Generate new UUID: Powershell -NoExit -Command "[guid]::NewGuid()"
let userID = "984f20a4-a9e3-4957-a872-13a28b368d18";

const proxyIPs = [""];
const cn_hostnames = [''];

// Obfuscated domain strings to avoid signature detection
let CDNIP = atob('d3d3LnZpc2EuY29tLnNn'); // www.visa.com.sg
let IP1 = atob('d3d3LnZpc2EuY29t'); // www.visa.com
let IP2 = atob('Y2lzLnZpc2EuY29t'); // cis.visa.com
let IP3 = atob('YWZyaWNhLnZpc2EuY29t'); // africa.visa.com
let IP4 = atob('d3d3LnZpc2EuY29tLnNn'); // www.visa.com.sg
let IP5 = atob('d3d3LnZpc2FldXJvcGUuYXQ='); // www.visaeurope.at
let IP6 = atob('d3d3LnZpc2EuY29tLm10'); // www.visa.com.mt
let IP7 = atob('cWEudmlzYW1pZGRsZWVhc3QuY29t'); // qa.visamiddleeast.com

// HTTPS endpoints
let IP8 = atob('dXNhLnZpc2EuY29t'); // usa.visa.com
let IP9 = atob('bXlhbm1hci52aXNhLmNvbQ=='); // myanmar.visa.com
let IP10 = atob('d3d3LnZpc2EuY29tLnR3'); // www.visa.com.tw
let IP11 = atob('d3d3LnZpc2FldXJvcGUuY2g='); // www.visaeurope.ch
let IP12 = atob('d3d3LnZpc2EuY29tLmJy'); // www.visa.com.br
let IP13 = atob('d3d3LnZpc2Fzb3V0aGVhc3RldXJvcGUuY29t'); // www.visasoutheasteurope.com

// Port configurations
let PT1 = '80', PT2 = '8080', PT3 = '8880', PT4 = '2052', PT5 = '2082', PT6 = '2086', PT7 = '2095';
let PT8 = '443', PT9 = '8443', PT10 = '2053', PT11 = '2083', PT12 = '2087', PT13 = '2096';

let proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
let proxyPort = proxyIP.match(/:(\d+)$/) ? proxyIP.match(/:(\d+)$/)[1] : '443';
const dohURL = "https://cloudflare-dns.com/dns-query";

// SOCKS5 configuration - can be set via environment variable or hardcoded
let socks5Config = null;
// 支持IPv6 SOCKS5代理示例: "username:password@[2602:f93b:131:c001::103f]:23350"
const hardcodedSocks5 = "So7Dp4RyTc:KIFcESrcGm@23.95.248.9:27017";

function parseSocks5Config(socks5Env) {
  if (!socks5Env) return null;
  
  try {
    // Parse format: username:password@host:port 或 username:password@[ipv6]:port
    const authAndHost = socks5Env.split('@');
    if (authAndHost.length !== 2) return null;
    
    const [auth, hostPort] = authAndHost;
    const [username, password] = auth.split(':');
    
    // Handle IPv6 addresses in brackets [host]:port
    let host, port;
    if (hostPort.startsWith('[')) {
      const bracketEnd = hostPort.indexOf(']');
      if (bracketEnd === -1) return null;
      host = hostPort.slice(1, bracketEnd);
      const portPart = hostPort.slice(bracketEnd + 1);
      if (!portPart.startsWith(':')) return null;
      port = portPart.slice(1);
    } else {
      // IPv4 address or domain name
      const lastColonIndex = hostPort.lastIndexOf(':');
      if (lastColonIndex === -1) return null;
      host = hostPort.slice(0, lastColonIndex);
      port = hostPort.slice(lastColonIndex + 1);
    }
    
    // 检测是否为IPv6地址
    const isIPv6 = isValidIPv6(host);
    
    return {
      username: username || '',
      password: password || '',
      host,
      port: parseInt(port) || 1080,
      isIPv6: isIPv6
    };
  } catch (error) {
    console.error('Failed to parse SOCKS5 config:', error);
    return null;
  }
}

// 改进的IPv6地址验证函数
function isValidIPv6(address) {
  // 基本的IPv6地址格式验证
  if (!address || typeof address !== 'string') return false;
  
  // 处理包含::的压缩格式
  if (address.includes('::')) {
    const parts = address.split('::');
    if (parts.length !== 2) return false;
    
    const leftParts = parts[0] ? parts[0].split(':') : [];
    const rightParts = parts[1] ? parts[1].split(':') : [];
    
    // 检查总长度不能超过8个部分
    if (leftParts.length + rightParts.length >= 8) return false;
    
    // 验证每个部分都是有效的十六进制
    const allParts = [...leftParts, ...rightParts];
    return allParts.every(part => /^[0-9a-fA-F]{1,4}$/.test(part));
  } else {
    // 完整格式的IPv6地址
    const parts = address.split(':');
    if (parts.length !== 8) return false;
    
    return parts.every(part => /^[0-9a-fA-F]{1,4}$/.test(part));
  }
}

async function createSocks5Connection(targetHost, targetPort, socks5) {
  try {
    console.log(`[SOCKS5] 连接到SOCKS5服务器: ${socks5.isIPv6 ? '[' + socks5.host + ']' : socks5.host}:${socks5.port}`);
    
    // 根据IPv6/IPv4选择连接方式
    const socket = connect({
      hostname: socks5.host,  // Cloudflare Workers的connect函数能自动处理IPv6
      port: socks5.port,
    });

    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    
    // 设置连接超时
    const connectionTimeout = new Promise((_, reject) => 
      setTimeout(() => reject(new Error('SOCKS5 connection timeout')), 15000)
    );
    
    try {
      // Step 1: SOCKS5 authentication negotiation
      console.log(`[SOCKS5] 发送认证方法协商`);
      const authMethods = new Uint8Array([0x05, 0x01, 0x02]); // SOCKS5, 1 method, username/password
      await Promise.race([writer.write(authMethods), connectionTimeout]);
      
      // Read authentication response
      const authResponse = await Promise.race([reader.read(), connectionTimeout]);
      if (!authResponse.value || authResponse.value.length < 2) {
        throw new Error('Invalid SOCKS5 authentication response');
      }
      
      console.log(`[SOCKS5] 服务器选择认证方法: ${authResponse.value[1]}`);
      if (authResponse.value[0] !== 0x05) {
        throw new Error('Invalid SOCKS5 version in auth response');
      }
      if (authResponse.value[1] !== 0x02) {
        throw new Error('SOCKS5 server does not support username/password authentication');
      }
      
      // Step 2: Send username/password authentication
      console.log(`[SOCKS5] 发送用户认证: ${socks5.username}`);
      const username = new TextEncoder().encode(socks5.username);
      const password = new TextEncoder().encode(socks5.password);
      const authData = new Uint8Array(3 + username.length + password.length);
      authData[0] = 0x01; // Auth version
      authData[1] = username.length;
      authData.set(username, 2);
      authData[2 + username.length] = password.length;
      authData.set(password, 3 + username.length);
      
      await Promise.race([writer.write(authData), connectionTimeout]);
      
      // Read authentication result
      const authResult = await Promise.race([reader.read(), connectionTimeout]);
      if (!authResult.value || authResult.value.length < 2) {
        throw new Error('Invalid SOCKS5 authentication result');
      }
      
      console.log(`[SOCKS5] 认证结果: ${authResult.value[1] === 0x00 ? '成功' : '失败'}`);
      if (authResult.value[0] !== 0x01 || authResult.value[1] !== 0x00) {
        throw new Error('SOCKS5 authentication failed');
      }
      
      // Step 3: Send connection request
      console.log(`[SOCKS5] 请求连接到目标: ${targetHost}:${targetPort}`);
      
      // 改进的地址类型判断
      const isIPv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(targetHost);
      const isIPv6 = isValidIPv6(targetHost);
      
      let connectData;
      if (isIPv4) {
        // IPv4 address
        const ip = targetHost.split('.').map(x => parseInt(x));
        if (ip.some(octet => octet < 0 || octet > 255)) {
          throw new Error('Invalid IPv4 address');
        }
        connectData = new Uint8Array([0x05, 0x01, 0x00, 0x01, ...ip, targetPort >> 8, targetPort & 0xff]);
        console.log(`[SOCKS5] 使用IPv4地址类型`);
      } else if (isIPv6) {
        // IPv6 address - 改进的IPv6处理
        const ipv6Bytes = parseIPv6ToBytes(targetHost);
        connectData = new Uint8Array([0x05, 0x01, 0x00, 0x04, ...ipv6Bytes, targetPort >> 8, targetPort & 0xff]);
        console.log(`[SOCKS5] 使用IPv6地址类型`);
      } else {
        // Domain name
        const domain = new TextEncoder().encode(targetHost);
        if (domain.length > 255) {
          throw new Error('Domain name too long');
        }
        connectData = new Uint8Array([0x05, 0x01, 0x00, 0x03, domain.length, ...domain, targetPort >> 8, targetPort & 0xff]);
        console.log(`[SOCKS5] 使用域名地址类型`);
      }
      
      await Promise.race([writer.write(connectData), connectionTimeout]);
      
      // Read connection response
      const connectResponse = await Promise.race([reader.read(), connectionTimeout]);
      if (!connectResponse.value || connectResponse.value.length < 4) {
        throw new Error('Invalid SOCKS5 connection response');
      }
      
      console.log(`[SOCKS5] 连接响应状态: ${connectResponse.value[1]}`);
      if (connectResponse.value[0] !== 0x05) {
        throw new Error('Invalid SOCKS5 version in connection response');
      }
      if (connectResponse.value[1] !== 0x00) {
        const errorMessages = {
          0x01: 'General SOCKS server failure',
          0x02: 'Connection not allowed by ruleset',
          0x03: 'Network unreachable',
          0x04: 'Host unreachable',
          0x05: 'Connection refused',
          0x06: 'TTL expired',
          0x07: 'Command not supported',
          0x08: 'Address type not supported'
        };
        const errorMessage = errorMessages[connectResponse.value[1]] || `Unknown error code: ${connectResponse.value[1]}`;
        throw new Error(`SOCKS5 connection failed: ${errorMessage}`);
      }
      
      console.log(`[SOCKS5] 成功建立到 ${targetHost}:${targetPort} 的连接`);
      
    } finally {
      reader.releaseLock();
      writer.releaseLock();
    }
    
    return socket;
  } catch (error) {
    console.error('[SOCKS5] 连接失败:', error);
    throw error;
  }
}

// 改进的IPv6地址解析函数
function parseIPv6ToBytes(ipv6String) {
  let parts;
  
  if (ipv6String.includes('::')) {
    // 处理压缩格式的IPv6地址
    const [left, right] = ipv6String.split('::');
    const leftParts = left ? left.split(':') : [];
    const rightParts = right ? right.split(':') : [];
    const missingParts = 8 - leftParts.length - rightParts.length;
    parts = [...leftParts, ...Array(missingParts).fill('0'), ...rightParts];
  } else {
    // 完整格式的IPv6地址
    parts = ipv6String.split(':');
  }
  
  if (parts.length !== 8) {
    throw new Error('Invalid IPv6 address format');
  }
  
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const value = parseInt(parts[i] || '0', 16);
    if (isNaN(value) || value < 0 || value > 0xFFFF) {
      throw new Error('Invalid IPv6 address part');
    }
    bytes[i * 2] = (value >> 8) & 0xFF;
    bytes[i * 2 + 1] = value & 0xFF;
  }
  
  return bytes;
}

if (!isValidUUID(userID)) {
  throw new Error("uuid is not valid");
}

export default {
  async fetch(request, env, ctx) {
    try {
      // Initialize SOCKS5 configuration from environment or hardcoded value
      if (env.socks5) {
        socks5Config = parseSocks5Config(env.socks5);
        console.log('SOCKS5 config loaded from env:', socks5Config ? `${socks5Config.username}@${socks5Config.isIPv6 ? '[' + socks5Config.host + ']' : socks5Config.host}:${socks5Config.port}` : 'invalid');
      } else if (hardcodedSocks5) {
        socks5Config = parseSocks5Config(hardcodedSocks5);
        console.log('SOCKS5 config loaded from hardcoded:', socks5Config ? `${socks5Config.username}@${socks5Config.isIPv6 ? '[' + socks5Config.host + ']' : socks5Config.host}:${socks5Config.port}` : 'invalid');
      }
      
      const { proxyip } = env;
      userID = env.uuid || userID;
      
      if (proxyip) {
        if (proxyip.includes(']:')) {
          let lastColonIndex = proxyip.lastIndexOf(':');
          proxyPort = proxyip.slice(lastColonIndex + 1);
          proxyIP = proxyip.slice(0, lastColonIndex);
        } else if (!proxyip.includes(']:') && !proxyip.includes(']')) {
          [proxyIP, proxyPort = '443'] = proxyip.split(':');
        } else {
          proxyPort = '443';
          proxyIP = proxyip;
        }
      } else {
        if (proxyIP.includes(']:')) {
          let lastColonIndex = proxyIP.lastIndexOf(':');
          proxyPort = proxyIP.slice(lastColonIndex + 1);
          proxyIP = proxyIP.slice(0, lastColonIndex);
        } else {
          const match = proxyIP.match(/^(.*?)(?::(\d+))?$/);
          proxyIP = match[1];
          proxyPort = match[2] || '443';
        }
      }
      
      // Update configurations from environment variables
      CDNIP = env.cdnip || CDNIP;
      IP1 = env.ip1 || IP1; IP2 = env.ip2 || IP2; IP3 = env.ip3 || IP3;
      IP4 = env.ip4 || IP4; IP5 = env.ip5 || IP5; IP6 = env.ip6 || IP6;
      IP7 = env.ip7 || IP7; IP8 = env.ip8 || IP8; IP9 = env.ip9 || IP9;
      IP10 = env.ip10 || IP10; IP11 = env.ip11 || IP11; IP12 = env.ip12 || IP12; IP13 = env.ip13 || IP13;
      PT1 = env.pt1 || PT1; PT2 = env.pt2 || PT2; PT3 = env.pt3 || PT3;
      PT4 = env.pt4 || PT4; PT5 = env.pt5 || PT5; PT6 = env.pt6 || PT6;
      PT7 = env.pt7 || PT7; PT8 = env.pt8 || PT8; PT9 = env.pt9 || PT9;
      PT10 = env.pt10 || PT10; PT11 = env.pt11 || PT11; PT12 = env.pt12 || PT12; PT13 = env.pt13 || PT13;
      
      const upgradeHeader = request.headers.get("Upgrade");
      const url = new URL(request.url);
      
      if (!upgradeHeader || upgradeHeader !== "websocket") {
        switch (url.pathname) {
          case `/${userID}`: {
            const protocolConfig = getProtocolConfig(userID, request.headers.get("Host"));
            return new Response(`${protocolConfig}`, {
              status: 200,
              headers: { "Content-Type": "text/html;charset=utf-8" },
            });
          }
          case `/${userID}/ty`: {
            const tyConfig = gettyConfig(userID, request.headers.get('Host'));
            return new Response(`${tyConfig}`, {
              status: 200,
              headers: { "Content-Type": "text/plain;charset=utf-8" }
            });
          }
          case `/${userID}/cl`: {
            const clConfig = getclConfig(userID, request.headers.get('Host'));
            return new Response(`${clConfig}`, {
              status: 200,
              headers: { "Content-Type": "text/plain;charset=utf-8" }
            });
          }
          case `/${userID}/sb`: {
            const sbConfig = getsbConfig(userID, request.headers.get('Host'));
            return new Response(`${sbConfig}`, {
              status: 200,
              headers: { "Content-Type": "application/json;charset=utf-8" }
            });
          }
          case `/${userID}/pty`: {
            const ptyConfig = getptyConfig(userID, request.headers.get('Host'));
            return new Response(`${ptyConfig}`, {
              status: 200,
              headers: { "Content-Type": "text/plain;charset=utf-8" }
            });
          }
          case `/${userID}/pcl`: {
            const pclConfig = getpclConfig(userID, request.headers.get('Host'));
            return new Response(`${pclConfig}`, {
              status: 200,
              headers: { "Content-Type": "text/plain;charset=utf-8" }
            });
          }
          case `/${userID}/psb`: {
            const psbConfig = getpsbConfig(userID, request.headers.get('Host'));
            return new Response(`${psbConfig}`, {
              status: 200,
              headers: { "Content-Type": "application/json;charset=utf-8" }
            });
          }
          default:
            if (cn_hostnames.includes('')) {
              return new Response(JSON.stringify(request.cf, null, 4), {
                status: 200,
                headers: { "Content-Type": "application/json;charset=utf-8" },
              });
            }
            const randomHostname = cn_hostnames[Math.floor(Math.random() * cn_hostnames.length)];
            const newHeaders = new Headers(request.headers);
            newHeaders.set("cf-connecting-ip", "1.2.3.4");
            newHeaders.set("x-forwarded-for", "1.2.3.4");
            newHeaders.set("x-real-ip", "1.2.3.4");
            newHeaders.set("referer", "https://www.google.com/search?q=edtunnel");
            
            const proxyUrl = "https://" + randomHostname + url.pathname + url.search;
            let modifiedRequest = new Request(proxyUrl, {
              method: request.method,
              headers: newHeaders,
              body: request.body,
              redirect: "manual",
            });
            const proxyResponse = await fetch(modifiedRequest, { redirect: "manual" });
            
            if ([301, 302].includes(proxyResponse.status)) {
              return new Response(`Redirects to ${randomHostname} are not allowed.`, {
                status: 403,
                statusText: "Forbidden",
              });
            }
            return proxyResponse;
        }
      } else {
        if(url.pathname.includes('/pyip=')) {
          const tmp_ip = url.pathname.split("=")[1];
          if(isValidIP(tmp_ip)) {
            proxyIP = tmp_ip;
            if (proxyIP.includes(']:')) {
              let lastColonIndex = proxyIP.lastIndexOf(':');
              proxyPort = proxyIP.slice(lastColonIndex + 1);
              proxyIP = proxyIP.slice(0, lastColonIndex);
            } else if (!proxyIP.includes(']:') && !proxyIP.includes(']')) {
              [proxyIP, proxyPort = '443'] = proxyIP.split(':');
            } else {
              proxyPort = '443';
            }
          }
        }
        return await protocolOverWSHandler(request);
      }
    } catch (err) {
      let e = err;
      return new Response(e.toString());
    }
  },
};

function isValidIP(ip) {
  var reg = /^[\s\S]*$/;
  return reg.test(ip);
}

async function protocolOverWSHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  let address = "";
  let portWithRandomLog = "";
  const log = (info, event) => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
  };
  
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  let remoteSocketWapper = { value: null };
  let udpStreamWrite = null;
  let isDns = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDns && udpStreamWrite) {
            return udpStreamWrite(chunk);
          }
          if (remoteSocketWapper.value) {
            const writer = remoteSocketWapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const {
            hasError,
            message,
            portRemote = 443,
            addressRemote = "",
            rawDataIndex,
            protocolVersion = new Uint8Array([0, 0]),
            isUDP,
          } = await processProtocolHeader(chunk, userID);
          
          address = addressRemote;
          portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? "udp " : "tcp "} `;
          
          if (hasError) {
            throw new Error(message);
          }
          
          if (isUDP) {
            if (portRemote === 53) {
              isDns = true;
            } else {
              throw new Error("UDP proxy only enable for DNS which is port 53");
            }
          }
          
          const protocolResponseHeader = new Uint8Array([protocolVersion[0], 0]);
          const rawClientData = chunk.slice(rawDataIndex);

          if (isDns) {
            const { write } = await handleUDPOutBound(webSocket, protocolResponseHeader, log);
            udpStreamWrite = write;
            udpStreamWrite(rawClientData);
            return;
          }
          
          handleTCPOutBound(
            remoteSocketWapper,
            addressRemote,
            portRemote,
            rawClientData,
            webSocket,
            protocolResponseHeader,
            log
          );
        },
        close() {
          log(`readableWebSocketStream is close`);
        },
        abort(reason) {
          log(`readableWebSocketStream is abort`, JSON.stringify(reason));
        },
      })
    )
    .catch((err) => {
      log("readableWebSocketStream pipeTo error", err);
    });

  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}

async function checkUuidInApiResponse(targetUuid) {
  try {
    const apiResponse = await getApiResponse();
    if (!apiResponse) {
      return false;
    }
    const isUuidInResponse = apiResponse.users.some((user) => user.uuid === targetUuid);
    return isUuidInResponse;
  } catch (error) {
    console.error("Error:", error);
    return false;
  }
}

async function getApiResponse() {
  return { users: [] };
}

// 修复后的 handleTCPOutBound 函数
async function handleTCPOutBound(
  remoteSocket,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  protocolResponseHeader,
  log
) {
  async function connectAndWrite(address, port) {
    let tcpSocket;
    
    // 强制优先使用SOCKS5（如果配置了）
    if (socks5Config) {
      try {
        const socks5Display = socks5Config.isIPv6 ? 
          `[${socks5Config.host}]:${socks5Config.port}` : 
          `${socks5Config.host}:${socks5Config.port}`;
        
        log(`[连接] 强制使用SOCKS5代理: ${socks5Config.username}@${socks5Display} -> ${address}:${port}`);
        
        // 使用SOCKS5连接，将原始目标地址传递给SOCKS5服务器
        tcpSocket = await createSocks5Connection(address, port, socks5Config);
        
        log(`[连接] SOCKS5代理连接成功: ${address}:${port}`);
      } catch (socks5Error) {
        log(`[连接] SOCKS5连接失败: ${socks5Error.message}，回退到直连`);
        
        // SOCKS5失败，回退到直连
        let fallbackAddress, fallbackPort;
        if (proxyIP && proxyIP !== "") {
          fallbackAddress = proxyIP;
          fallbackPort = parseInt(proxyPort) || port;
          log(`[连接] 使用proxyIP直连: ${fallbackAddress}:${fallbackPort}`);
        } else {
          // 处理IP地址混淆（仅在直连时）
          fallbackAddress = address;
          if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(fallbackAddress)) {
            fallbackAddress = `${atob('d3d3Lg==')}${fallbackAddress}${atob('LnNzbGlwLmlv')}`;
          }
          fallbackPort = port;
          log(`[连接] 使用混淆地址直连: ${fallbackAddress}:${fallbackPort}`);
        }
        
        tcpSocket = connect({ hostname: fallbackAddress, port: fallbackPort });
      }
    } else {
      // 没有SOCKS5配置，使用直连
      let directAddress, directPort;
      
      if (proxyIP && proxyIP !== "") {
        directAddress = proxyIP;
        directPort = parseInt(proxyPort) || port;
        log(`[连接] 无SOCKS5，使用proxyIP直连: ${directAddress}:${directPort}`);
      } else {
        // 处理IP地址混淆
        directAddress = address;
        if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(directAddress)) {
          directAddress = `${atob('d3d3Lg==')}${directAddress}${atob('LnNzbGlwLmlv')}`;
        }
        directPort = port;
        log(`[连接] 无SOCKS5，使用混淆地址直连: ${directAddress}:${directPort}`);
      }
      
      tcpSocket = connect({ hostname: directAddress, port: directPort });
    }
    
    remoteSocket.value = tcpSocket;
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retry() {
    log(`[重试] 开始重试连接...`);
    let retrySocket;
    
    // 重试时也强制使用SOCKS5（如果配置了）
    if (socks5Config) {
      try {
        const socks5Display = socks5Config.isIPv6 ? 
          `[${socks5Config.host}]:${socks5Config.port}` : 
          `${socks5Config.host}:${socks5Config.port}`;
        
        log(`[重试] 使用SOCKS5代理: ${socks5Config.username}@${socks5Display} -> ${addressRemote}:${portRemote}`);
        retrySocket = await createSocks5Connection(addressRemote, portRemote, socks5Config);
        log(`[重试] SOCKS5连接成功`);
      } catch (socks5Error) {
        log(`[重试] SOCKS5失败: ${socks5Error.message}，使用直连`);
        
        // SOCKS5重试失败，使用直连
        let fallbackAddress, fallbackPort;
        if (proxyIP && proxyIP !== "") {
          fallbackAddress = proxyIP;
          fallbackPort = parseInt(proxyPort) || portRemote;
        } else {
          fallbackAddress = addressRemote;
          fallbackPort = portRemote;
        }
        
        retrySocket = connect({ hostname: fallbackAddress, port: fallbackPort });
        log(`[重试] 直连建立到 ${fallbackAddress}:${fallbackPort}`);
      }
    } else {
      // 没有SOCKS5，使用直连重试
      let directAddress, directPort;
      if (proxyIP && proxyIP !== "") {
        directAddress = proxyIP;
        directPort = parseInt(proxyPort) || portRemote;
      } else {
        directAddress = addressRemote;
        directPort = portRemote;
      }
      
      log(`[重试] 无SOCKS5，使用直连到 ${directAddress}:${directPort}`);
      retrySocket = connect({ hostname: directAddress, port: directPort });
    }
    
    // Write initial data
    const writer = retrySocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    
    retrySocket.closed
      .catch((error) => {
        console.log("retry tcpSocket closed error", error);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    remoteSocketToWS(retrySocket, webSocket, protocolResponseHeader, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  remoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, retry, log);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) return;
        const message = event.data;
        controller.enqueue(message);
      });

      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) return;
        controller.close();
      });
      
      webSocketServer.addEventListener("error", (err) => {
        log("webSocketServer has error");
        controller.error(err);
      });
      
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },

    pull(controller) {},
    cancel(reason) {
      if (readableStreamCancel) return;
      log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });

  return stream;
}

async function processProtocolHeader(protocolBuffer, userID) {
  if (protocolBuffer.byteLength < 24) {
    return { hasError: true, message: "invalid data" };
  }
  
  const version = new Uint8Array(protocolBuffer.slice(0, 1));
  let isValidUser = false;
  let isUDP = false;
  const slicedBuffer = new Uint8Array(protocolBuffer.slice(1, 17));
  const slicedBufferString = stringify(slicedBuffer);

  const uuids = userID.includes(",") ? userID.split(",") : [userID];
  const checkUuidInApi = await checkUuidInApiResponse(slicedBufferString);
  isValidUser = uuids.some((userUuid) => checkUuidInApi || slicedBufferString === userUuid.trim());

  if (!isValidUser) {
    return { hasError: true, message: "invalid user" };
  }

  const optLength = new Uint8Array(protocolBuffer.slice(17, 18))[0];
  const command = new Uint8Array(protocolBuffer.slice(18 + optLength, 18 + optLength + 1))[0];

  if (command === 1) {
    // TCP
  } else if (command === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
    };
  }
  
  const portIndex = 18 + optLength + 1;
  const portBuffer = protocolBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);

  let addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(protocolBuffer.slice(addressIndex, addressIndex + 1));
  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";
  
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 2:
      addressLength = new Uint8Array(protocolBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3:
      addressLength = 16;
      const dataView = new DataView(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return { hasError: true, message: `invalid addressType is ${addressType}` };
  }
  
  if (!addressValue) {
    return { hasError: true, message: `addressValue is empty, addressType is ${addressType}` };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    protocolVersion: version,
    isUDP,
  };
}

async function remoteSocketToWS(remoteSocket, webSocket, protocolResponseHeader, retry, log) {
  let remoteChunkCount = 0;
  let chunks = [];
  let protocolHeader = protocolResponseHeader;
  let hasIncomingData = false;
  
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        start() {},
        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("webSocket.readyState is not open, maybe close");
          }
          if (protocolHeader) {
            webSocket.send(await new Blob([protocolHeader, chunk]).arrayBuffer());
            protocolHeader = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {
          log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
        },
        abort(reason) {
          console.error(`remoteConnection!.readable abort`, reason);
        },
      })
    )
    .catch((error) => {
      console.error(`remoteSocketToWS has exception `, error.stack || error);
      safeCloseWebSocket(webSocket);
    });

  if (hasIncomingData === false && retry) {
    log(`retry`);
    retry();
  }
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

function isValidUUID(uuid) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error", error);
  }
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
  return (
    byteToHex[arr[offset + 0]] +
    byteToHex[arr[offset + 1]] +
    byteToHex[arr[offset + 2]] +
    byteToHex[arr[offset + 3]] +
    "-" +
    byteToHex[arr[offset + 4]] +
    byteToHex[arr[offset + 5]] +
    "-" +
    byteToHex[arr[offset + 6]] +
    byteToHex[arr[offset + 7]] +
    "-" +
    byteToHex[arr[offset + 8]] +
    byteToHex[arr[offset + 9]] +
    "-" +
    byteToHex[arr[offset + 10]] +
    byteToHex[arr[offset + 11]] +
    byteToHex[arr[offset + 12]] +
    byteToHex[arr[offset + 13]] +
    byteToHex[arr[offset + 14]] +
    byteToHex[arr[offset + 15]]
  ).toLowerCase();
}

function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) {
    throw TypeError("Stringified UUID is invalid");
  }
  return uuid;
}

async function handleUDPOutBound(webSocket, protocolResponseHeader, log) {
  let isProtocolHeaderSent = false;
  const transformStream = new TransformStream({
    start(controller) {},
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength; ) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPakcetLength));
        index = index + 2 + udpPakcetLength;
        controller.enqueue(udpData);
      }
    },
    flush(controller) {},
  });

  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          const resp = await fetch(dohURL, {
            method: "POST",
            headers: { "content-type": "application/dns-message" },
            body: chunk,
          });
          const dnsQueryResult = await resp.arrayBuffer();
          const udpSize = dnsQueryResult.byteLength;
          const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
          
          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            log(`doh success and dns message length is ${udpSize}`);
            if (isProtocolHeaderSent) {
              webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
            } else {
              webSocket.send(await new Blob([protocolResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
              isProtocolHeaderSent = true;
            }
          }
        },
      })
    )
    .catch((error) => {
      log("dns udp has error" + error);
    });

  const writer = transformStream.writable.getWriter();
  return {
    write(chunk) {
      writer.write(chunk);
    },
  };
}

function getProtocolConfig(userID, hostName) {
  // Use obfuscated protocol name to avoid detection
  const protocolName = atob('dmxlc3M='); // vless
  
  const wsConfig = `${protocolName}://${userID}@${CDNIP}:8880?encryption=none&security=none&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#${hostName}`;
  const wsTlsConfig = `${protocolName}://${userID}@${CDNIP}:8443?encryption=none&security=tls&type=ws&host=${hostName}&sni=${hostName}&fp=random&path=%2F%3Fed%3D2560#${hostName}`;
  
  const note = `Blog: https://ygkkk.blogspot.com\nYouTube: https://www.youtube.com/@ygkkk\nTelegram Group: https://t.me/ygkkktg\nTelegram Channel: https://t.me/ygkkktgpd\n\nProxy settings: ${proxyIP}:${proxyPort}${socks5Config ? `\nSOCKS5: ${socks5Config.username}@${socks5Config.isIPv6 ? '[' + socks5Config.host + ']' : socks5Config.host}:${socks5Config.port}` : ''}`;
  
  const noteshow = note.replace(/\n/g, '<br>');
  const displayHtml = `
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<style>.limited-width { max-width: 200px; overflow: auto; word-wrap: break-word; }</style>
</head>
<script>
function copyToClipboard(text) {
  const input = document.createElement('textarea');
  input.style.position = 'fixed';
  input.style.opacity = 0;
  input.value = text;
  document.body.appendChild(input);
  input.select();
  document.execCommand('Copy');
  document.body.removeChild(input);
  alert('Copied to clipboard');
}
</script>`;

  if (hostName.includes("workers.dev")) {
    return `
${displayHtml}
<body>
<div class="container">
    <div class="row">
        <div class="col-md-12">
            <h1>Cloudflare Workers Proxy Script V25.5.4</h1>
            <hr>
            <p>${noteshow}</p>
            <hr>
            <h3>1: CF-workers Protocol+ws Node</h3>
            <table class="table">
                <thead>
                    <tr>
                        <th>Features:</th>
                        <th>Configuration:</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">TLS disabled, domain blocking bypassed</td>
                        <td class="limited-width">${wsConfig}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${wsConfig}')">Copy Link</button></td>
                    </tr>
                </tbody>
            </table>
            <h3>2: CF-workers Protocol+ws+tls Node</h3>
            <table class="table">
                <thead>
                    <tr>
                        <th>Features:</th>
                        <th>Configuration:</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">TLS enabled, supports fragmentation</td>
                        <td class="limited-width">${wsTlsConfig}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${wsTlsConfig}')">Copy Link</button></td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</div>
</body>`;
  } else {
    return `
${displayHtml}
<body>
<div class="container">
    <div class="row">
        <div class="col-md-12">
            <h1>Cloudflare Workers Proxy Script V25.5.4</h1>
            <hr>
            <p>${noteshow}</p>
            <hr>
            <h3>1: CF-pages/workers Protocol+ws+tls Node</h3>
            <table class="table">
                <thead>
                    <tr>
                        <th>Features:</th>
                        <th>Configuration:</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">TLS enabled, supports fragmentation</td>
                        <td class="limited-width">${wsTlsConfig}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${wsTlsConfig}')">Copy Link</button></td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</div>
</body>`;
  }
}

function gettyConfig(userID, hostName) {
  const protocolName = atob('dmxlc3M='); // vless
  const configStr = `${protocolName}://${userID}@${IP1}:${PT1}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V1_${IP1}_${PT1}\n` +
    `${protocolName}://${userID}@${IP2}:${PT2}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V2_${IP2}_${PT2}\n` +
    `${protocolName}://${userID}@${IP3}:${PT3}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V3_${IP3}_${PT3}\n` +
    `${protocolName}://${userID}@${IP4}:${PT4}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V4_${IP4}_${PT4}\n` +
    `${protocolName}://${userID}@${IP5}:${PT5}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V5_${IP5}_${PT5}\n` +
    `${protocolName}://${userID}@${IP6}:${PT6}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V6_${IP6}_${PT6}\n` +
    `${protocolName}://${userID}@${IP7}:${PT7}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V7_${IP7}_${PT7}\n` +
    `${protocolName}://${userID}@${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\n` +
    `${protocolName}://${userID}@${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\n` +
    `${protocolName}://${userID}@${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\n` +
    `${protocolName}://${userID}@${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\n` +
    `${protocolName}://${userID}@${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\n` +
    `${protocolName}://${userID}@${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`;
  return btoa(configStr);
}

function getclConfig(userID, hostName) {
  const protocolName = atob('dmxlc3M='); // vless
  return `
port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: false
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver: 
    - 223.5.5.5
    - 114.114.114.114
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:
- name: CF_V1_${IP1}_${PT1}
  type: ${protocolName}
  server: ${IP1.replace(/[\[\]]/g, '')}
  port: ${PT1}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V2_${IP2}_${PT2}
  type: ${protocolName}
  server: ${IP2.replace(/[\[\]]/g, '')}
  port: ${PT2}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V3_${IP3}_${PT3}
  type: ${protocolName}
  server: ${IP3.replace(/[\[\]]/g, '')}
  port: ${PT3}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V4_${IP4}_${PT4}
  type: ${protocolName}
  server: ${IP4.replace(/[\[\]]/g, '')}
  port: ${PT4}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V5_${IP5}_${PT5}
  type: ${protocolName}
  server: ${IP5.replace(/[\[\]]/g, '')}
  port: ${PT5}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V6_${IP6}_${PT6}
  type: ${protocolName}
  server: ${IP6.replace(/[\[\]]/g, '')}
  port: ${PT6}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V7_${IP7}_${PT7}
  type: ${protocolName}
  server: ${IP7.replace(/[\[\]]/g, '')}
  port: ${PT7}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V8_${IP8}_${PT8}
  type: ${protocolName}
  server: ${IP8.replace(/[\[\]]/g, '')}
  port: ${PT8}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V9_${IP9}_${PT9}
  type: ${protocolName}
  server: ${IP9.replace(/[\[\]]/g, '')}
  port: ${PT9}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V10_${IP10}_${PT10}
  type: ${protocolName}
  server: ${IP10.replace(/[\[\]]/g, '')}
  port: ${PT10}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V11_${IP11}_${PT11}
  type: ${protocolName}
  server: ${IP11.replace(/[\[\]]/g, '')}
  port: ${PT11}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V12_${IP12}_${PT12}
  type: ${protocolName}
  server: ${IP12.replace(/[\[\]]/g, '')}
  port: ${PT12}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V13_${IP13}_${PT13}
  type: ${protocolName}
  server: ${IP13.replace(/[\[\]]/g, '')}
  port: ${PT13}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

proxy-groups:
- name: Load Balance
  type: load-balance
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
    - CF_V1_${IP1}_${PT1}
    - CF_V2_${IP2}_${PT2}
    - CF_V3_${IP3}_${PT3}
    - CF_V4_${IP4}_${PT4}
    - CF_V5_${IP5}_${PT5}
    - CF_V6_${IP6}_${PT6}
    - CF_V7_${IP7}_${PT7}
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

- name: Auto Select
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
    - CF_V1_${IP1}_${PT1}
    - CF_V2_${IP2}_${PT2}
    - CF_V3_${IP3}_${PT3}
    - CF_V4_${IP4}_${PT4}
    - CF_V5_${IP5}_${PT5}
    - CF_V6_${IP6}_${PT6}
    - CF_V7_${IP7}_${PT7}
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

- name: 🌍Select Proxy
  type: select
  proxies:
    - Load Balance
    - Auto Select
    - DIRECT
    - CF_V1_${IP1}_${PT1}
    - CF_V2_${IP2}_${PT2}
    - CF_V3_${IP3}_${PT3}
    - CF_V4_${IP4}_${PT4}
    - CF_V5_${IP5}_${PT5}
    - CF_V6_${IP6}_${PT6}
    - CF_V7_${IP7}_${PT7}
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🌍Select Proxy`;
}

function getsbConfig(userID, hostName) {
  const protocolName = atob('dmxlc3M='); // vless
  return JSON.stringify({
    "log": {
      "disabled": false,
      "level": "info",
      "timestamp": true
    },
    "experimental": {
      "clash_api": {
        "external_controller": "127.0.0.1:9090",
        "external_ui": "ui",
        "external_ui_download_url": "",
        "external_ui_download_detour": "",
        "secret": "",
        "default_mode": "Rule"
      },
      "cache_file": {
        "enabled": true,
        "path": "cache.db",
        "store_fakeip": true
      }
    },
    "dns": {
      "servers": [
        {
          "tag": "proxydns",
          "address": "tls://8.8.8.8/dns-query",
          "detour": "select"
        },
        {
          "tag": "localdns",
          "address": "h3://223.5.5.5/dns-query",
          "detour": "direct"
        },
        {
          "tag": "dns_fakeip",
          "address": "fakeip"
        }
      ],
      "rules": [
        {
          "outbound": "any",
          "server": "localdns",
          "disable_cache": true
        },
        {
          "clash_mode": "Global",
          "server": "proxydns"
        },
        {
          "clash_mode": "Direct",
          "server": "localdns"
        },
        {
          "rule_set": "geosite-cn",
          "server": "localdns"
        },
        {
          "rule_set": "geosite-geolocation-!cn",
          "server": "proxydns"
        },
        {
          "rule_set": "geosite-geolocation-!cn",
          "query_type": ["A", "AAAA"],
          "server": "dns_fakeip"
        }
      ],
      "fakeip": {
        "enabled": true,
        "inet4_range": "198.18.0.0/15",
        "inet6_range": "fc00::/18"
      },
      "independent_cache": true,
      "final": "proxydns"
    },
    "inbounds": [
      {
        "type": "tun",
        "tag": "tun-in",
        "address": ["172.19.0.1/30", "fd00::1/126"],
        "auto_route": true,
        "strict_route": true,
        "sniff": true,
        "sniff_override_destination": true,
        "domain_strategy": "prefer_ipv4"
      }
    ],
    "outbounds": [
      {
        "tag": "select",
        "type": "selector",
        "default": "auto",
        "outbounds": [
          "auto",
          `CF_V1_${IP1}_${PT1}`,
          `CF_V2_${IP2}_${PT2}`,
          `CF_V3_${IP3}_${PT3}`,
          `CF_V4_${IP4}_${PT4}`,
          `CF_V5_${IP5}_${PT5}`,
          `CF_V6_${IP6}_${PT6}`,
          `CF_V7_${IP7}_${PT7}`,
          `CF_V8_${IP8}_${PT8}`,
          `CF_V9_${IP9}_${PT9}`,
          `CF_V10_${IP10}_${PT10}`,
          `CF_V11_${IP11}_${PT11}`,
          `CF_V12_${IP12}_${PT12}`,
          `CF_V13_${IP13}_${PT13}`
        ]
      },
      ...Array.from({length: 13}, (_, i) => {
        const ipVar = eval(`IP${i+1}`);
        const ptVar = eval(`PT${i+1}`);
        const isTLS = i >= 7;
        
        const config = {
          "server": ipVar,
          "server_port": parseInt(ptVar),
          "tag": `CF_V${i+1}_${ipVar}_${ptVar}`,
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": { "Host": [hostName] },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": protocolName,
          "uuid": userID
        };
        
        if (isTLS) {
          config.tls = {
            "enabled": true,
            "server_name": hostName,
            "insecure": false,
            "utls": {
              "enabled": true,
              "fingerprint": "chrome"
            }
          };
        }
        
        return config;
      }),
      {
        "tag": "direct",
        "type": "direct"
      },
      {
        "tag": "auto",
        "type": "urltest",
        "outbounds": Array.from({length: 13}, (_, i) => `CF_V${i+1}_${eval(`IP${i+1}`)}_${eval(`PT${i+1}`)}`),
        "url": "https://www.gstatic.com/generate_204",
        "interval": "1m",
        "tolerance": 50,
        "interrupt_exist_connections": false
      }
    ],
    "route": {
      "rule_set": [
        {
          "tag": "geosite-geolocation-!cn",
          "type": "remote",
          "format": "binary",
          "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
          "download_detour": "select",
          "update_interval": "1d"
        },
        {
          "tag": "geosite-cn",
          "type": "remote",
          "format": "binary",
          "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-cn.srs",
          "download_detour": "select",
          "update_interval": "1d"
        },
        {
          "tag": "geoip-cn",
          "type": "remote",
          "format": "binary",
          "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
          "download_detour": "select",
          "update_interval": "1d"
        }
      ],
      "auto_detect_interface": true,
      "final": "select",
      "rules": [
        {
          "inbound": "tun-in",
          "action": "sniff"
        },
        {
          "protocol": "dns",
          "action": "hijack-dns"
        },
        {
          "port": 443,
          "network": "udp",
          "action": "reject"
        },
        {
          "clash_mode": "Direct",
          "outbound": "direct"
        },
        {
          "clash_mode": "Global",
          "outbound": "select"
        },
        {
          "rule_set": "geoip-cn",
          "outbound": "direct"
        },
        {
          "rule_set": "geosite-cn",
          "outbound": "direct"
        },
        {
          "ip_is_private": true,
          "outbound": "direct"
        },
        {
          "rule_set": "geosite-geolocation-!cn",
          "outbound": "select"
        }
      ]
    },
    "ntp": {
      "enabled": true,
      "server": "time.apple.com",
      "server_port": 123,
      "interval": "30m",
      "detour": "direct"
    }
  }, null, 2);
}

function getptyConfig(userID, hostName) {
  const protocolName = atob('dmxlc3M='); // vless
  const configStr = `${protocolName}://${userID}@${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\n` +
    `${protocolName}://${userID}@${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\n` +
    `${protocolName}://${userID}@${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\n` +
    `${protocolName}://${userID}@${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\n` +
    `${protocolName}://${userID}@${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\n` +
    `${protocolName}://${userID}@${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`;
  return btoa(configStr);
}

function getpclConfig(userID, hostName) {
  const protocolName = atob('dmxlc3M='); // vless
  return `
port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: false
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver: 
    - 223.5.5.5
    - 114.114.114.114
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:
- name: CF_V8_${IP8}_${PT8}
  type: ${protocolName}
  server: ${IP8.replace(/[\[\]]/g, '')}
  port: ${PT8}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V9_${IP9}_${PT9}
  type: ${protocolName}
  server: ${IP9.replace(/[\[\]]/g, '')}
  port: ${PT9}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V10_${IP10}_${PT10}
  type: ${protocolName}
  server: ${IP10.replace(/[\[\]]/g, '')}
  port: ${PT10}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V11_${IP11}_${PT11}
  type: ${protocolName}
  server: ${IP11.replace(/[\[\]]/g, '')}
  port: ${PT11}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V12_${IP12}_${PT12}
  type: ${protocolName}
  server: ${IP12.replace(/[\[\]]/g, '')}
  port: ${PT12}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V13_${IP13}_${PT13}
  type: ${protocolName}
  server: ${IP13.replace(/[\[\]]/g, '')}
  port: ${PT13}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

proxy-groups:
- name: Load Balance
  type: load-balance
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

- name: Auto Select
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

- name: 🌍Select Proxy
  type: select
  proxies:
    - Load Balance
    - Auto Select
    - DIRECT
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🌍Select Proxy`;
}

function getpsbConfig(userID, hostName) {
  const protocolName = atob('dmxlc3M='); // vless
  return JSON.stringify({
    "log": {
      "disabled": false,
      "level": "info",
      "timestamp": true
    },
    "experimental": {
      "clash_api": {
        "external_controller": "127.0.0.1:9090",
        "external_ui": "ui",
        "external_ui_download_url": "",
        "external_ui_download_detour": "",
        "secret": "",
        "default_mode": "Rule"
      },
      "cache_file": {
        "enabled": true,
        "path": "cache.db",
        "store_fakeip": true
      }
    },
    "dns": {
      "servers": [
        {
          "tag": "proxydns",
          "address": "tls://8.8.8.8/dns-query",
          "detour": "select"
        },
        {
          "tag": "localdns",
          "address": "h3://223.5.5.5/dns-query",
          "detour": "direct"
        },
        {
          "tag": "dns_fakeip",
          "address": "fakeip"
        }
      ],
      "rules": [
        {
          "outbound": "any",
          "server": "localdns",
          "disable_cache": true
        },
        {
          "clash_mode": "Global",
          "server": "proxydns"
        },
        {
          "clash_mode": "Direct",
          "server": "localdns"
        },
        {
          "rule_set": "geosite-cn",
          "server": "localdns"
        },
        {
          "rule_set": "geosite-geolocation-!cn",
          "server": "proxydns"
        },
        {
          "rule_set": "geosite-geolocation-!cn",
          "query_type": ["A", "AAAA"],
          "server": "dns_fakeip"
        }
      ],
      "fakeip": {
        "enabled": true,
        "inet4_range": "198.18.0.0/15",
        "inet6_range": "fc00::/18"
      },
      "independent_cache": true,
      "final": "proxydns"
    },
    "inbounds": [
      {
        "type": "tun",
        "tag": "tun-in",
        "address": ["172.19.0.1/30", "fd00::1/126"],
        "auto_route": true,
        "strict_route": true,
        "sniff": true,
        "sniff_override_destination": true,
        "domain_strategy": "prefer_ipv4"
      }
    ],
    "outbounds": [
      {
        "tag": "select",
        "type": "selector",
        "default": "auto",
        "outbounds": [
          "auto",
          `CF_V8_${IP8}_${PT8}`,
          `CF_V9_${IP9}_${PT9}`,
          `CF_V10_${IP10}_${PT10}`,
          `CF_V11_${IP11}_${PT11}`,
          `CF_V12_${IP12}_${PT12}`,
          `CF_V13_${IP13}_${PT13}`
        ]
      },
      ...Array.from({length: 6}, (_, i) => {
        const ipVar = eval(`IP${i+8}`);
        const ptVar = eval(`PT${i+8}`);
        
        return {
          "server": ipVar,
          "server_port": parseInt(ptVar),
          "tag": `CF_V${i+8}_${ipVar}_${ptVar}`,
          "tls": {
            "enabled": true,
            "server_name": hostName,
            "insecure": false,
            "utls": {
              "enabled": true,
              "fingerprint": "chrome"
            }
          },
          "packet_encoding": "packetaddr",
          "transport": {
            "headers": { "Host": [hostName] },
            "path": "/?ed=2560",
            "type": "ws"
          },
          "type": protocolName,
          "uuid": userID
        };
      }),
      {
        "tag": "direct",
        "type": "direct"
      },
      {
        "tag": "auto",
        "type": "urltest",
        "outbounds": Array.from({length: 6}, (_, i) => `CF_V${i+8}_${eval(`IP${i+8}`)}_${eval(`PT${i+8}`)}`),
        "url": "https://www.gstatic.com/generate_204",
        "interval": "1m",
        "tolerance": 50,
        "interrupt_exist_connections": false
      }
    ],
    "route": {
      "rule_set": [
        {
          "tag": "geosite-geolocation-!cn",
          "type": "remote",
          "format": "binary",
          "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
          "download_detour": "select",
          "update_interval": "1d"
        },
        {
          "tag": "geosite-cn",
          "type": "remote",
          "format": "binary",
          "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-cn.srs",
          "download_detour": "select",
          "update_interval": "1d"
        },
        {
          "tag": "geoip-cn",
          "type": "remote",
          "format": "binary",
          "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
          "download_detour": "select",
          "update_interval": "1d"
        }
      ],
      "auto_detect_interface": true,
      "final": "select",
      "rules": [
        {
          "inbound": "tun-in",
          "action": "sniff"
        },
        {
          "protocol": "dns",
          "action": "hijack-dns"
        },
        {
          "port": 443,
          "network": "udp",
          "action": "reject"
        },
        {
          "clash_mode": "Direct",
          "outbound": "direct"
        },
        {
          "clash_mode": "Global",
          "outbound": "select"
        },
        {
          "rule_set": "geoip-cn",
          "outbound": "direct"
        },
        {
          "rule_set": "geosite-cn",
          "outbound": "direct"
        },
        {
          "ip_is_private": true,
          "outbound": "direct"
        },
        {
          "rule_set": "geosite-geolocation-!cn",
          "outbound": "select"
        }
      ]
    },
    "ntp": {
      "enabled": true,
      "server": "time.apple.com",
      "server_port": 123,
      "interval": "30m",
      "detour": "direct"
    }
  }, null, 2);
}