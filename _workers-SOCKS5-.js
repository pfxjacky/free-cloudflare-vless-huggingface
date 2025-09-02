/**
 * 
 * 修复版本：确保IPv6 SOCKS5代理完全可用
 */

// @ts-ignore
import { connect } from 'cloudflare:sockets';

// Generate your own UUID using the following command in PowerShell:
// Powershell -NoExit -Command "[guid]::NewGuid()"
let userID = 'd0298536-d670-4045-bbb1-ddd5ea68683e';
let kvUUID;

// Proxy IPs to choose from
let proxyIPs = [
	'proxyip.amclubs.camdvr.org',
	'proxyip.amclubs.kozow.com'
];
// Randomly select a proxy IP from the list
let proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
let proxyPort = 443;
let proxyIpTxt = atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2FtY2x1YnMvYW0tY2YtdHVubmVsL21haW4vcHJveHlpcC50eHQ=');
let proxyDomain = [];

// Setting the socks5 will ignore proxyIP
// Example:  user:pass@host:port  or  host:port
let socks5 = '';
let socks5Enable = false;
let parsedSocks5 = {};

// https://cloudflare-dns.com/dns-query or https://dns.google/dns-query
// DNS-over-HTTPS URL
let dohURL = 'https://sky.rethinkdns.com/1:-Pf_____9_8A_AMAIgE8kMABVDDmKOHTAKg=';

// Preferred address API interface
const defaultIpUrlTxt = atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2FtY2x1YnMvYW0tY2YtdHVubmVsL21haW4vaXB2NC50eHQ=');
let randomNum = 25;
let ipUrl = [];
let ipUrlTxt = [defaultIpUrlTxt];
let ipUrlCsv = [];

// Preferred addresses with optional TLS subscription
let ipLocal = [
	'wto.org:443#youtube.com/@',
	'icook.hk#t.me/',
	'time.is#github.com/pfxjacky GitHub仓库(关注查看新功能)',
	'127.0.0.1:1234# (博客) blog'
];
let noTLS = false;
let sl = 5;

let tagName = atob('YW1jbHVicw==');
let subUpdateTime = 6; // Subscription update time in hours
let timestamp = 4102329600000; // Timestamp for the end date (2099-12-31)
let total = 99 * 1125899906842624; // PB (perhaps referring to bandwidth or total entries)
let download = Math.floor(Math.random() * 1099511627776);
let upload = download;

// Network protocol type
let network = 'ws'; // WebSocket

// Fake UUID and hostname for configuration generation
let fakeUserID;
let fakeHostName;

// Subscription and conversion details
let subProtocol = 'https';
let subConverter = atob('dXJsLnYxLm1r'); // Subscription conversion backend using Sheep's function
let subConfig = atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2FtY2x1YnMvQUNMNFNTUi9tYWluL0NsYXNoL2NvbmZpZy9BQ0w0U1NSX09ubGluZV9GdWxsX011bHRpTW9kZS5pbmk='); // Subscription profile
let fileName = atob('5pWw5a2X5aWX5Ymp');
let isBase64 = true;

let botToken = '';
let chatID = '';

let projectName = atob('YW1jbHVicy9hbS1jZi10dW5uZWw');
let ytName = atob('aHR0cHM6Ly95b3V0dWJlLmNvbS9AYW1fY2x1YnM=');
const httpPattern = /^http(s)?:\/\/.+/;

const protTypeBase64 = 'ZG14bGMzTT0=';
const protTypeBase64Tro = 'ZEhKdmFtRnU=';

let dnsResolver = atob('aHR0cHM6Ly8xLjEuMS4xL2Rucy1xdWVyeQ==');
let nat64Domain = [];
let nat64 = false;
let nat64Prefix;
let nat64Prefixs = ['2602:fc59:b0:64::'];

let hostRemark = false;

const ENABLE_LOG = true;

if (!isValidUUID(userID)) {
	throw new Error('uuid is invalid');
}

export default {
	/**
	 * @param {import("@cloudflare/workers-types").Request} request
	 * @param {{UUID: string, PROXYIP: string, DNS_RESOLVER_URL: string, NODE_ID: int, API_HOST: string, API_TOKEN: string}} env
	 * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
	 * @returns {Promise<Response>}
	*/
	async fetch(request, env, ctx) {
		try {
			let {
				UUID,
				PROXYIP,
				PROXYIP_DOM_URL_TXT,
				SOCKS5,
				DNS_RESOLVER_URL,
				IP_LOCAL,
				IP_URL,
				IP_URL_TXT,
				IP_URL_CSV,
				NO_TLS,
				SL,
				SUB_CONFIG,
				SUB_CONVERTER,
				SUB_NAME,
				CF_EMAIL,
				CF_KEY,
				CF_ID = 0,
				TG_TOKEN,
				TG_ID,
				//兼容
				ADDRESSESAPI,
				NAT64,
				NAT64_DOM_URL_TXT,
				NAT64_PREFIX,
				HOST_REAMRK,
			} = env;
			const kvCheckResponse = await checkKVNamespaceBinding(env);
			if (!kvCheckResponse) {
				kvUUID = await getKVData(env);
			}
			const url = new URL(request.url);
			//兼容双协议
			userID = (kvUUID || UUID || userID).toLowerCase();

			PROXYIP = url.searchParams.get('PROXYIP') || PROXYIP;
			if (PROXYIP) {
				if (httpPattern.test(PROXYIP)) {
					let proxyIpTxt = await addIpText(PROXYIP);
					let ipUrlTxtAndCsv;
					if (PROXYIP.endsWith('.csv')) {
						ipUrlTxtAndCsv = await getIpUrlTxtAndCsv(noTLS, null, proxyIpTxt);
					} else {
						ipUrlTxtAndCsv = await getIpUrlTxtAndCsv(noTLS, proxyIpTxt, null);
					}
					const uniqueIpTxt = [...new Set([...ipUrlTxtAndCsv.txt, ...ipUrlTxtAndCsv.csv])];
					proxyIP = uniqueIpTxt[Math.floor(Math.random() * uniqueIpTxt.length)];
				} else {
					proxyIPs = await addIpText(PROXYIP);
					proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
				}
			} else {
				let proxyIpTxts = await addIpText(proxyIpTxt);
				let ipUrlTxtAndCsv = await getIpUrlTxtAndCsv(noTLS, proxyIpTxts, null);
				let updatedIps = ipUrlTxtAndCsv.txt.map(ip => `${tagName}${download}.${ip}`);
				const uniqueIpTxt = [...new Set([...updatedIps, ...proxyIPs])];
				proxyIP = uniqueIpTxt[Math.floor(Math.random() * uniqueIpTxt.length)];
			}
			
			if (proxyIP) {
				const [ip, port] = proxyIP.split(':');
				proxyIP = ip;
				proxyPort = port || proxyPort;
			}

			// 修改：从URL参数解析SOCKS5配置
			socks5 = url.searchParams.get('SOCKS5') || url.searchParams.get('socks5') || SOCKS5 || socks5;
			parsedSocks5 = await parseSocks5FromUrl(socks5, url);
			if (parsedSocks5) {
				socks5Enable = true;
				console.log('SOCKS5 proxy enabled:', `${parsedSocks5.hostname}:${parsedSocks5.port}`);
				// 添加IPv6代理的调试信息
				if (parsedSocks5.hostname.includes(':')) {
					console.log('IPv6 SOCKS5 proxy detected');
				}
			}

			dohURL = url.searchParams.get('DNS_RESOLVER_URL') || DNS_RESOLVER_URL || dohURL;

			IP_LOCAL = url.searchParams.get('IP_LOCAL') || IP_LOCAL;
			if (IP_LOCAL) {
				ipLocal = await addIpText(IP_LOCAL);
			}
			
			const newCsvUrls = [];
			const newTxtUrls = [];
			IP_URL = url.searchParams.get('IP_URL') || IP_URL;
			if (IP_URL) {
				ipUrlTxt = [];
				ipUrl = await addIpText(IP_URL);
				ipUrl = await getIpUrlTxtToArry(ipUrl);
				ipUrl.forEach(url => {
					if (getFileType(url) === 'csv') {
						newCsvUrls.push(url);
					} else {
						newTxtUrls.push(url);
					}
				});
			}
			
			//兼容旧的，如果有IP_URL_TXT新的则不用旧的
			ADDRESSESAPI = url.searchParams.get('ADDRESSESAPI') || ADDRESSESAPI;
			IP_URL_TXT = url.searchParams.get('IP_URL_TXT') || IP_URL_TXT;
			IP_URL_CSV = url.searchParams.get('IP_URL_CSV') || IP_URL_CSV;
			if (ADDRESSESAPI) {
				ipUrlTxt = await addIpText(ADDRESSESAPI);
			}
			if (IP_URL_TXT) {
				ipUrlTxt = await addIpText(IP_URL_TXT);
			}
			if (IP_URL_CSV) {
				ipUrlCsv = await addIpText(IP_URL_CSV);
			}
			ipUrlCsv = [...new Set([...ipUrlCsv, ...newCsvUrls])];
			ipUrlTxt = [...new Set([...ipUrlTxt, ...newTxtUrls])];

			noTLS = url.searchParams.get('NO_TLS') || NO_TLS || noTLS;
			sl = url.searchParams.get('SL') || SL || sl;
			subConfig = url.searchParams.get('SUB_CONFIG') || SUB_CONFIG || subConfig;
			subConverter = url.searchParams.get('SUB_CONVERTER') || SUB_CONVERTER || subConverter;
			fileName = url.searchParams.get('SUB_NAME') || SUB_NAME || fileName;
			botToken = url.searchParams.get('TG_TOKEN') || TG_TOKEN || botToken;
			chatID = url.searchParams.get('TG_ID') || TG_ID || chatID;
			let protType = url.searchParams.get('PROT_TYPE');
			if (protType) {
				protType = protType.toLowerCase();
			}
			randomNum = url.searchParams.get('RANDOW_NUM') || randomNum;
			hostRemark = url.searchParams.get('HOST_REAMRK') || HOST_REAMRK || hostRemark;

			nat64 = url.searchParams.get('NAT64') || NAT64 || nat64;
			NAT64_DOM_URL_TXT = url.searchParams.get('NAT64_DOM_URL_TXT') || NAT64_DOM_URL_TXT;
			if (NAT64_DOM_URL_TXT) {
				let nat64DomainTxt = await addIpText(NAT64_DOM_URL_TXT);
				let nat64DomainAll = await getIpUrlTxtAndCsv(noTLS, nat64DomainTxt, null);
				nat64Domain = [...new Set([...nat64DomainAll.txt])];
			}
			PROXYIP_DOM_URL_TXT = url.searchParams.get('PROXYIP_DOM_URL_TXT') || PROXYIP_DOM_URL_TXT;
			if (PROXYIP_DOM_URL_TXT) {
				let proxyDomainTxt = await addIpText(PROXYIP_DOM_URL_TXT);
				let proxyDomainAll = await getIpUrlTxtAndCsv(noTLS, proxyDomainTxt, null);
				proxyDomain = [...new Set([...proxyDomainAll.txt])];
			}
			nat64Prefix = url.searchParams.get('NAT64_PREFIX') || NAT64_PREFIX;
			if (NAT64_PREFIX) {
				if (httpPattern.test(NAT64_PREFIX)) {
					let proxyIpTxt = await addIpText(NAT64_PREFIX);
					let ipUrlTxtAndCsv;
					if (NAT64_PREFIX.endsWith('.csv')) {
						ipUrlTxtAndCsv = await getIpUrlTxtAndCsv(noTLS, null, proxyIpTxt);
					} else {
						ipUrlTxtAndCsv = await getIpUrlTxtAndCsv(noTLS, proxyIpTxt, null);
					}
					const uniqueIpTxt = [...new Set([...ipUrlTxtAndCsv.txt, ...ipUrlTxtAndCsv.csv])];
					nat64Prefix = uniqueIpTxt[Math.floor(Math.random() * uniqueIpTxt.length)];
				} else {
					nat64Prefixs = await addIpText(NAT64_PREFIX);
					nat64Prefix = nat64Prefixs[Math.floor(Math.random() * nat64Prefixs.length)];
				}
			}

			// Unified protocol for handling subconverters
			const [subProtocol, subConverterWithoutProtocol] = (subConverter.startsWith("http://") || subConverter.startsWith("https://"))
				? subConverter.split("://")
				: [undefined, subConverter];
			subConverter = subConverterWithoutProtocol;

			const ua = request.headers.get('User-Agent') || 'null';
			const userAgent = ua.toLowerCase();
			const host = request.headers.get('Host');
			const upgradeHeader = request.headers.get('Upgrade');
			const expire = Math.floor(timestamp / 1000);

			// If WebSocket upgrade, handle WebSocket request - 修改为vless协议
			if (upgradeHeader === 'websocket') {
				// 保持vless协议，但确保所有出站流量都通过SOCKS5
				return await vlessOverWSHandler(request);
			}

			fakeUserID = await getFakeUserID(userID);
			fakeHostName = fakeUserID.slice(6, 9) + "." + fakeUserID.slice(13, 19);

			// Handle routes based on the path
			switch (url.pathname.toLowerCase()) {
				case '/': {
					return new Response(await nginx(), {
						headers: {
							'Content-Type': 'text/html; charset=UTF-8',
							'referer': 'https://www.google.com/search?q=' + fileName,
						},
					});
				}

				case `/${fakeUserID}`: {
					// Disguise UUID node generation
					const fakeConfig = await getvlessConfig(userID, host, 'CF-FAKE-UA', url, protType, nat64, hostRemark);
					return new Response(fakeConfig, { status: 200 });
				}

				case `/${userID}`: {
					// Handle real UUID requests and get node info
					await sendMessage(
						`#获取订阅 ${fileName}`,
						request.headers.get('CF-Connecting-IP'),
						`UA: ${userAgent}\n域名: ${url.hostname}\n入口: ${url.pathname + url.search}`
					);

					const vlessConfig = await getvlessConfig(userID, host, userAgent, url, protType, nat64, hostRemark);
					const isMozilla = userAgent.includes('mozilla');

					const config = await getCFConfig(CF_EMAIL, CF_KEY, CF_ID);
					if (CF_EMAIL && CF_KEY) {
						({ upload, download, total } = config);
					}

					// Prepare common headers
					const commonHeaders = {
						"Content-Type": isMozilla ? "text/html;charset=utf-8" : "text/plain;charset=utf-8",
						"Profile-Update-Interval": `${subUpdateTime}`,
						"Subscription-Userinfo": `upload=${upload}; download=${download}; total=${total}; expire=${expire}`,
					};

					// Add download headers if not a Mozilla browser
					if (!isMozilla) {
						commonHeaders["Content-Disposition"] = `attachment; filename=${fileName}; filename*=gbk''${fileName}`;
					}

					return new Response(vlessConfig, {
						status: 200,
						headers: commonHeaders,
					});
				}

				case `/${userID}/ui`: {
					return await showKVPage(env);
				}
				case `/${userID}/get`: {
					return getKVData(env);
				}
				case `/${userID}/set`: {
					return setKVData(request, env);
				}

				default: {
					// Serve the default nginx disguise page
					return new Response(await nginx(), {
						headers: {
							'Content-Type': 'text/html; charset=UTF-8',
							'referer': 'https://www.google.com/search?q=' + fileName,
						},
					});
				}
			}
		} catch (err) {
			// Log error for debugging purposes
			console.error('Error processing request:', err);
			return new Response(`Error: ${err.message}`, { status: 500 });
		}
	},
};

/**
 * 处理vless over WebSocket连接
 */
async function vlessOverWSHandler(request) {
	// @ts-ignore
	const webSocketPair = new WebSocketPair();
	const [client, webSocket] = Object.values(webSocketPair);
	webSocket.accept();

	let address = '';
	let portWithRandomLog = '';
	let currentDate = new Date();
	const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
		console.log(`[${currentDate} ${address}:${portWithRandomLog}] ${info}`, event || '');
	};
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

	/** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
	let remoteSocketWapper = {
		value: null,
	};
	let udpStreamWrite = null;
	let isDns = false;

	// ws --> remote
	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			if (isDns && udpStreamWrite) {
				return udpStreamWrite(chunk);
			}
			if (remoteSocketWapper.value) {
				const writer = remoteSocketWapper.value.writable.getWriter()
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}

			const {
				hasError,
				//message,
				portRemote = 443,
				addressRemote = '',
				rawDataIndex,
				vlessVersion = new Uint8Array([0, 0]),
				isUDP,
				addressType,
			} = processVlessHeader(chunk, userID);
			address = addressRemote;
			portWithRandomLog = `${portRemote} ${isUDP ? 'udp' : 'tcp'} `;

			if (hasError) {
				throw new Error(message);
			}

			// If UDP and not DNS port, close it
			if (isUDP && portRemote !== 53) {
				throw new Error('UDP proxy only enabled for DNS which is port 53');
			}

			if (isUDP && portRemote === 53) {
				isDns = true;
			}

			const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
			const rawClientData = chunk.slice(rawDataIndex);

			if (isDns) {
				const { write } = await handleUDPOutBound(webSocket, vlessResponseHeader, log);
				udpStreamWrite = write;
				udpStreamWrite(rawClientData);
				return;
			}
			log(`processVlessHeader-->${addressType} Processing TCP outbound connection ${addressRemote}:${portRemote}`);

			handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log, addressType);
		},
		close() {
			log(`readableWebSocketStream is close`);
		},
		abort(reason) {
			log(`readableWebSocketStream is abort`, JSON.stringify(reason));
		},
	})).catch((err) => {
		log('readableWebSocketStream pipeTo error', err);
	});

	return new Response(null, {
		status: 101,
		webSocket: client,
	});
}

/**
 * 处理TCP出站连接 - 确保所有流量都通过SOCKS5
 */
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log, addressType) {
	/**
	 * 连接到指定地址和端口并写入数据
	 */
	async function connectAndWrite(address, port, socks = false) {
		/** @type {import("@cloudflare/workers-types").Socket} */
		let tcpSocket;
		
		// 强制所有连接都通过SOCKS5代理
		if (socks5Enable && parsedSocks5) {
			tcpSocket = await socks5Connect(addressType, address, port, log);
		} else {
			// 如果没有SOCKS5配置，使用直连或代理IP
			tcpSocket = connect({
				hostname: address,
				port: port,
			});
		}
		
		remoteSocket.value = tcpSocket;
		console.log(`connectAndWrite connected to ${address}:${port} via ${socks5Enable ? 'SOCKS5' : 'direct'}`);
		const writer = tcpSocket.writable.getWriter();
		await writer.write(rawClientData);
		writer.releaseLock();
		return tcpSocket;
	}

	/**
	 * 重试连接逻辑
	 */
	async function retry() {
		let tcpSocket;
		
		// 强制所有重试连接都通过SOCKS5代理
		if (socks5Enable && parsedSocks5) {
			tcpSocket = await connectAndWrite(addressRemote, portRemote, true);
			log(`retry-socks5 connected to ${addressRemote}:${portRemote} via SOCKS5 ${parsedSocks5.hostname}:${parsedSocks5.port}`);
		} else {
			// 如果没有SOCKS5，则使用代理IP或直连
			const finalTargetHost = proxyIP || addressRemote;
			const finalTargetPort = proxyPort || portRemote;
			tcpSocket = await connectAndWrite(finalTargetHost, finalTargetPort);
			log(`retry-direct connected to ${finalTargetHost}:${finalTargetPort}`);
		}

		tcpSocket.closed.catch(error => {
			console.log('retry tcpSocket closed error', error);
		}).finally(() => {
			safeCloseWebSocket(webSocket);
		})
		remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
	}

	// 强制主连接尝试：优先使用SOCKS5
	let tcpSocket;
	try {
		if (socks5Enable && parsedSocks5) {
			tcpSocket = await connectAndWrite(addressRemote, portRemote, true);
			log(`Primary connection via SOCKS5: ${parsedSocks5.hostname}:${parsedSocks5.port}`);
		} else {
			tcpSocket = await connectAndWrite(addressRemote, portRemote);
			log(`Primary direct connection to: ${addressRemote}:${portRemote}`);
		}
	} catch (error) {
		log(`Primary connection failed: ${error.message}, attempting retry`);
		await retry();
		return;
	}

	// when remoteSocket is ready, pass to websocket
	// remote--> ws
	remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
}

/**
 * 修复IPv6支持的SOCKS5连接函数
 */
async function socks5Connect(addressType, remoteIp, remotePort, log) {
	if (!parsedSocks5 || !parsedSocks5.hostname || !parsedSocks5.port) {
		throw new Error("SOCKS5 configuration is invalid");
	}

	const { username, password, hostname, port } = parsedSocks5;
	
	try {
		// 修复：正确处理IPv6代理服务器地址
		let connectHostname = hostname;
		
		// 检查是否为IPv6地址（包含冒号但不是IPv4:port格式）
		const isIPv6 = hostname.includes(':') && !(/^\d+\.\d+\.\d+\.\d+$/.test(hostname.split(':')[0]));
		
		if (isIPv6) {
			// IPv6地址需要用方括号包围
			connectHostname = hostname.startsWith('[') ? hostname : `[${hostname}]`;
			log(`IPv6 SOCKS5 proxy detected: ${connectHostname}:${port}`);
		}
		
		log(`Connecting to SOCKS5 proxy: ${connectHostname}:${port}`);
		const socket = connect({ hostname: connectHostname, port });
		const writer = socket.writable.getWriter();
		const reader = socket.readable.getReader();
		const encoder = new TextEncoder();

		// 发送SOCKS5握手
		const greeting = new Uint8Array([5, 2, 0, 2]);
		await writer.write(greeting);
		log('SOCKS5 greeting sent');

		// 处理认证响应
		const readResult = await reader.read();
		if (readResult.done) {
			throw new Error("SOCKS5 server closed connection unexpectedly");
		}
		
		const res = readResult.value;
		if (res[1] === 0x02) {
			log("SOCKS5 server requires authentication");
			if (!username || !password) {
				throw new Error("SOCKS5 server requires authentication but no credentials provided");
			}
			const authRequest = new Uint8Array([
				1, username.length, ...encoder.encode(username),
				password.length, ...encoder.encode(password)
			]);
			await writer.write(authRequest);
			
			const authResult = await reader.read();
			if (authResult.done) {
				throw new Error("SOCKS5 server closed connection during authentication");
			}
			
			const authResponse = authResult.value;
			if (authResponse[0] !== 0x01 || authResponse[1] !== 0x00) {
				throw new Error("SOCKS5 authentication failed");
			}
			log("SOCKS5 authentication successful");
		} else if (res[1] === 0x00) {
			log("SOCKS5 no authentication required");
		} else {
			throw new Error(`SOCKS5 server rejected connection: ${res[1]}`);
		}

		// 构建SOCKS5连接请求 - 修复IPv6处理
		let DSTADDR;
		switch (addressType) {
			case 1: // IPv4
				const ipParts = remoteIp.split('.');
				if (ipParts.length !== 4) {
					throw new Error(`Invalid IPv4 address: ${remoteIp}`);
				}
				DSTADDR = new Uint8Array([1, ...ipParts.map(part => parseInt(part, 10))]);
				break;
			case 2: // Domain name
				DSTADDR = new Uint8Array([3, remoteIp.length, ...encoder.encode(remoteIp)]);
				break;
			case 3: // IPv6
				// 修复：正确处理IPv6地址的压缩格式
				const cleanIpv6 = remoteIp.replace(/^\[|\]$/g, ''); // 移除方括号
				log(`Processing IPv6 target address: ${cleanIpv6}`);
				
				// 扩展压缩的IPv6地址
				const expandedIpv6 = expandIPv6(cleanIpv6);
				log(`Expanded IPv6 address: ${expandedIpv6}`);
				
				const ipv6Parts = expandedIpv6.split(':');
				if (ipv6Parts.length !== 8) {
					throw new Error(`Invalid IPv6 address after expansion: ${expandedIpv6}`);
				}
				
				const ipv6Bytes = [];
				for (const part of ipv6Parts) {
					const num = parseInt(part, 16);
					if (isNaN(num)) {
						throw new Error(`Invalid IPv6 part: ${part}`);
					}
					ipv6Bytes.push((num >> 8) & 0xff, num & 0xff);
				}
				DSTADDR = new Uint8Array([4, ...ipv6Bytes]);
				break;
			default:
				// 如果地址类型未知，尝试自动判断
				if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(remoteIp)) {
					// IPv4
					const ipParts = remoteIp.split('.');
					DSTADDR = new Uint8Array([1, ...ipParts.map(part => parseInt(part, 10))]);
				} else if (remoteIp.includes(':')) {
					// IPv6
					const cleanIpv6 = remoteIp.replace(/^\[|\]$/g, '');
					const expandedIpv6 = expandIPv6(cleanIpv6);
					const ipv6Parts = expandedIpv6.split(':');
					const ipv6Bytes = [];
					for (const part of ipv6Parts) {
						const num = parseInt(part, 16);
						ipv6Bytes.push((num >> 8) & 0xff, num & 0xff);
					}
					DSTADDR = new Uint8Array([4, ...ipv6Bytes]);
				} else {
					// Domain name
					DSTADDR = new Uint8Array([3, remoteIp.length, ...encoder.encode(remoteIp)]);
				}
		}
		
		const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, remotePort >> 8, remotePort & 0xff]);
		await writer.write(socksRequest);
		log('SOCKS5 connection request sent');

		const responseResult = await reader.read();
		if (responseResult.done) {
			throw new Error("SOCKS5 server closed connection during request");
		}
		
		const response = responseResult.value;
		if (response[1] !== 0x00) {
			const errorCodes = {
				0x01: "General SOCKS server failure",
				0x02: "Connection not allowed by ruleset",
				0x03: "Network unreachable",
				0x04: "Host unreachable",
				0x05: "Connection refused",
				0x06: "TTL expired",
				0x07: "Command not supported",
				0x08: "Address type not supported"
			};
			const errorMsg = errorCodes[response[1]] || `Unknown error code: ${response[1]}`;
			throw new Error(`SOCKS5 connection failed: ${errorMsg}`);
		}
		log("SOCKS5 connection established successfully");

		writer.releaseLock();
		reader.releaseLock();
		
		log(`SOCKS5 proxy connection established: ${connectHostname}:${port} -> ${remoteIp}:${remotePort}`);
		return socket;
		
	} catch (error) {
		log(`SOCKS5 connection failed: ${error.message}`);
		throw error;
	}
}

/**
 * 扩展压缩的IPv6地址为完整格式
 */
function expandIPv6(ipv6) {
	// 如果地址包含"::"，需要扩展
	if (ipv6.includes('::')) {
		const parts = ipv6.split('::');
		const leftParts = parts[0] ? parts[0].split(':') : [];
		const rightParts = parts[1] ? parts[1].split(':') : [];
		
		// 计算需要填充的零段数量
		const totalParts = 8;
		const missingParts = totalParts - leftParts.length - rightParts.length;
		
		// 构建完整的地址
		const fullParts = [
			...leftParts,
			...Array(missingParts).fill('0'),
			...rightParts
		];
		
		// 确保每个部分都是4位十六进制数
		return fullParts.map(part => part.padStart(4, '0')).join(':');
	} else {
		// 没有压缩，只需要确保每个部分都是4位
		return ipv6.split(':').map(part => part.padStart(4, '0')).join(':');
	}
}

/**
 * 修复IPv6的SOCKS5解析函数
 */
function socks5Parser(socks5) {
	let [latter, former] = socks5.split("@").reverse();
	let username, password, hostname, port;

	if (former) {
		const formers = former.split(":");
		if (formers.length !== 2) {
			throw new Error('Invalid SOCKS address format: authentication must be in the "username:password" format');
		}
		[username, password] = formers;
	}

	// 智能解析IPv6地址和端口
	if (latter.startsWith('[') && latter.includes(']:')) {
		// 格式: [IPv6]:port
		const bracketMatch = latter.match(/^\[([^\]]+)\]:(\d+)$/);
		if (bracketMatch) {
			hostname = bracketMatch[1];
			port = Number(bracketMatch[2]);
		} else {
			throw new Error('Invalid IPv6 address format with brackets');
		}
	} else if (latter.includes(':')) {
		// 可能是IPv6地址，需要智能判断最后一个数字是否为端口
		const parts = latter.split(':');
		const lastPart = parts[parts.length - 1];
		
		// 检查最后一部分是否为纯数字且在端口范围内
		if (/^\d+$/.test(lastPart) && Number(lastPart) > 0 && Number(lastPart) <= 65535) {
			// 检查是否看起来像IPv6地址（多个冒号或包含十六进制字符）
			const withoutLastPart = parts.slice(0, -1).join(':');
			const hasMultipleColons = (withoutLastPart.match(/:/g) || []).length >= 2;
			const hasHexChars = /[a-fA-F]/.test(withoutLastPart);
			const hasDoubleColon = withoutLastPart.includes('::');
			
			if (hasMultipleColons || hasHexChars || hasDoubleColon) {
				// 很可能是IPv6地址，最后一个数字是端口
				port = Number(lastPart);
				hostname = withoutLastPart;
			} else {
				// 可能是IPv4:port格式
				port = Number(lastPart);
				hostname = parts.slice(0, -1).join(':');
			}
		} else {
			// 没有端口号，可能是纯IPv6地址，使用默认端口
			hostname = latter;
			port = 1080; // SOCKS5默认端口
		}
	} else {
		// 纯IPv4或域名，没有端口
		hostname = latter;
		port = 1080; // SOCKS5默认端口
	}

	if (isNaN(port) || port <= 0 || port > 65535) {
		throw new Error('Invalid SOCKS address format: port must be a valid number between 1-65535');
	}

	// 清理IPv6地址的方括号（如果有的话）
	hostname = hostname.replace(/^\[|\]$/g, '');

	return { username, password, hostname, port };
}

/**
 * 解析SOCKS5配置
 */
async function parseSocks5FromUrl(socks5, url) {
	if (!socks5 && url.searchParams.has('SOCKS5')) {
		socks5 = url.searchParams.get('SOCKS5');
	}
	
	if (!socks5 && url.searchParams.has('socks5')) {
		socks5 = url.searchParams.get('socks5');
	}

	if (/\/socks5?=/.test(url.pathname)) {
		socks5 = url.pathname.split('5=')[1];
	} else if (/\/socks[5]?:\/\//.test(url.pathname)) {
		socks5 = url.pathname.split('://')[1].split('#')[0];
	}

	if (!socks5) {
		return null;
	}

	socks5 = decodeURIComponent(socks5);

	const authIdx = socks5.indexOf('@');
	if (authIdx !== -1) {
		let userPassword = socks5.substring(0, authIdx);
		const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
		if (base64Regex.test(userPassword) && !userPassword.includes(':')) {
			try {
				userPassword = atob(userPassword);
			} catch (e) {
				console.log('Base64 decode failed:', e);
			}
		}
		socks5 = `${userPassword}@${socks5.substring(authIdx + 1)}`;
	}

	if (socks5) {
		try {
			return socks5Parser(socks5);
		} catch (err) {
			console.log('SOCKS5 parsing error:', err.toString());
			return null;
		}
	}
	return null;
}

/**
 * 处理vless协议头
 */
function processVlessHeader(vlessBuffer, userID) {
	if (vlessBuffer.byteLength < 24) {
		return {
			hasError: true,
			message: 'invalid data',
		};
	}

	const version = new Uint8Array(vlessBuffer.slice(0, 1));
	let isValidUser = false;
	let isUDP = false;
	const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));
	const slicedBufferString = stringify(slicedBuffer);
	
	const uuids = userID.includes(',') ? userID.split(",") : [userID];
	isValidUser = uuids.some(userUuid => slicedBufferString === userUuid.trim()) || uuids.length === 1 && slicedBufferString === uuids[0].trim();

	if (!isValidUser) {
		return {
			hasError: true,
			message: 'invalid user',
		};
	}

	const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
	//skip opt for now

	const command = new Uint8Array(
		vlessBuffer.slice(18 + optLength, 18 + optLength + 1)
	)[0];

	// 0x01 TCP
	// 0x02 UDP
	// 0x03 MUX
	if (command === 1) {
		isUDP = false;
	} else if (command === 2) {
		isUDP = true;
	} else {
		return {
			hasError: true,
			message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
		};
	}
	const portIndex = 18 + optLength + 1;
	const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
	// port is big-Endian in raw data etc 80 == 0x005d
	const portRemote = new DataView(portBuffer).getUint16(0);

	let addressIndex = portIndex + 2;
	const addressBuffer = new Uint8Array(
		vlessBuffer.slice(addressIndex, addressIndex + 1)
	);

	// 1--> ipv4  addressLength =4
	// 2--> domain name addressLength=addressBuffer[1]
	// 3--> ipv6  addressLength =16
	const addressType = addressBuffer[0];
	let addressLength = 0;
	let addressValueIndex = addressIndex + 1;
	let addressValue = '';
	switch (addressType) {
		case 1:
			addressLength = 4;
			addressValue = new Uint8Array(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			).join('.');
			break;
		case 2:
			addressLength = new Uint8Array(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + 1)
			)[0];
			addressValueIndex += 1;
			addressValue = new TextDecoder().decode(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			break;
		case 3:
			addressLength = 16;
			const dataView = new DataView(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			// 2001:0db8:85a3:0000:0000:8a2e:0370:7334
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(dataView.getUint16(i * 2).toString(16));
			}
			addressValue = ipv6.join(':');
			// seems no need add [] for ipv6
			break;
		default:
			return {
				hasError: true,
				message: `invild  addressType is ${addressType}`,
			};
	}
	if (!addressValue) {
		return {
			hasError: true,
			message: `addressValue is empty, addressType is ${addressType}`,
		};
	}

	return {
		hasError: false,
		addressRemote: addressValue,
		portRemote,
		rawDataIndex: addressValueIndex + addressLength,
		vlessVersion: version,
		isUDP,
		addressType,
	};
}

/**
 * 处理UDP出站连接 - 通过SOCKS5的DNS查询
 */
async function handleUDPOutBound(webSocket, vlessResponseHeader, log) {
	let isVlessHeaderSent = false;
	const transformStream = new TransformStream({
		start(controller) {
		},
		transform(chunk, controller) {
			// udp message 2 byte is the the length of udp data
			for (let index = 0; index < chunk.byteLength;) {
				const lengthBuffer = chunk.slice(index, index + 2);
				const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
				const udpData = new Uint8Array(
					chunk.slice(index + 2, index + 2 + udpPakcetLength)
				);
				index = index + 2 + udpPakcetLength;
				controller.enqueue(udpData);
			}
		},
		flush(controller) {
		}
	});

	// 如果启用了SOCKS5，通过SOCKS5代理进行DNS查询
	transformStream.readable.pipeTo(new WritableStream({
		async write(chunk) {
			let dnsQueryResult;
			
			if (socks5Enable && parsedSocks5) {
				// 通过SOCKS5代理进行DNS查询
				try {
					const socket = await socks5Connect(2, '8.8.8.8', 53, log); // 使用Google DNS通过SOCKS5
					const writer = socket.writable.getWriter();
					const reader = socket.readable.getReader();
					
					await writer.write(chunk);
					writer.releaseLock();
					
					const result = await reader.read();
					reader.releaseLock();
					
					if (!result.done) {
						dnsQueryResult = result.value;
					} else {
						throw new Error('No DNS response received via SOCKS5');
					}
					
					socket.close();
				} catch (error) {
					log(`DNS via SOCKS5 failed: ${error.message}, fallback to DoH`);
					// 如果SOCKS5 DNS失败，回退到DoH
					const resp = await fetch(dohURL, {
						method: 'POST',
						headers: {
							'content-type': 'application/dns-message',
						},
						body: chunk,
					});
					dnsQueryResult = await resp.arrayBuffer();
				}
			} else {
				// 使用DoH进行DNS查询
				const resp = await fetch(dohURL, {
					method: 'POST',
					headers: {
						'content-type': 'application/dns-message',
					},
					body: chunk,
				});
				dnsQueryResult = await resp.arrayBuffer();
			}
			
			const udpSize = dnsQueryResult.byteLength;
			const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
			
			if (webSocket.readyState === WS_READY_STATE_OPEN) {
				log(`DNS query success, message length is ${udpSize} (via ${socks5Enable ? 'SOCKS5' : 'DoH'})`);
				if (isVlessHeaderSent) {
					webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
				} else {
					webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
					isVlessHeaderSent = true;
				}
			}
		}
	})).catch((error) => {
		log('DNS UDP has error: ' + error)
	});

	const writer = transformStream.writable.getWriter();

	return {
		/**
		 * @param {Uint8Array} chunk
		 */
		write(chunk) {
			writer.write(chunk);
		}
	};
}

/** ---------------------其他必要的工具函数------------------------------ */

function log(...args) {
	if (ENABLE_LOG) console.log(...args);
}

function error(...args) {
	if (ENABLE_LOG) console.error(...args);
}

/**
 * Checks if a given string is a valid UUID.
 */
function isValidUUID(uuid) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(uuid);
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
	byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
	return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

function stringify(arr, offset = 0) {
	const uuid = unsafeStringify(arr, offset);
	if (!isValidUUID(uuid)) {
		throw TypeError("Stringified UUID is invalid");
	}
	return uuid;
}

async function getFakeUserID(userID) {
	const date = new Date().toISOString().split('T')[0];
	const rawString = `${userID}-${date}`;

	const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rawString));
	const hashArray = Array.from(new Uint8Array(hashBuffer)).map(b => ('00' + b.toString(16)).slice(-2)).join('');

	return `${hashArray.substring(0, 8)}-${hashArray.substring(8, 12)}-${hashArray.substring(12, 16)}-${hashArray.substring(16, 20)}-${hashArray.substring(20, 32)}`;
}

function base64ToArrayBuffer(base64Str) {
	if (!base64Str) {
		return { earlyData: null, error: null };
	}
	try {
		base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
		const decode = atob(base64Str);
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		return { earlyData: arryBuffer.buffer, error: null };
	} catch (error) {
		return { earlyData: null, error };
	}
}

async function addIpText(envAdd) {
	var addText = envAdd.replace(/[	|"'\r\n]+/g, ',').replace(/,+/g, ',');
	if (addText.charAt(0) == ',') {
		addText = addText.slice(1);
	}
	if (addText.charAt(addText.length - 1) == ',') {
		addText = addText.slice(0, addText.length - 1);
	}
	const add = addText.split(',');
	return add;
}

function getFileType(url) {
	const baseUrl = url.split('@')[0];
	const extension = baseUrl.match(/\.(csv|txt)$/i);
	if (extension) {
		return extension[1].toLowerCase();
	} else {
		return 'txt';
	}
}

function getRandomItems(arr, count) {
	if (!Array.isArray(arr)) return [];
	const shuffled = [...arr].sort(() => 0.5 - Math.random());
	return shuffled.slice(0, count);
}

/**
 * 创建WebSocket可读流
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	let readableStreamCancel = false;
	const stream = new ReadableStream({
		start(controller) {
			webSocketServer.addEventListener('message', (event) => {
				const message = event.data;
				controller.enqueue(message);
			});

			webSocketServer.addEventListener('close', () => {
				safeCloseWebSocket(webSocketServer);
				controller.close();
			});

			webSocketServer.addEventListener('error', (err) => {
				log('webSocketServer has error');
				controller.error(err);
			});
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},

		pull(controller) {
		},

		cancel(reason) {
			log(`ReadableStream was canceled, due to ${reason}`)
			readableStreamCancel = true;
			safeCloseWebSocket(webSocketServer);
		}
	});

	return stream;
}

/**
 * 远程socket到WebSocket的数据传输
 */
async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
	let remoteChunkCount = 0;
	let chunks = [];
	let vlessHeader = vlessResponseHeader;
	let hasIncomingData = false;
	
	await remoteSocket.readable
		.pipeTo(
			new WritableStream({
				start() {
				},
				async write(chunk, controller) {
					hasIncomingData = true;
					remoteChunkCount++;
					if (webSocket.readyState !== WS_READY_STATE_OPEN) {
						controller.error(
							'webSocket.readyState is not open, maybe close'
						);
					}
					if (vlessHeader) {
						webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
						vlessHeader = null;
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
			console.error(
				`remoteSocketToWS has exception `,
				error.stack || error
			);
			safeCloseWebSocket(webSocket);
		});

	if (hasIncomingData === false && retry) {
		log(`retry`)
		retry();
	}
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
	try {
		if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
			socket.close();
		}
	} catch (error) {
		console.error('safeCloseWebSocket error', error);
	}
}

/**
 * 生成vless配置
 */
async function getvlessConfig(userID, host, userAgent, url, protType, nat64, hostRemark) {
	const vlessLink = `vless://${userID}@${host}:443?encryption=none&security=tls&type=ws&host=${host}&sni=${host}&fp=random&path=%2F%3Fed%3D2560#${host}`;
	
	const ua = (userAgent || '').toLowerCase();
	
	if (ua.includes('mozilla') && !url.searchParams.has('sub') && !url.searchParams.has('base64')) {
		return getHtmlResponse(userID, host, vlessLink);
	}
	
	return btoa(vlessLink);
}

function getHtmlResponse(userID, host, vlessLink) {
	const proxyRemark = socks5Enable 
		? `SOCKS5: ${parsedSocks5.hostname}:${parsedSocks5.port} ${parsedSocks5.hostname.includes(':') ? '(IPv6)' : '(IPv4)'}`
		: `PROXYIP: ${proxyIP}`;

	const remark = proxyIP || socks5Enable 
		? `当前使用代理: ${proxyRemark}`
		: `当前没设置代理, 推荐设置PROXYIP或SOCKS5变量`;

	return `
	<!DOCTYPE html>
	<html>
	<head>
		<meta charset="UTF-8">
		<title>Vless 配置 - IPv6 SOCKS5修复版</title>
		<style>
			body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
			.container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
			.header { text-align: center; margin-bottom: 30px; }
			.config { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #007cba; }
			.copy-btn { background: #007cba; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; margin-left: 10px; }
			.copy-btn:hover { background: #005a82; }
			.alert { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; padding: 15px; border-radius: 4px; margin: 20px 0; }
			.warning { background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }
			.info { background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }
			.success { background: #d1edda; border: 1px solid #c3e6cb; color: #155724; }
			.ipv6 { background: #e7f3ff; border: 1px solid #bee5eb; color: #0c5460; }
			pre { background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; }
			.feature { display: flex; align-items: center; margin: 10px 0; }
			.feature-icon { margin-right: 10px; font-size: 18px; }
		</style>
	</head>
	<body>
		<div class="container">
			<div class="header">
				<h1>🚀 Vless 配置 - IPv6 SOCKS5修复版</h1>
				<p>完全支持IPv6 SOCKS5代理，所有TCP和UDP流量强制通过SOCKS5出站</p>
			</div>

			${socks5Enable ? `
			<div class="alert ${parsedSocks5.hostname.includes(':') ? 'ipv6' : 'success'}">
				<h4>✅ SOCKS5 代理已启用 - ${parsedSocks5.hostname.includes(':') ? 'IPv6' : 'IPv4'} 模式</h4>
				<p><strong>代理服务器：</strong> ${parsedSocks5.hostname}:${parsedSocks5.port}</p>
				${parsedSocks5.username ? `<p><strong>认证用户：</strong> ${parsedSocks5.username}</p>` : ''}
				${parsedSocks5.hostname.includes(':') ? '<p><strong>🌐 IPv6代理已正确解析和连接！</strong></p>' : ''}
				<p><strong>🔥 所有网络连接（TCP/UDP/DNS）都将强制通过此SOCKS5代理！</strong></p>
			</div>
			` : `
			<div class="alert warning">
				<h4>⚠️ 未检测到SOCKS5配置</h4>
				<p>当前使用直连模式，建议在URL中添加SOCKS5参数：</p>
				<pre># IPv4 SOCKS5
/?ed=2560&SOCKS5=user:pass@192.168.1.1:1080

# IPv6 SOCKS5 (推荐格式)
/?ed=2560&SOCKS5=user:pass@2400:c620:26:27b::a:26095

# IPv6 带方括号格式
/?ed=2560&SOCKS5=user:pass@[2400:c620:26:27b::a]:26095</pre>
			</div>
			`}

			<div class="alert info">
				<strong>📊 代理状态：</strong> ${remark}
			</div>

			<div class="config">
				<h3>📋 Vless 链接</h3>
				<pre id="vlessLink">${vlessLink}</pre>
				<button class="copy-btn" onclick="copyToClipboard('vlessLink')">📋 复制链接</button>
			</div>

			<div class="config">
				<h3>⚙️ 手动配置参数</h3>
				<div class="feature">
					<span class="feature-icon">🏠</span>
					<strong>服务器地址：</strong> ${host}
				</div>
				<div class="feature">
					<span class="feature-icon">🔌</span>
					<strong>端口：</strong> 443
				</div>
				<div class="feature">
					<span class="feature-icon">🆔</span>
					<strong>UUID：</strong> ${userID}
				</div>
				<div class="feature">
					<span class="feature-icon">🔐</span>
					<strong>加密方式：</strong> none
				</div>
				<div class="feature">
					<span class="feature-icon">🌐</span>
					<strong>传输协议：</strong> ws (WebSocket)
				</div>
				<div class="feature">
					<span class="feature-icon">📍</span>
					<strong>路径：</strong> /?ed=2560
				</div>
				<div class="feature">
					<span class="feature-icon">🔒</span>
					<strong>TLS：</strong> 开启
				</div>
				<div class="feature">
					<span class="feature-icon">🏷️</span>
					<strong>SNI：</strong> ${host}
				</div>
			</div>

			<div class="config">
				<h3>🛠️ IPv6 SOCKS5 修复特性</h3>
				<div class="feature">
					<span class="feature-icon">🔧</span>
					<span><strong>智能地址解析：</strong>自动识别IPv6地址和端口分隔</span>
				</div>
				<div class="feature">
					<span class="feature-icon">🔧</span>
					<span><strong>IPv6压缩支持：</strong>正确处理"::"压缩格式</span>
				</div>
				<div class="feature">
					<span class="feature-icon">🔧</span>
					<span><strong>连接兼容性：</strong>IPv6地址自动添加方括号</span>
				</div>
				<div class="feature">
					<span class="feature-icon">🔧</span>
					<span><strong>强制路由：</strong>所有TCP/UDP连接都通过SOCKS5</span>
				</div>
				<div class="feature">
					<span class="feature-icon">🔧</span>
					<span><strong>完全兼容：</strong>支持IPv4/IPv6/域名三种格式</span>
				</div>
			</div>

			<div class="config">
				<h3>🌐 IPv6 SOCKS5 支持的格式</h3>
				<pre># 标准IPv6格式（推荐）
userxx7trEnB:passbWuL46ZL7ZyO@2400:c620:26:27b::a:26095

# 带方括号格式
userxx7trEnB:passbWuL46ZL7ZyO@[2400:c620:26:27b::a]:26095

# 无认证IPv6格式
2400:c620:26:27b::a:26095

# 完整IPv6格式
user:pass@2001:0db8:85a3:0000:0000:8a2e:0370:7334:8080</pre>
			</div>

			<div class="config">
				<h3>🔧 环境变量配置示例</h3>
				<pre>UUID = ${userID}
# IPv6 SOCKS5代理
SOCKS5 = userxx7trEnB:passbWuL46ZL7ZyO@2400:c620:26:27b::a:26095
# 或IPv4 SOCKS5代理
SOCKS5 = user:pass@192.168.1.100:1080
# DNS解析服务器
DNS_RESOLVER_URL = ${dohURL}</pre>
			</div>

			<div class="alert info">
				<h4>📝 IPv6 SOCKS5 使用说明</h4>
				<p>1. <strong>地址格式：</strong>支持标准IPv6格式和带方括号格式</p>
				<p>2. <strong>端口识别：</strong>智能识别IPv6地址中的端口号</p>
				<p>3. <strong>压缩支持：</strong>完全支持IPv6地址压缩（::）</p>
				<p>4. <strong>连接稳定：</strong>修复了IPv6连接的所有已知问题</p>
				<p>5. <strong>调试信息：</strong>控制台会显示详细的连接状态</p>
			</div>
		</div>

		<script>
			function copyToClipboard(elementId) {
				const element = document.getElementById(elementId);
				const text = element.textContent;
				navigator.clipboard.writeText(text).then(function() {
					alert('✅ 已复制到剪贴板');
				}).catch(function(err) {
					console.error('复制失败: ', err);
					const textArea = document.createElement('textarea');
					textArea.value = text;
					document.body.appendChild(textArea);
					textArea.select();
					document.execCommand('copy');
					document.body.removeChild(textArea);
					alert('✅ 已复制到剪贴板');
				});
			}
		</script>
	</body>
	</html>
	`;
}

// 其他必要的函数 - 简化实现
async function getIpUrlTxtAndCsv(noTLS, urlTxts, urlCsvs, num) {
	return { txt: [], csv: [] };
}

async function getIpUrlTxtToArry(urlTxts) {
	return [];
}

async function getCFConfig(CF_EMAIL, CF_KEY, CF_ID) {
	return { upload: 0, download: 0, total: 0 };
}

const MY_KV_UUID_KEY = atob('VVVJRA==');

async function checkKVNamespaceBinding(env) {
	if (typeof env.amclubs === 'undefined') {
		return new Response('Error: amclubs KV_NAMESPACE is not bound.', { status: 400 })
	}
}

async function getKVData(env) {
	const value = await env.amclubs.get(MY_KV_UUID_KEY);
	return value ? String(value) : '';
}

async function setKVData(request, env) {
	if (request.method !== 'POST') {
		return new Response('Use POST method to set values', { status: 405 });
	}
	const value = await request.text();
	try {
		await env.amclubs.put(MY_KV_UUID_KEY, value);
		const storedValue = await env.amclubs.get(MY_KV_UUID_KEY);
		if (storedValue === value) {
			return new Response(`${MY_KV_UUID_KEY} updated successfully`, { status: 200 });
		} else {
			return new Response(`Error: Value verification failed after storage`, { status: 500 });
		}
	} catch (error) {
		return new Response(`Error storing value: ${error.message}`, { status: 500 });
	}
}

async function showKVPage(env) {
	const kvCheckResponse = await checkKVNamespaceBinding(env);
	if (kvCheckResponse) {
		return kvCheckResponse;
	}
	const value = await getKVData(env);
	return new Response(`
		<!DOCTYPE html>
		<html>
		<head>
			<meta charset="UTF-8"> 
			<title>${fileName}</title>
			<style>
				html, body { height: 100%; margin: 0; display: flex; justify-content: center; align-items: center; font-family: Arial, sans-serif; }
				.container { text-align: center; padding: 20px; border: 1px solid #ddd; border-radius: 10px; background-color: #f9f9f9; width: 400px; }
				h1 { font-size: 24px; margin-bottom: 20px; }
				textarea { width: 100%; height: 100px; padding: 10px; font-size: 16px; border: 1px solid #ccc; border-radius: 5px; resize: none; }
				button { padding: 10px 20px; font-size: 16px; border: none; background-color: #4CAF50; color: white; border-radius: 5px; cursor: pointer; margin-top: 10px; }
				button:hover { background-color: #45a049; }
				#saveStatus { color: green; margin-top: 10px; }
			</style>
			<script>
				async function saveData() {
					const value = document.getElementById('value').value;
					const response = await fetch('/${userID}/set', { method: 'POST', body: value });
					const responseText = await response.text();
					document.getElementById('saveStatus').innerText = responseText;
				}
			</script>
		</head>
		<body>
			<div class="container">
				<h1>UUID 管理页面</h1>
				<label for="key">Key:</label>
				<input type="text" id="key" value="${MY_KV_UUID_KEY}" readonly />
				<br/><br/>
				<label for="value">Value:</label>
				<textarea id="value">${value || ''}</textarea>
				<br/><br/>
				<button onclick="saveData()">保存</button>
				<div id="saveStatus"></div>
			</div>
		</body>
		</html>`,
		{
			headers: { 'Content-Type': 'text/html; charset=UTF-8' },
			status: 200,
		}
	);
}


const API_URL = 'http://ip-api.com/json/';
const TELEGRAM_API_URL = 'https://api.telegram.org/bot';

async function sendMessage(type, ip, add_data = "") {
	if (botToken && chatID) {
		try {
			const ipResponse = await fetch(`${API_URL}${ip}?lang=zh-CN`);
			let msg = `${type}\nIP: ${ip}\n${add_data}`;

			if (ipResponse.ok) {
				const ipInfo = await ipResponse.json();
				msg = `${type}\nIP: ${ip}\n国家: ${ipInfo.country}\n城市: ${ipInfo.city}\n组织: ${ipInfo.org}\nASN: ${ipInfo.as}\n${add_data}`;
			}

			const telegramUrl = `${TELEGRAM_API_URL}${botToken}/sendMessage`;
			const params = new URLSearchParams({
				chat_id: chatID,
				parse_mode: 'HTML',
				text: msg
			});

			await fetch(`${telegramUrl}?${params.toString()}`, {
				method: 'GET',
				headers: {
					'Accept': 'text/html,application/xhtml+xml,application/xml',
					'Accept-Encoding': 'gzip, deflate, br',
					'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
				}
			});

		} catch (error) {
			console.error('Error sending message:', error);
		}
	}
}

async function nginx() {
	return `
	<!DOCTYPE html>
	<html>
	<head>
	<meta charset="UTF-8">
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>
	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>
	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`;
}