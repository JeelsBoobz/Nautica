import { connect } from "cloudflare:sockets";

// Variables
let cachedProxyList = [];
let proxyIP = "";

// Constant
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CORS_HEADER_OPTIONS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,HEAD",
  "Access-Control-Max-Age": "86400",
};

async function getProxyList(env, forceReload = false) {
    if (!cachedProxyList.length || forceReload) {
        const proxyBankUrl = env.PROXY_BANK_URL || "";
        if (!proxyBankUrl) {
            throw new Error("No Proxy Bank URL Provided!");
        }

        const proxyBank = await fetch(proxyBankUrl);
        if (proxyBank.status === 200) {
            try {
                const proxyData = await proxyBank.json();
                if (Array.isArray(proxyData)) {
                    cachedProxyList = proxyData.filter(
                        (entry) =>
                            entry.country &&
                            entry.proxy
                    );
                }
            } catch (err) {
                throw new Error("Invalid JSON format in Proxy Bank URL");
            }
        }
    }

    return cachedProxyList;
}

async function reverseProxy(request, target) {
    const targetUrl = new URL(request.url);
    const targetChunk = target.split(":");

    targetUrl.hostname = targetChunk[0];
    targetUrl.port = targetChunk.toString() || "443";

    const modifiedRequest = new Request(targetUrl, request);
 
    modifiedRequest.headers.set("X-Forwarded-Host", request.headers.get("Host"));

    const response = await fetch(modifiedRequest);

    const newResponse = new Response(response.body, response);
    for (const [key, value] of Object.entries(CORS_HEADER_OPTIONS)) {
        newResponse.headers.set(key, value);
    }
    newResponse.headers.set("X-Proxied-By", "Cloudflare Worker");

    return newResponse;
}

function getProxyCC(cc, proxyList) {
    const entry = proxyList.find(item => item.country.toLowerCase() === cc.toLowerCase());
    return entry ? entry.proxy : null;
}

export default {
    async fetch(request, env, ctx) {
        try {
            const url = new URL(request.url);
            const upgradeHeader = request.headers.get("Upgrade");

            if (upgradeHeader === "websocket") {
                const ccPath = url.pathname.match(/^\/cc\/([A-Za-z]{2})$/);

                if (ccPath) {
                    const cc = ccPath[1];
                    const ccMatch = getProxyCC(cc, await getProxyList(env, true));

                    if (ccMatch) {
                        proxyIP = ccMatch;
                        return await websockerHandler(request);
                    }
                }

                const proxyMatch = url.pathname.match(/^\/(.+[:=-]\d+)$/);

                if (proxyMatch) {
                    proxyIP = proxyMatch[1];
                    return await websockerHandler(request);
                }
            }

            const targetReverseProxy = env.REVERSE_PROXY_TARGET || "example.com";
            return await reverseProxy(request, targetReverseProxy);
        } catch (err) {
            return new Response(`An error occurred: ${err.toString()}`, {
                status: 500,
                headers: {
                    ...CORS_HEADER_OPTIONS,
                },
            });
        }
    },
};

async function websocketHandler(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);

    webSocket.accept();

    let addressLog = "";
    let portLog = "";
    const log = (info, event) => {
        console.log(`[${addressLog}:${portLog}] ${info}`, event || "");
    };
    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";

    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    let remoteSocketWrapper = {
        value: null,
    };
    let udpStreamWrite = null;
    let isDNS = false;

    readableWebSocketStream
        .pipeTo(
            new WritableStream({
                async write(chunk, controller) {
                    if (isDNS && udpStreamWrite) {
                        return udpStreamWrite(chunk);
                    }
                    if (remoteSocketWrapper.value) {
                        const writer = remoteSocketWrapper.value.writable.getWriter();
                        await writer.write(chunk);
                        writer.releaseLock();
                        return;
                    }

                    const protocol = await protocolSniffer(chunk);
                    let protocolHeader;

                    if (protocol === "Trojan") {
                        protocolHeader = parseTrojanHeader(chunk);
                    } else if (protocol === "VLESS") {
                        protocolHeader = parseVlessHeader(chunk);
                    } else if (protocol === "Shadowsocks") {
                        protocolHeader = parseShadowsocksHeader(chunk);
                    } else {
                        parseVmessHeader(chunk);
                        throw new Error("Unknown Protocol!");
                    }

                    addressLog = protocolHeader.addressRemote;
                    portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;

                    if (protocolHeader.hasError) {
                        throw new Error(protocolHeader.message);
                    }

                    if (protocolHeader.isUDP) {
                        if (protocolHeader.portRemote === 53) {
                            isDNS = true;
                        } else {
                            throw new Error("UDP only support for DNS port 53");
                        }
                    }

                    if (isDNS) {
                        const { write } = await handleUDPOutbound(webSocket, protocolHeader.version, log);
                        udpStreamWrite = write;
                        udpStreamWrite(protocolHeader.rawClientData);
                        return;
                    }

                    handleTCPOutBound(
                        remoteSocketWrapper,
                        protocolHeader.addressRemote,
                        protocolHeader.portRemote,
                        protocolHeader.rawClientData,
                        webSocket,
                        protocolHeader.version,
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

async function protocolSniffer(buffer) {
    if (buffer.byteLength >= 62) {
        const trojanDelimiter = new Uint8Array(buffer.slice(56, 60));
        if (trojanDelimiter[0] === 0x0d && trojanDelimiter[1] === 0x0a) {
            if (trojanDelimiter[2] === 0x01 || trojanDelimiter[2] === 0x03 || trojanDelimiter[2] === 0x7f) {
                if (trojanDelimiter[3] === 0x01 || trojanDelimiter[3] === 0x03 || trojanDelimiter[3] === 0x04) {
                    return "Trojan";
                }
            }
        }
    }

    const vlessDelimiter = new Uint8Array(buffer.slice(1, 17));
    // Hanya mendukung UUID v4
    if (arrayBufferToHex(vlessDelimiter).match(/^[0-9a-f]{8}[0-9a-f]{4}4[0-9a-f]{3}[89ab][0-9a-f]{3}[0-9a-f]{12}$/i)) {
        return "VLESS";
    }

    return "Shadowsocks"; // default
}

async function handleTCPOutBound(
    remoteSocket,
    addressRemote,
    portRemote,
    rawClientData,
    webSocket,
    responseHeader,
    log
) {
    async function connectAndWrite(address, port) {
        const tcpSocket = connect({
            hostname: address,
            port: port,
        });
        remoteSocket.value = tcpSocket;
        log(`connected to ${address}:${port}`);
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();

        return tcpSocket;
    }

    async function retry() {
        const tcpSocket = await connectAndWrite(
            proxyIP.split(/[:=-]/)[0] || addressRemote,
            proxyIP.split(/[:=-]/)[1] || portRemote
        );
        tcpSocket.closed
            .catch((error) => {
                console.log("retry tcpSocket closed error", error);
            })
            .finally(() => {
                safeCloseWebSocket(webSocket);
            });
        remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
    }

    const tcpSocket = await connectAndWrite(addressRemote, portRemote);

    remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
}

async function handleUDPOutbound(webSocket, responseHeader, log) {
    let isHeaderSent = false;
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
                    const resp = await fetch(DOH_SERVER, {
                        method: "POST",
                        headers: {
                            "content-type": "application/dns-message",
                        },
                        body: chunk,
                    });
                    const dnsQueryResult = await resp.arrayBuffer();
                    const udpSize = dnsQueryResult.byteLength;
                    const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
                    if (webSocket.readyState === WS_READY_STATE_OPEN) {
                        log(`doh success and dns message length is ${udpSize}`);
                        if (isHeaderSent) {
                            webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                        } else {
                            webSocket.send(await new Blob([responseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                            isHeaderSent = true;
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

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener("message", (event) => {
                if (readableStreamCancel) {
                    return;
                }
                const message = event.data;
                controller.enqueue(message);
            });
            webSocketServer.addEventListener("close", () => {
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) {
                    return;
                }
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
            if (readableStreamCancel) {
                return;
            }
            log(`ReadableStream was canceled, due to ${reason}`);
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        },
    });

    return stream;
}

function parseVmessHeader(vmessBuffer) {
    // https://xtls.github.io/development/protocols/vmess.html#%E6%8C%87%E4%BB%A4%E9%83%A8%E5%88%86
}

function parseShadowsocksHeader(ssBuffer) {
    const view = new DataView(ssBuffer);

    const addressType = view.getUint8(0);
    let addressLength = 0;
    let addressValueIndex = 1;
    let addressValue = "";

    switch (addressType) {
        case 1:
            addressLength = 4;
            addressValue = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
            break;
        case 3:
            addressLength = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 4:
            addressLength = 16;
            const dataView = new DataView(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(":");
            break;
        default:
            return {
                hasError: true,
                message: `Invalid addressType for Shadowsocks: ${addressType}`,
            };
    }

    if (!addressValue) {
        return {
            hasError: true,
            message: `Destination address empty, address type is: ${addressType}`,
        };
    }

    const portIndex = addressValueIndex + addressLength;
    const portBuffer = ssBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    return {
        hasError: false,
        addressRemote: addressValue,
        addressType: addressType,
        portRemote: portRemote,
        rawDataIndex: portIndex + 2,
        rawClientData: ssBuffer.slice(portIndex + 2),
        version: null,
        isUDP: portRemote == 53,
    };
}

function parseVlessHeader(vlessBuffer) {
    const version = new Uint8Array(vlessBuffer.slice(0, 1));
    let isUDP = false;

    const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];

    const cmd = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
    if (cmd === 1) {
    } else if (cmd === 2) {
        isUDP = true;
    } else {
        return {
            hasError: true,
            message: `command ${cmd} is not support, command 01-tcp,02-udp,03-mux`,
        };
    }
    const portIndex = 18 + optLength + 1;
    const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);

    let addressIndex = portIndex + 2;
    const addressBuffer = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1));

    const addressType = addressBuffer[0];
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = "";
    switch (addressType) {
        case 1: // For IPv4
            addressLength = 4;
            addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
            break;
        case 2: // For Domain
            addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 3: // For IPv6
            addressLength = 16;
            const dataView = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(":");
            break;
        default:
            return {
                hasError: true,
                message: `invild    addressType is ${addressType}`,
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
        addressType: addressType,
        portRemote: portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        rawClientData: vlessBuffer.slice(addressValueIndex + addressLength),
        version: new Uint8Array([version[0], 0]),
        isUDP: isUDP,
    };
}

function parseTrojanHeader(buffer) {
    const socks5DataBuffer = buffer.slice(58);
    if (socks5DataBuffer.byteLength < 6) {
        return {
            hasError: true,
            message: "invalid SOCKS5 request data",
        };
    }

    let isUDP = false;
    const view = new DataView(socks5DataBuffer);
    const cmd = view.getUint8(0);
    if (cmd == 3) {
        isUDP = true;
    } else if (cmd != 1) {
        throw new Error("Unsupported command type!");
    }

    let addressType = view.getUint8(1);
    let addressLength = 0;
    let addressValueIndex = 2;
    let addressValue = "";
    switch (addressType) {
        case 1: // For IPv4
            addressLength = 4;
            addressValue = new Uint8Array(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(
                "."
            );
            break;
        case 3: // For Domain
            addressLength = new Uint8Array(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(
                socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            );
            break;
        case 4: // For IPv6
            addressLength = 16;
            const dataView = new DataView(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(":");
            break;
        default:
            return {
                hasError: true,
                message: `invalid addressType is ${addressType}`,
            };
    }

    if (!addressValue) {
        return {
            hasError: true,
            message: `address is empty, addressType is ${addressType}`,
        };
    }

    const portIndex = addressValueIndex + addressLength;
    const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    return {
        hasError: false,
        addressRemote: addressValue,
        addressType: addressType,
        portRemote: portRemote,
        rawDataIndex: portIndex + 4,
        rawClientData: socks5DataBuffer.slice(portIndex + 4),
        version: null,
        isUDP: isUDP,
    };
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
    let header = responseHeader;
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
                    if (header) {
                        webSocket.send(await new Blob([header, chunk]).arrayBuffer());
                        header = null;
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

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        console.error("safeCloseWebSocket error", error);
    }
}
