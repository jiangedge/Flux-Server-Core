package com.flux.client.network;

import com.flux.client.FluxClient;
import com.flux.client.config.Config;
import com.flux.client.crypto.KeyExchange;
import com.flux.client.crypto.PacketCipher;
import com.flux.client.protocol.FluxPacket;
import com.flux.client.protocol.PacketType;
import com.flux.client.protocol.SeqManager;

import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.BiConsumer;

public class NetworkClient {

    private Socket tcpSocket;
    private DataInputStream tcpIn;
    private DataOutputStream tcpOut;

    private final KeyExchange keyExchange = new KeyExchange();
    private final PacketCipher cipher = new PacketCipher();
    private final SeqManager seqManager = new SeqManager();

    private final BlockingQueue<FluxPacket> inboundQueue = new LinkedBlockingQueue<>(Config.maxQueuedPackets);
    private final ByteBuffer readBuffer = ByteBuffer.allocate(Config.maxPacketSize * 2);

    private volatile boolean connected = false;
    private volatile boolean authenticated = false;
    private Thread readThread;

    // 缓存同步阶段收到的 CHUNK_LOG_ENTRY 包，供 WorldSync 回放
    private final java.util.List<FluxPacket> cachedSyncPackets = new java.util.ArrayList<>();

    // 回调接口用于非阻塞模式下的包处理
    private BiConsumer<PacketType, byte[]> packetCallback;

    public boolean connect() {
        try {
            tcpSocket = new Socket(Config.serverHost, Config.serverPort);
            tcpSocket.setTcpNoDelay(true);
            tcpSocket.setKeepAlive(true);
            tcpSocket.setSoTimeout(0);

            tcpIn = new DataInputStream(new BufferedInputStream(tcpSocket.getInputStream()));
            tcpOut = new DataOutputStream(new BufferedOutputStream(tcpSocket.getOutputStream()));

            startReadThread();
            connected = true;

            return performHandshake();
        } catch (IOException e) {
            FluxClient.LOGGER.error("[Flux] TCP connect failed: {}", e.getMessage());
            return false;
        }
    }

    private boolean performHandshake() {
        try {
            keyExchange.generateKeyPair();
            byte[] publicKey = keyExchange.getClientPublicKey();

            ByteBuffer buf = ByteBuffer.allocate(FluxPacket.HEADER_SIZE + publicKey.length);
            buf.order(ByteOrder.BIG_ENDIAN);
            buf.putShort(FluxPacket.MAGIC);
            buf.put(PacketType.CLIENT_HELLO.code);
            buf.putInt(publicKey.length);
            buf.put(new byte[12]);
            buf.put(publicKey);

            synchronized (tcpOut) {
                tcpOut.write(buf.array());
                tcpOut.flush();
            }

            FluxPacket response = waitForPacket(PacketType.SERVER_HELLO, 5000);
            if (response == null) return false;

            cipher.init(keyExchange.computeSharedSecret(response.getPayload()));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    //桥接方法

    public void setPacketCallback(BiConsumer<PacketType, byte[]> callback) {
        this.packetCallback = callback;
    }

    public boolean isAuthenticated() {
        return this.authenticated;
    }

    public boolean isConnected() {
        return this.connected && this.tcpSocket != null && !this.tcpSocket.isClosed();
    }

    public boolean authenticate(UUID uuid, String username) {
        return authenticateAndSync(uuid, username);
    }

    public void pollIncomingPackets() {
        while (!inboundQueue.isEmpty()) {
            FluxPacket pkt = inboundQueue.poll();
            if (pkt != null && packetCallback != null) {
                packetCallback.accept(pkt.getType(), pkt.getPayload());
            }
        }
    }

    // 业务逻辑

    public boolean authenticateAndSync(UUID uuid, String username) {
        byte[] authData = FluxPacket.encodeAuthRequest(uuid, username);
        sendPacket(new FluxPacket(PacketType.AUTH_REQUEST, authData, cipher.generateIV(), seqManager.nextSendSeq()));

        FluxPacket authRes = waitForPacket(PacketType.AUTH_SUCCESS, 10000);
        if (authRes == null) {
            this.authenticated = false;
            return false;
        }
        this.authenticated = true;

        FluxClient.LOGGER.info("[Flux] 开始同步世界数据...");
        boolean syncFinished = false;
        while (!syncFinished && connected) {
            FluxPacket pkt = waitForPacket(null, 500);
            if (pkt == null) continue;

            if (pkt.getType() == PacketType.SEED_SYNC) {
                Config.currentWorldSeed = ByteBuffer.wrap(pkt.getPayload()).order(ByteOrder.LITTLE_ENDIAN).getLong();
                FluxClient.LOGGER.info("[Flux] Seed received in auth phase: {}", Config.currentWorldSeed);
            } else if (pkt.getType() == PacketType.SYNC_COMPLETE) {
                syncFinished = true;
            } else if (pkt.getType() == PacketType.CHUNK_LOG_ENTRY) {
                // 缓存事件回放包，供 WorldSync 后续使用
                cachedSyncPackets.add(pkt);
            } else {
                if (packetCallback != null) packetCallback.accept(pkt.getType(), pkt.getPayload());
            }
        }
        return true;
    }

    public void sendPacket(FluxPacket packet) {
        if (!connected) return;
        try {
            byte[] encrypted = cipher.encrypt(packet.encodePayload(), packet.getIv());
            synchronized (tcpOut) {
                tcpOut.write(packet.encodeWire(encrypted));
                tcpOut.flush();
            }
        } catch (Exception e) { FluxClient.LOGGER.error("[Flux] Send failed: {}", e.getMessage()); }
    }

    private FluxPacket waitForPacket(PacketType expectedType, long timeoutMs) {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            FluxPacket packet = inboundQueue.poll();
            if (packet != null) {
                if (expectedType == null || packet.getType() == expectedType) return packet;
                inboundQueue.offer(packet);
            }
            try { Thread.sleep(10); } catch (InterruptedException e) { break; }
        }
        return null;
    }

    private void startReadThread() {
        readThread = new Thread(() -> {
            while (connected) {
                try {
                    byte[] temp = new byte[1024];
                    int len = tcpIn.read(temp);
                    if (len <= 0) break;

                    readBuffer.put(temp, 0, len);
                    readBuffer.flip();

                    while (readBuffer.remaining() >= FluxPacket.HEADER_SIZE) {
                        readBuffer.mark();
                        FluxPacket.HeaderInfo h = FluxPacket.decodeHeader(readBuffer);
                        if (h == null || readBuffer.remaining() < h.payloadLength()) {
                            readBuffer.reset(); break;
                        }

                        byte[] payload = new byte[h.payloadLength()];
                        readBuffer.get(payload);

                        byte[] plaintext = (h.type() == PacketType.SERVER_HELLO) ? payload : cipher.decrypt(payload, h.iv());
                        if (plaintext == null) continue;

                        FluxPacket p = (h.type() == PacketType.SERVER_HELLO)
                                ? new FluxPacket(h.type(), plaintext, 0)
                                : new FluxPacket(h.type(), FluxPacket.decodePayload(plaintext).payload(), FluxPacket.decodePayload(plaintext).seqId());
                        inboundQueue.offer(p);
                    }
                    readBuffer.compact();
                } catch (IOException e) { break; }
            }
            connected = false;
        }, "flux-tcp-reader");
        readThread.setDaemon(true);
        readThread.start();
    }


    /**
     * 获取同步阶段缓存的 CHUNK_LOG_ENTRY 包，供 WorldSync 回放
     */
    public java.util.List<FluxPacket> getCachedSyncPackets() {
        return cachedSyncPackets;
    }

    public void sendGameEvent(PacketType type, byte[] payload) {
        // 封装 FluxPacket
        FluxPacket packet = new FluxPacket(
                type,
                payload,
                cipher.generateIV(),      // 使用已有的加密引擎生成 IV
                seqManager.nextSendSeq()  // 使用序列号管理器生成 SeqID
        );

        // 调用sendPacket
        sendPacket(packet);
    }

    public void disconnect() {
        connected = false;
        try { if (tcpSocket != null) tcpSocket.close(); } catch (IOException e) {}
    }
}