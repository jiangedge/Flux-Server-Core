package com.flux.client.config;

import com.flux.client.FluxClient;
import java.io.*;
import java.nio.file.*;
import java.util.Properties;

/**
 * Flux 配置管理
 *
 * 配置文件路径：.minecraft/flux.properties
 */
public class Config {

    // === 服务端连接 ===
    public static long currentWorldSeed = 0L;
    public static String serverHost = "127.0.0.1";
    public static int serverPort = 25580;
    public static boolean autoConnect = true;           // 启动游戏时自动连接
    public static int reconnectDelayMs = 5000;          // 断线重连延迟
    public static int maxReconnectAttempts = 10;        // 最大重连次数

    // === 加密 ===
    public static int handshakeTimeoutMs = 5000;
    public static int maxPacketSize = 1024;

    // === 性能 ===
    public static int maxQueuedPackets = 256;
    public static double moveThreshold = 0.001;         // 移动上报阈值 (方块)
    public static float rotationThreshold = 0.01f;      // 旋转上报阈值 (度)

    private static final Path CONFIG_PATH = Paths.get(
            System.getProperty("user.dir"), "flux.properties"
    );

    public static void load() {
        Properties props = new Properties();

        if (Files.exists(CONFIG_PATH)) {
            try (InputStream in = Files.newInputStream(CONFIG_PATH)) {
                props.load(in);
                FluxClient.LOGGER.info("[Flux] Config loaded from {}", CONFIG_PATH);
            } catch (IOException e) {
                FluxClient.LOGGER.warn("[Flux] Failed to load config, using defaults", e);
            }
        }

        serverHost = props.getProperty("server.host", serverHost);
        serverPort = Integer.parseInt(props.getProperty("server.port", String.valueOf(serverPort)));
        autoConnect = Boolean.parseBoolean(props.getProperty("auto.connect", String.valueOf(autoConnect)));
        reconnectDelayMs = Integer.parseInt(props.getProperty("reconnect.delay_ms", String.valueOf(reconnectDelayMs)));
        maxReconnectAttempts = Integer.parseInt(props.getProperty("reconnect.max_attempts", String.valueOf(maxReconnectAttempts)));
        handshakeTimeoutMs = Integer.parseInt(props.getProperty("crypto.handshake_timeout", String.valueOf(handshakeTimeoutMs)));
        maxPacketSize = Integer.parseInt(props.getProperty("crypto.max_packet_size", String.valueOf(maxPacketSize)));
        maxQueuedPackets = Integer.parseInt(props.getProperty("perf.max_queued_packets", String.valueOf(maxQueuedPackets)));
        moveThreshold = Double.parseDouble(props.getProperty("perf.move_threshold", String.valueOf(moveThreshold)));
        rotationThreshold = Float.parseFloat(props.getProperty("perf.rotation_threshold", String.valueOf(rotationThreshold)));

        // 首次运行时生成默认配置文件
        if (!Files.exists(CONFIG_PATH)) {
            save();
        }
    }

    public static void save() {
        Properties props = new Properties();
        props.setProperty("server.host", serverHost);
        props.setProperty("server.port", String.valueOf(serverPort));
        props.setProperty("auto.connect", String.valueOf(autoConnect));
        props.setProperty("reconnect.delay_ms", String.valueOf(reconnectDelayMs));
        props.setProperty("reconnect.max_attempts", String.valueOf(maxReconnectAttempts));
        props.setProperty("crypto.handshake_timeout", String.valueOf(handshakeTimeoutMs));
        props.setProperty("crypto.max_packet_size", String.valueOf(maxPacketSize));
        props.setProperty("perf.max_queued_packets", String.valueOf(maxQueuedPackets));
        props.setProperty("perf.move_threshold", String.valueOf(moveThreshold));
        props.setProperty("perf.rotation_threshold", String.valueOf(rotationThreshold));

        try (OutputStream out = Files.newOutputStream(CONFIG_PATH)) {
            props.store(out, "Flux Client Configuration");
            FluxClient.LOGGER.info("[Flux] Config saved to {}", CONFIG_PATH);
        } catch (IOException e) {
            FluxClient.LOGGER.error("[Flux] Failed to save config", e);
        }
    }
}
