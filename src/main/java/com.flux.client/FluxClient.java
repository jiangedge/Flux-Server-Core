package com.flux.client;

import com.flux.client.config.Config;
import com.flux.client.network.NetworkClient;
import com.flux.client.listener.EventListener;
import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.command.v2.ClientCommandManager;
import net.fabricmc.fabric.api.client.command.v2.ClientCommandRegistrationCallback;
import net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientLifecycleEvents;
import net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientTickEvents;
import net.minecraft.client.MinecraftClient;
import net.minecraft.text.Text;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FluxClient implements ClientModInitializer {

    public static final String MOD_ID = "flux-client";
    public static final Logger LOGGER = LoggerFactory.getLogger(MOD_ID);

    private static NetworkClient networkClient;
    private static EventListener eventListener;

    private static volatile boolean connected = false;
    private static volatile boolean connecting = false;

    @Override
    public void onInitializeClient() {
        Config.load();

        //方法引用
        ClientLifecycleEvents.CLIENT_STARTED.register(this::onClientStarted);
        ClientLifecycleEvents.CLIENT_STOPPING.register(this::onClientStopping);
        ClientTickEvents.END_CLIENT_TICK.register(this::onTick);

        ClientCommandRegistrationCallback.EVENT.register((dispatcher, registryAccess) -> {
            dispatcher.register(ClientCommandManager.literal("flux")
                    .then(ClientCommandManager.literal("connect").executes(ctx -> { manualConnect(); return 1; }))
                    .then(ClientCommandManager.literal("disconnect").executes(ctx -> { manualDisconnect(); return 1; }))
                    .then(ClientCommandManager.literal("status").executes(ctx -> {
                        sendMessage("状态: " + (isConnected() ? "已连接" : "未连接"));
                        return 1;
                    })));
        });
    }

    public static void sendMessage(String message) {
        MinecraftClient mc = MinecraftClient.getInstance();
        if (mc.player != null) {
            mc.player.sendMessage(Text.literal("§b[Flux] §f" + message), false);
        }
    }

    private void onClientStarted(MinecraftClient client) {
        if (Config.autoConnect) connectToServer(client);
    }

    public static void connectToServer(MinecraftClient client) {
        if (connected || connecting) return;
        connecting = true;

        networkClient = new NetworkClient();
        networkClient.setPacketCallback((type, payload) -> {
            if (type != null) {
                handleServerPacket(client, type, payload);
            }
        });

        //连接线程
    }

    private static void handleServerPacket(MinecraftClient client, com.flux.client.protocol.PacketType type, byte[] payload) {

        if (payload != null && payload.length > 0) {
            LOGGER.debug("Received packet {} with {} bytes", type, payload.length);
        }
    }

    private void onTick(MinecraftClient client) {
        if (isConnected() && networkClient != null) {
            networkClient.pollIncomingPackets();
        }
    }

    private void onClientStopping(MinecraftClient client) { disconnectFromServer(); }

    public static boolean isConnected() {
        return networkClient != null && networkClient.isConnected();
    }

    public static void manualConnect() { connectToServer(MinecraftClient.getInstance()); }
    public static void manualDisconnect() { disconnectFromServer(); }
    public static void disconnectFromServer() { /* ... */ }

    public static NetworkClient getNetworkClient() { return networkClient; }

    /**
     * 由 FluxConnectScreen 在连接成功后调用，将已建立连接的 NetworkClient 存入全局
     */
    public static void setNetworkClient(NetworkClient client) {
        networkClient = client;
        // 注册事件监听器
        if (eventListener != null) {
            eventListener.unregister();
        }
        eventListener = new EventListener(client);
        eventListener.register();
    }

     //由 ClientPlayNetworkHandlerMixin 在玩家加入游戏世界时触发
     //启动三阶段世界同步：种子下发 → 日志回放 → 同步完成

    public static void triggerWorldSync() {
        if (networkClient == null || !networkClient.isConnected()) {
            LOGGER.warn("[Flux] Cannot trigger world sync: not connected.");
            return;
        }
        com.flux.client.sync.WorldSync worldSync = new com.flux.client.sync.WorldSync(networkClient);
        worldSync.startSync().thenAccept(success -> {
            if (success) {
                sendMessage("世界同步完成！");
                connected = true;
            } else {
                sendMessage("世界同步失败！");
            }
        });
    }


    //完成连接通知

    public static void completeConnection() {
        connected = true;
        connecting = false;
        sendMessage("已连接到 Flux 服务端");
    }
}