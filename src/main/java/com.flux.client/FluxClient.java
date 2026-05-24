package com.flux.client;

import com.flux.client.config.Config;
import com.flux.client.network.NetworkClient;
import com.flux.client.listener.EventListener;
import com.flux.client.player.PlayerManager;
import com.flux.client.protocol.PacketType;
import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.command.v2.ClientCommandManager;
import net.fabricmc.fabric.api.client.command.v2.ClientCommandRegistrationCallback;
import net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientLifecycleEvents;
import net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientTickEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents;
import net.minecraft.client.MinecraftClient;
import net.minecraft.text.Text;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.UUID;

public class FluxClient implements ClientModInitializer {

    public static final String MOD_ID = "flux-client";
    public static final Logger LOGGER = LoggerFactory.getLogger(MOD_ID);

    private static NetworkClient networkClient;
    private static EventListener eventListener;
    private static PlayerManager playerManager;

    private static volatile boolean connected = false;
    private static volatile boolean connecting = false;

    @Override
    public void onInitializeClient() {
        Config.load();

        playerManager = new PlayerManager();

        //方法引用
        ClientLifecycleEvents.CLIENT_STARTED.register(this::onClientStarted);
        ClientLifecycleEvents.CLIENT_STOPPING.register(this::onClientStopping);
        ClientTickEvents.END_CLIENT_TICK.register(this::onTick);

        // 世界加载/卸载事件：管理远程玩家实体
        ClientPlayConnectionEvents.JOIN.register((handler, sender, client) -> {
            if (client.world != null) {
                playerManager.onWorldLoaded(client.world);
            }
        });

        ClientPlayConnectionEvents.DISCONNECT.register((handler, client) -> {
            playerManager.onWorldUnloaded();
        });

        ClientCommandRegistrationCallback.EVENT.register((dispatcher, registryAccess) -> {
            dispatcher.register(ClientCommandManager.literal("flux")
                    .then(ClientCommandManager.literal("connect").executes(ctx -> { manualConnect(); return 1; }))
                    .then(ClientCommandManager.literal("disconnect").executes(ctx -> { manualDisconnect(); return 1; }))
                    .then(ClientCommandManager.literal("status").executes(ctx -> {
                        int count = playerManager.getPlayerCount();
                        String status = isConnected() ? "已连接" : "未连接";
                        sendMessage("状态: " + status + " | 远程玩家: " + count);
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

    /**
     * 处理服务端广播包
     */
    private static void handleServerPacket(MinecraftClient client, PacketType type, byte[] payload) {
        switch (type) {
            case BROADCAST_MOVE -> {
                // 远程玩家位置更新
                playerManager.handleBroadcastMove(payload);
            }

            case BROADCAST_BLOCK -> {
                // 方块变更广播（其他玩家放置/破坏了方块）
                if (payload != null && payload.length >= 16) {
                    ByteBuffer buf = ByteBuffer.wrap(payload);
                    buf.order(ByteOrder.LITTLE_ENDIAN);
                    int x = buf.getInt();
                    int y = buf.getInt();
                    int z = buf.getInt();
                    int blockStateId = buf.getInt();

                    // 同步到本地世界
                    if (client.world != null) {
                        client.execute(() -> {
                            net.minecraft.util.math.BlockPos pos = new net.minecraft.util.math.BlockPos(x, y, z);
                            net.minecraft.block.BlockState state = net.minecraft.block.Block.getStateFromRawId(blockStateId);
                            client.world.setBlockState(pos, state);
                        });
                    }
                }
            }

            case BROADCAST_ENTITY -> {
                // 实体同步（TODO）
            }

            case BROADCAST_INVENTORY -> {
                // 物品栏同步（TODO）
            }

            case BROADCAST_PLAYER_JOIN -> {
                // 新玩家加入 — PlayerManager 通过 BROADCAST_MOVE 自动创建
                // 这里只打印日志
                if (payload != null && payload.length >= 18) {
                    ByteBuffer buf = ByteBuffer.wrap(payload);
                    buf.order(ByteOrder.LITTLE_ENDIAN);
                    long msb = buf.getLong();
                    long lsb = buf.getLong();
                    UUID uuid = new UUID(msb, lsb);
                    int nameLen = buf.getShort() & 0xFFFF;
                    if (buf.remaining() >= nameLen) {
                        byte[] nameBytes = new byte[nameLen];
                        buf.get(nameBytes);
                        String name = new String(nameBytes, java.nio.charset.StandardCharsets.UTF_8);
                        LOGGER.info("[Flux] Player joined: {} ({})", name, uuid);
                        sendMessage("§a" + name + " 加入了游戏");
                    }
                }
            }

            case BROADCAST_PLAYER_LEAVE -> {
                // 玩家离开
                if (payload != null && payload.length >= 18) {
                    ByteBuffer buf = ByteBuffer.wrap(payload);
                    buf.order(ByteOrder.LITTLE_ENDIAN);
                    long msb = buf.getLong();
                    long lsb = buf.getLong();
                    UUID uuid = new UUID(msb, lsb);
                    int nameLen = buf.getShort() & 0xFFFF;
                    if (buf.remaining() >= nameLen) {
                        byte[] nameBytes = new byte[nameLen];
                        buf.get(nameBytes);
                        String name = new String(nameBytes, java.nio.charset.StandardCharsets.UTF_8);
                        playerManager.handlePlayerLeave(uuid);
                        LOGGER.info("[Flux] Player left: {} ({})", name, uuid);
                        sendMessage("§c" + name + " 离开了游戏");
                    }
                }
            }

            default -> {
                if (payload != null && payload.length > 0) {
                    LOGGER.debug("Received unhandled packet {} with {} bytes", type, payload.length);
                }
            }
        }
    }

    private void onTick(MinecraftClient client) {
        if (isConnected() && networkClient != null) {
            networkClient.pollIncomingPackets();
        }

        // 驱动远程玩家平滑插值
        if (playerManager != null) {
            playerManager.tick();
        }
    }

    private void onClientStopping(MinecraftClient client) { disconnectFromServer(); }

    public static boolean isConnected() {
        return networkClient != null && networkClient.isConnected();
    }

    public static void manualConnect() { connectToServer(MinecraftClient.getInstance()); }
    public static void manualDisconnect() { disconnectFromServer(); }
    public static void disconnectFromServer() {
        if (playerManager != null) {
            playerManager.clear();
        }
        if (networkClient != null) {
            networkClient.disconnect();
        }
        connected = false;
        connecting = false;
    }

    public static NetworkClient getNetworkClient() { return networkClient; }
    public static PlayerManager getPlayerManager() { return playerManager; }

    /**
     * 由 FluxConnectScreen 在连接成功后调用，将已建立连接的 NetworkClient 存入全局
     */
    public static void setNetworkClient(NetworkClient client) {
        networkClient = client;

        // ★ 关键修复：注册 packetCallback，让 inboundQueue 中的广播包被实际处理
        MinecraftClient mc = MinecraftClient.getInstance();
        client.setPacketCallback((type, payload) -> {
            handleServerPacket(mc, type, payload);
        });

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
                // 同步完成后，为已知远程玩家生成实体
                MinecraftClient mc = MinecraftClient.getInstance();
                if (mc.world != null) {
                    playerManager.onWorldLoaded(mc.world);
                }
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
