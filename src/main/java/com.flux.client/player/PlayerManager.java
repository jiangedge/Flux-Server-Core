package com.flux.client.player;

import com.flux.client.FluxClient;
import net.minecraft.client.MinecraftClient;
import net.minecraft.client.world.ClientWorld;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

//远程玩家管理器
//维护所有通过 Flux 网络连接的远程玩家：
//创建/销毁假玩家实体
// 处理位置广播
//每 Tick 驱动平滑插值

public class PlayerManager {

    // UUID → GhostPlayer
    private final Map<UUID, GhostPlayer> players = new ConcurrentHashMap<>();

//每 Tick 调用，驱动所有远程玩家的平滑插值

    public void tick() {
        for (GhostPlayer ghost : players.values()) {
            ghost.tick();
        }
    }

    public void handleBroadcastMove(byte[] payload) {
        if (payload == null || payload.length < 36) return;

        ByteBuffer buf = ByteBuffer.wrap(payload);
        buf.order(ByteOrder.LITTLE_ENDIAN);

        //先读位置
        float x = buf.getFloat();
        float y = buf.getFloat();
        float z = buf.getFloat();
        float yaw = buf.getFloat();
        float pitch = buf.getFloat();

        // 读取 UUID
        long msb = buf.getLong();
        long lsb = buf.getLong();
        UUID uuid = new UUID(msb, lsb);

        // 读取用户名
        String username = "Player";
        if (buf.remaining() >= 2) {
            int nameLen = buf.getShort() & 0xFFFF;
            if (buf.remaining() >= nameLen) {
                byte[] nameBytes = new byte[nameLen];
                buf.get(nameBytes);
                username = new String(nameBytes, java.nio.charset.StandardCharsets.UTF_8);
            }
        }

        // 忽略自己
        MinecraftClient client = MinecraftClient.getInstance();
        if (client.player != null && uuid.equals(client.player.getUuid())) return;

        GhostPlayer ghost = players.get(uuid);
        if (ghost == null) {
            // 新玩家，创建并生成
            ghost = new GhostPlayer(uuid, username);
            ghost.updatePosition(x, y, z, yaw, pitch);
            players.put(uuid, ghost);

            // 如果世界已加载，立即生成实体
            if (client.world != null) {
                ghost.spawn(client.world);
            }

            FluxClient.LOGGER.info("[Flux] New remote player: {} ({})", username, uuid);
        } else {
            // 已有玩家，更新位置
            ghost.updatePosition(x, y, z, yaw, pitch);
        }
    }

    /**
     * 处理玩家离开通知
     */
    public void handlePlayerLeave(UUID uuid) {
        GhostPlayer ghost = players.remove(uuid);
        if (ghost != null) {
            MinecraftClient client = MinecraftClient.getInstance();
            if (client.world != null) {
                ghost.despawn(client.world);
            }
            FluxClient.LOGGER.info("[Flux] Remote player left: {}", ghost.getUsername());
        }
    }

    /**
     * 当本地世界加载时，为所有已知远程玩家生成实体
     */
    public void onWorldLoaded(ClientWorld world) {
        for (GhostPlayer ghost : players.values()) {
            if (!ghost.isSpawned()) {
                ghost.spawn(world);
            }
        }
    }

    /**
     * 当本地世界卸载时，清理所有远程玩家实体
     */
    public void onWorldUnloaded() {
        for (GhostPlayer ghost : players.values()) {
            ghost.despawn(MinecraftClient.getInstance().world);
        }
    }

    /**
     * 断开连接时清理所有数据
     */
    public void clear() {
        MinecraftClient client = MinecraftClient.getInstance();
        if (client.world != null) {
            for (GhostPlayer ghost : players.values()) {
                ghost.despawn(client.world);
            }
        }
        players.clear();
        FluxClient.LOGGER.info("[Flux] Cleared all ghost players.");
    }

    public Map<UUID, GhostPlayer> getPlayers() { return players; }
    public int getPlayerCount() { return players.size(); }
}
