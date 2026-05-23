package com.flux.client.sync;

import com.flux.client.FluxClient;
import com.flux.client.network.NetworkClient;
import net.minecraft.client.MinecraftClient;
import net.minecraft.util.math.BlockPos;

import java.util.concurrent.CompletableFuture;

//世界同步机制

//1. 种子下发 — 服务端发送世界种子，客户端在本地生成原始地形
//2. 日志回放 — 服务端发送历史变更日志，客户端回放方块变更
//3. 同步完成 — 客户端正式进入世界

public class WorldSync {

    private final NetworkClient networkClient;
    private long worldSeed = -1;
    private int replayedEvents = 0;
    private volatile boolean syncing = false;

    public WorldSync(NetworkClient networkClient) {
        this.networkClient = networkClient;
    }

    public CompletableFuture<Boolean> startSync() {
        return CompletableFuture.supplyAsync(() -> {
            syncing = true;
            FluxClient.LOGGER.info("[Flux] === World Sync Start ===");

            try {
                //等待世界种子
                if (!receiveSeed()) {
                    FluxClient.LOGGER.error("[Flux] Sync failed: no seed received");
                    return false;
                }

                //等待事件回放完成
                if (!replayLogs()) {
                    FluxClient.LOGGER.error("[Flux] Sync failed: log replay error");
                    return false;
                }

                FluxClient.LOGGER.info("[Flux] === World Sync Complete === Seed: {}, Events: {}",
                        worldSeed, replayedEvents);
                return true;

            } catch (Exception e) {
                FluxClient.LOGGER.error("[Flux] Sync exception: {}", e.getMessage(), e);
                return false;
            } finally {
                syncing = false;
            }
        });
    }

    private boolean receiveSeed() {
        FluxClient.LOGGER.info("[Flux] Waiting for world seed...");

        // 种子可能已在 authenticateAndSync() 阶段存入 Config
        if (com.flux.client.config.Config.currentWorldSeed != 0) {
            this.worldSeed = com.flux.client.config.Config.currentWorldSeed;
            FluxClient.LOGGER.info("[Flux] Seed already available from auth phase: {}", worldSeed);
            return true;
        }

        // 否则等待服务器通过 onSeedReceived() 推送
        long deadline = System.currentTimeMillis() + 10000;
        while (worldSeed < 0 && System.currentTimeMillis() < deadline) {
            try { Thread.sleep(100); } catch (InterruptedException e) { return false; }
        }
        if (worldSeed < 0) {
            FluxClient.LOGGER.error("[Flux] Seed timeout!");
            return false;
        }
        FluxClient.LOGGER.info("[Flux] Seed received: {}", worldSeed);
        return true;
    }

    private boolean replayLogs() {
        FluxClient.LOGGER.info("[Flux] Replaying change logs...");
        replayedEvents = 0;

        // authenticateAndSync() 已在连接阶段缓存了 CHUNK_LOG_ENTRY 包
        java.util.List<com.flux.client.protocol.FluxPacket> cached = networkClient.getCachedSyncPackets();
        FluxClient.LOGGER.info("[Flux] Found {} cached sync packets to replay", cached.size());

        for (com.flux.client.protocol.FluxPacket pkt : cached) {
            byte[] data = pkt.getPayload();
            if (data == null || data.length < 5) continue;

            // 服务端格式: event_type(1B) + block_event_data(16B: x,y,z,blockId 各4B LE)
            int eventType = data[0] & 0xFF;
            if (data.length >= 17 && (eventType == 0x21 || eventType == 0x22)) {
                java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(data, 1, 16);
                buf.order(java.nio.ByteOrder.LITTLE_ENDIAN);
                int x = buf.getInt();
                int y = buf.getInt();
                int z = buf.getInt();
                int blockStateId = buf.getInt();
                onChunkLogEntry(x, y, z, blockStateId);
            }
        }

        FluxClient.LOGGER.info("[Flux] Replayed {} block changes.", replayedEvents);
        return true;
    }

    public void onSeedReceived(long seed) {
        this.worldSeed = seed;
        FluxClient.LOGGER.info("[Flux] Seed data received: {}", seed);
    }

    public void onChunkLogEntry(int x, int y, int z, int blockStateId) {
        MinecraftClient client = MinecraftClient.getInstance();
        if (client.world == null) return;

        client.execute(() -> {
            try {
                BlockPos pos = new BlockPos(x, y, z);
                net.minecraft.block.BlockState state = net.minecraft.block.Block.getStateFromRawId(blockStateId);
                client.world.setBlockState(pos, state);
                FluxClient.LOGGER.debug("[Flux] Replay: ({},{},{}) → stateId={}", x, y, z, blockStateId);
                replayedEvents++;
            } catch (Exception e) {
                FluxClient.LOGGER.warn("[Flux] Failed to replay block at ({},{},{}): {}",
                        x, y, z, e.getMessage());
            }
        });
    }

    public void onSyncComplete() {
        syncing = false;
        FluxClient.LOGGER.info("[Flux] Sync complete signal received.");
    }

    public long getWorldSeed() { return worldSeed; }
    public boolean isSyncing() { return syncing; }
    public int getReplayedEvents() { return replayedEvents; }
}
