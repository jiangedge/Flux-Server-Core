package com.flux.client.player;

import com.flux.client.FluxClient;
import com.mojang.authlib.GameProfile;
import net.minecraft.client.MinecraftClient;
import net.minecraft.client.network.OtherClientPlayerEntity;
import net.minecraft.client.world.ClientWorld;
import net.minecraft.entity.player.PlayerEntity;
import net.minecraft.util.math.Vec3d;

import java.util.UUID;

//远程玩家数据模型
//用于在本地世界中渲染其他 Flux 玩家。
//OtherClientPlayerEntity 是 Minecraft 内置的客户端玩家实体，
//自动拥有完整的玩家模型、皮肤渲染、行走/手臂动画。

public class GhostPlayer {

    private final UUID uuid;
    private final String username;
    private OtherClientPlayerEntity entity;

    // 目标位置（服务端发来的最新坐标）
    private double targetX, targetY, targetZ;
    private float targetYaw, targetPitch;

    // 平滑插值用
    private double prevX, prevY, prevZ;
    private float prevYaw, prevPitch;
    private long lastUpdateTime;
    private boolean firstUpdate = true;

    public GhostPlayer(UUID uuid, String username) {
        this.uuid = uuid;
        this.username = username;
    }

    /**
     * 在客户端世界中生成假玩家实体
     */
    public void spawn(ClientWorld world) {
        if (entity != null) return;

        MinecraftClient client = MinecraftClient.getInstance();

        // 创建 GameProfile（皮肤会自动通过 Mojang API 加载）
        GameProfile profile = new GameProfile(uuid, username);

        entity = new OtherClientPlayerEntity(world, profile);

        // 设置初始位置
        entity.setPos(targetX, targetY, targetZ);
        entity.setYaw(targetYaw);
        entity.setPitch(targetPitch);

        // 添加到世界（触发渲染）
        world.addEntity(entity.getId(), entity);

        FluxClient.LOGGER.info("[Flux] Spawned ghost player: {} ({})", username, uuid);
    }

    /**
     * 从世界中移除假玩家
     */
    public void despawn(ClientWorld world) {
        if (entity == null) return;

        world.removeEntity(entity.getId(), PlayerEntity.RemovalReason.DISCARDED);
        entity = null;

        FluxClient.LOGGER.info("[Flux] Despawned ghost player: {}", username);
    }

    /**
     * 更新服务端发来的位置数据
     */
    public void updatePosition(double x, double y, double z, float yaw, float pitch) {
        // 保存上一帧位置用于插值
        if (!firstUpdate) {
            prevX = targetX;
            prevY = targetY;
            prevZ = targetZ;
            prevYaw = targetYaw;
            prevPitch = targetPitch;
        }

        targetX = x;
        targetY = y;
        targetZ = z;
        targetYaw = yaw;
        targetPitch = pitch;
        lastUpdateTime = System.currentTimeMillis();

        if (firstUpdate) {
            prevX = x;
            prevY = y;
            prevZ = z;
            prevYaw = yaw;
            prevPitch = pitch;
            firstUpdate = false;
        }

        // 同步到实体
        if (entity != null) {
            entity.setPos(x, y, z);
            entity.setYaw(yaw);
            entity.setPitch(pitch);
        }
    }

    /**
     * 每 Tick 调用：平滑插值渲染位置
     */
    public void tick() {
        if (entity == null) return;

        // 计算插值进度（基于服务端更新频率 ~20 tick/s）
        long elapsed = System.currentTimeMillis() - lastUpdateTime;
        float t = Math.min(elapsed / 50.0f, 1.0f); // 50ms = 1 tick

        // 线性插值
        double renderX = prevX + (targetX - prevX) * t;
        double renderY = prevY + (targetY - prevY) * t;
        double renderZ = prevZ + (targetZ - prevZ) * t;
        float renderYaw = lerpAngle(prevYaw, targetYaw, t);
        float renderPitch = prevPitch + (targetPitch - prevPitch) * t;

        // 设置渲染位置（不触发碰撞/物理）
        entity.updateTrackedPositionAndAngles(renderX, renderY, renderZ, renderYaw, renderPitch, 3, true);
        entity.setPos(renderX, renderY, renderZ);
        entity.setYaw(renderYaw);
        entity.setPitch(renderPitch);
    }


    private float lerpAngle(float from, float to, float t) {
        float diff = to - from;
        while (diff > 180f) diff -= 360f;
        while (diff < -180f) diff += 360f;
        return from + diff * t;
    }


    public UUID getUuid() { return uuid; }
    public String getUsername() { return username; }
    public OtherClientPlayerEntity getEntity() { return entity; }
    public boolean isSpawned() { return entity != null; }
    public double getX() { return targetX; }
    public double getY() { return targetY; }
    public double getZ() { return targetZ; }
}
