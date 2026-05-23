package com.flux.client.listener;

import com.flux.client.FluxClient;
import com.flux.client.protocol.FluxPacket;
import com.flux.client.protocol.PacketType;
import com.flux.client.network.NetworkClient;
import com.flux.client.config.Config;

import net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientTickEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents;
import net.fabricmc.fabric.api.event.player.AttackBlockCallback;
import net.fabricmc.fabric.api.event.player.UseBlockCallback;
import net.minecraft.block.Block;
import net.minecraft.block.BlockState;
import net.minecraft.client.MinecraftClient;
import net.minecraft.entity.player.PlayerEntity;
import net.minecraft.util.ActionResult;
import net.minecraft.util.Hand;
import net.minecraft.util.math.BlockPos;
import net.minecraft.util.math.Direction;
import net.minecraft.world.World;

/**
 * 游戏事件拦截器
 *
 * 拦截所有需要发送给 Flux 服务端的游戏事件：
 * - 玩家移动（每 Tick 检查位置变化）
 * - 方块破坏/放置
 * - 攻击实体
 * - 物品栏变更
 *
 * 事件被拦截后，编码为 Flux 二进制格式，加密后通过 TCP 发送
 */
public class EventListener {

    private final NetworkClient networkClient;

    private double lastX = Double.NaN, lastY = Double.NaN, lastZ = Double.NaN;
    private float lastYaw = Float.NaN, lastPitch = Float.NaN;

    public EventListener(NetworkClient networkClient) {
        this.networkClient = networkClient;
    }

    public void register() {
        // Tick 事件：检测移动
        ClientTickEvents.END_CLIENT_TICK.register(this::onTick);

        // 方块破坏
        AttackBlockCallback.EVENT.register(this::onBlockBreak);

        // 方块放置
        UseBlockCallback.EVENT.register(this::onBlockPlace);

        // 连接断开
        ClientPlayConnectionEvents.DISCONNECT.register((handler, client) -> {
            FluxClient.LOGGER.info("[Flux] Player disconnected from game world.");
        });

        FluxClient.LOGGER.info("[Flux] Event listeners registered.");
    }

    public void unregister() {
        FluxClient.LOGGER.info("[Flux] Event listeners unregistered.");
    }


    //每 Tick 检测玩家移动
    private void onTick(MinecraftClient client) {
        if (!networkClient.isConnected() || client.player == null) return;

        PlayerEntity player = client.player;
        double x = player.getX();
        double y = player.getY();
        double z = player.getZ();
        float yaw = player.getYaw();
        float pitch = player.getPitch();

        boolean moved = Double.isNaN(lastX) ||
                Math.abs(x - lastX) > Config.moveThreshold ||
                Math.abs(y - lastY) > Config.moveThreshold ||
                Math.abs(z - lastZ) > Config.moveThreshold;

        boolean rotated = Float.isNaN(lastYaw) ||
                Math.abs(yaw - lastYaw) > Config.rotationThreshold ||
                Math.abs(pitch - lastPitch) > Config.rotationThreshold;

        if (moved || rotated) {
            byte[] payload = FluxPacket.encodeMovement(x, y, z, yaw, pitch);
            networkClient.sendGameEvent(PacketType.PLAYER_MOVE, payload);

            lastX = x; lastY = y; lastZ = z;
            lastYaw = yaw; lastPitch = pitch;
        }
    }


    //方块破坏
    private ActionResult onBlockBreak(PlayerEntity player, World world,
                                       Hand hand, BlockPos pos, Direction direction) {
        if (!networkClient.isConnected()) return ActionResult.PASS;

        MinecraftClient.getInstance().execute(() -> {
            BlockState state = world.getBlockState(pos);
            int blockStateId = Block.getRawIdFromState(state);
            byte[] payload = FluxPacket.encodeBlockEvent(pos.getX(), pos.getY(), pos.getZ(), blockStateId);
            networkClient.sendGameEvent(PacketType.BLOCK_BREAK, payload);
        });

        return ActionResult.PASS;
    }


    //方块放置
    private ActionResult onBlockPlace(PlayerEntity player, World world,
                                       Hand hand, net.minecraft.util.hit.BlockHitResult hitResult) {
        if (!networkClient.isConnected()) return ActionResult.PASS;

        BlockPos pos = hitResult.getBlockPos().offset(hitResult.getSide());

        MinecraftClient.getInstance().execute(() -> {
            byte[] payload = FluxPacket.encodeBlockEvent(pos.getX(), pos.getY(), pos.getZ(), 0);
            networkClient.sendGameEvent(PacketType.BLOCK_PLACE, payload);
        });

        return ActionResult.PASS;
    }
}
