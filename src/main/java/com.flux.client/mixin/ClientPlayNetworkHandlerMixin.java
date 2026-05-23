package com.flux.client.mixin;

import com.flux.client.FluxClient;
import net.minecraft.client.network.ClientPlayNetworkHandler;
import net.minecraft.network.packet.s2c.play.GameJoinS2CPacket;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * 客户端网络 Mixin
 *
 * 注入点：玩家加入游戏世界时
 * 用途：触发世界同步流程
 */
@Mixin(ClientPlayNetworkHandler.class)
public class ClientPlayNetworkHandlerMixin {


    //世界同步机制
    @Inject(method = "onGameJoin", at = @At("TAIL"))
    private void onGameJoin(GameJoinS2CPacket packet, CallbackInfo ci) {
        FluxClient.LOGGER.info("[Flux] Game joined! Triggering world sync...");

        if (FluxClient.getNetworkClient() != null && FluxClient.getNetworkClient().isConnected()) {
            FluxClient.triggerWorldSync();
        } else {
            FluxClient.LOGGER.warn("[Flux] Not connected to Flux server, skipping world sync.");
        }
    }
}
