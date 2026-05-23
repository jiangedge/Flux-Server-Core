package com.flux.client.mixin;

import com.flux.client.FluxClient;
import net.minecraft.client.MinecraftClient;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * MinecraftClient Mixin
 *
 * 注入点：客户端初始化完成时
 * 用途：确保 Flux 子系统在游戏完全加载后才启动
 */
@Mixin(MinecraftClient.class)
public class MinecraftClientMixin {

    @Inject(method = "run", at = @At("HEAD"))
    private void onRun(CallbackInfo ci) {
        FluxClient.LOGGER.info("[Flux] MinecraftClient.run() started - systems ready.");
    }

    @Inject(method = "stop", at = @At("HEAD"))
    private void onStop(CallbackInfo ci) {
        FluxClient.LOGGER.info("[Flux] MinecraftClient.stop() - cleaning up...");
    }
}
