package com.flux.client.gui;

import com.flux.client.FluxClient;
import com.flux.client.config.Config;
import com.flux.client.network.NetworkClient;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.client.MinecraftClient;
import net.minecraft.client.gui.DrawContext;
import net.minecraft.client.gui.screen.Screen;
import net.minecraft.client.gui.widget.ButtonWidget;
import net.minecraft.client.gui.widget.TextFieldWidget;
import net.minecraft.nbt.NbtCompound;
import net.minecraft.nbt.NbtIo;
import net.minecraft.nbt.NbtList;
import net.minecraft.nbt.NbtString;
import net.minecraft.text.Text;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

public class FluxConnectScreen extends Screen {
    private final Screen parent;
    private TextFieldWidget hostField;
    private TextFieldWidget portField;
    private volatile Text statusText = Text.literal("等待操作...");
    private boolean isConnecting = false;

    public FluxConnectScreen(Screen parent) {
        super(Text.literal("Flux 连接中心"));
        this.parent = parent;
    }

    @Override
    protected void init() {
        int centerX = this.width / 2;
        int centerY = this.height / 4;

        this.hostField = new TextFieldWidget(this.textRenderer, centerX - 100, centerY + 20, 200, 20, Text.literal("Host"));
        this.hostField.setText(Config.serverHost);
        this.addSelectableChild(this.hostField);

        this.portField = new TextFieldWidget(this.textRenderer, centerX - 100, centerY + 50, 200, 20, Text.literal("Port"));
        this.portField.setText(String.valueOf(Config.serverPort));
        this.addSelectableChild(this.portField);

        this.addDrawableChild(ButtonWidget.builder(Text.literal("连接 Flux 服务器"),
                button -> initiateFluxConnection()
        ).dimensions(centerX - 100, centerY + 90, 200, 20).build());

        this.addDrawableChild(ButtonWidget.builder(Text.literal("返回主菜单"),
                button -> Objects.requireNonNull(this.client).setScreen(this.parent)
        ).dimensions(centerX - 100, centerY + 120, 200, 20).build());
    }

    private void updateStatus(String message) {
        MinecraftClient.getInstance().execute(() -> this.statusText = Text.literal(message));
    }

    private void ensureFluxWorldExists() {
        Path savesDir = FabricLoader.getInstance().getGameDir().resolve("saves");
        Path worldDir = savesDir.resolve("FluxNode");
        Path levelDat = worldDir.resolve("level.dat");

        if (Files.exists(levelDat)) {
            FluxClient.LOGGER.info("[Flux] FluxNode world already exists");
            return;
        }

        long seed = Config.currentWorldSeed != 0 ? Config.currentWorldSeed : 12345L;

        try {
            Files.createDirectories(worldDir.resolve("data"));
            Files.createDirectories(worldDir.resolve("region"));
            Files.createDirectories(worldDir.resolve("DIM1/region"));
            Files.createDirectories(worldDir.resolve("DIM-1/region"));

            NbtCompound data = new NbtCompound();
            data.putInt("DataVersion", 3465);
            data.putString("LevelName", "FluxNode");
            data.putLong("RandomSeed", seed);
            data.putInt("GameType", 0);
            data.putBoolean("Hardcore", false);
            data.putBoolean("allowCommands", true);
            data.putInt("SpawnX", 0);
            data.putInt("SpawnY", 64);
            data.putInt("SpawnZ", 0);
            data.putBoolean("initialized", true);
            data.putLong("LastPlayed", System.currentTimeMillis());
            data.putLong("DayTime", 6000);
            data.putLong("Time", 0);
            data.putByte("Difficulty", (byte) 1);
            data.putBoolean("DifficultyLocked", false);
            data.putInt("version", 19133);
            data.putByte("WasModded", (byte) 1);

            NbtCompound worldGen = new NbtCompound();
            worldGen.putLong("seed", seed);
            worldGen.putBoolean("generate_features", true);
            worldGen.putBoolean("bonus_chest", false);

            NbtCompound dimensions = new NbtCompound();

            NbtCompound overworld = new NbtCompound();
            overworld.putString("type", "minecraft:overworld");
            NbtCompound overworldGen = new NbtCompound();
            overworldGen.putString("type", "minecraft:flat");
            NbtCompound flatSettings = new NbtCompound();
            flatSettings.putString("biome", "minecraft:plains");
            NbtList layers = new NbtList();
            NbtCompound bedrock = new NbtCompound();
            bedrock.putString("block", "minecraft:bedrock");
            bedrock.putInt("height", 1);
            layers.add(bedrock);
            NbtCompound dirt = new NbtCompound();
            dirt.putString("block", "minecraft:dirt");
            dirt.putInt("height", 2);
            layers.add(dirt);
            NbtCompound grass = new NbtCompound();
            grass.putString("block", "minecraft:grass_block");
            grass.putInt("height", 1);
            layers.add(grass);
            flatSettings.put("layers", layers);
            flatSettings.putBoolean("features", false);
            flatSettings.putBoolean("lakes", false);
            overworldGen.put("settings", flatSettings);
            overworld.put("generator", overworldGen);
            dimensions.put("minecraft:overworld", overworld);

            NbtCompound nether = new NbtCompound();
            nether.putString("type", "minecraft:the_nether");
            NbtCompound netherGen = new NbtCompound();
            netherGen.putString("type", "minecraft:noise");
            nether.put("generator", netherGen);
            dimensions.put("minecraft:the_nether", nether);

            NbtCompound end = new NbtCompound();
            end.putString("type", "minecraft:the_end");
            NbtCompound endGen = new NbtCompound();
            endGen.putString("type", "minecraft:noise");
            end.put("generator", endGen);
            dimensions.put("minecraft:the_end", end);

            worldGen.put("dimensions", dimensions);
            data.put("WorldGenSettings", worldGen);

            NbtCompound dataPacks = new NbtCompound();
            NbtList enabled = new NbtList();
            enabled.add(NbtString.of("vanilla"));
            dataPacks.put("Enabled", enabled);
            data.put("DataPacks", dataPacks);

            NbtCompound gameRules = new NbtCompound();
            gameRules.putString("doDaylightCycle", "false");
            gameRules.putString("doMobSpawning", "false");
            gameRules.putString("doWeatherCycle", "false");
            gameRules.putString("keepInventory", "true");
            gameRules.putString("doFireTick", "false");
            gameRules.putString("mobGriefing", "false");
            data.put("GameRules", gameRules);

            NbtCompound root = new NbtCompound();
            root.put("Data", data);

            writeNbt(root, levelDat);
            writeNbt(root, worldDir.resolve("level.dat_old"));

            FluxClient.LOGGER.info("[Flux] Created FluxNode world (seed={})", seed);
        } catch (Exception e) {
            FluxClient.LOGGER.error("[Flux] Failed to create FluxNode world: {}", e.getMessage(), e);
        }
    }

    private static void writeNbt(NbtCompound nbt, Path path) {
        try (OutputStream out = new FileOutputStream(path.toFile())) {
            NbtIo.writeCompressed(nbt, out);
        } catch (IOException e) {
            FluxClient.LOGGER.error("[Flux] Failed to write {}: {}", path, e.getMessage());
        }
    }

    private void initiateFluxConnection() {
        if (isConnecting) return;
        isConnecting = true;

        Config.serverHost = this.hostField.getText().trim();
        try {
            Config.serverPort = Integer.parseInt(this.portField.getText().trim());
            Config.save();
        } catch (NumberFormatException e) {
            this.statusText = Text.literal("错误: 端口必须为纯数字！");
            isConnecting = false;
            return;
        }

        updateStatus("正在初始化...");

        new Thread(() -> {
            try {
                updateStatus("连接服务器中...");
                NetworkClient client = new NetworkClient();
                FluxClient.setNetworkClient(client);

                if (!client.connect()) {
                    updateStatus("TCP 连接失败，请检查 IP/端口");
                    isConnecting = false;
                    return;
                }

                updateStatus("正在交换密钥与身份认证...");
                var session = MinecraftClient.getInstance().getSession();

                if (!client.authenticateAndSync(session.getUuidOrNull(), session.getUsername())) {
                    updateStatus("认证失败或同步超时！");
                    isConnecting = false;
                    return;
                }

                FluxClient.completeConnection();

                updateStatus("同步成功，正在加入世界...");
                MinecraftClient.getInstance().execute(() -> {
                    ensureFluxWorldExists();
                    MinecraftClient.getInstance()
                            .createIntegratedServerLoader()
                            .start(FluxConnectScreen.this, "FluxNode");
                });

            } catch (Exception e) {
                updateStatus("严重错误: " + e.getMessage());
                FluxClient.LOGGER.error("[Flux] Connection Error: ", e);
                isConnecting = false;
            }
        }, "flux-connection-thread").start();
    }

    @Override
    public void render(DrawContext context, int mouseX, int mouseY, float delta) {
        this.renderBackground(context);
        context.drawCenteredTextWithShadow(this.textRenderer, this.title, this.width / 2, 20, 0xFFFFFF);
        context.drawCenteredTextWithShadow(this.textRenderer, this.statusText, this.width / 2, this.height / 4 - 10, 0xFFAA00);
        this.hostField.render(context, mouseX, mouseY, delta);
        this.portField.render(context, mouseX, mouseY, delta);
        super.render(context, mouseX, mouseY, delta);
    }
}
