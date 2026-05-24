package com.flux.client.protocol;

/**
 * Flux 数据包类型枚举
 */
public enum PacketType {

    // === 握手阶段 ===
    CLIENT_HELLO        (0x01, "Client Hello (ECDH Public Key)"),
    SERVER_HELLO        (0x02, "Server Hello (ECDH Public Key)"),
    AUTH_REQUEST         (0x03, "Auth Request (UUID + Username)"),
    AUTH_SUCCESS         (0x04, "Auth Success"),
    AUTH_FAIL            (0x05, "Auth Failed"),

    // === 世界同步 ===
    SEED_SYNC            (0x10, "World Seed"),
    CHUNK_LOG_ENTRY      (0x11, "Block Change Log Entry"),
    ENTITY_SNAPSHOT      (0x12, "Entity Snapshot"),
    SYNC_COMPLETE        (0x13, "Sync Complete"),

    // === 游戏事件（客户端 → 服务端）===
    PLAYER_MOVE          (0x20, "Player Position Update"),
    BLOCK_BREAK          (0x21, "Block Broken"),
    BLOCK_PLACE          (0x22, "Block Placed"),
    ENTITY_INTERACT      (0x23, "Entity Interact"),
    INVENTORY_CHANGE     (0x24, "Inventory Change"),
    CHEST_MODIFY         (0x26, "Chest Modify"),
    CHUNK_TRANSFER       (0x27, "Chunk Transfer"),

    // === 广播事件（服务端 → 所有客户端）===
    BROADCAST_MOVE       (0x30, "Broadcast: Player Moved"),
    BROADCAST_BLOCK      (0x31, "Broadcast: Block Changed"),
    BROADCAST_ENTITY     (0x32, "Broadcast: Entity Update"),
    BROADCAST_INVENTORY  (0x33, "Broadcast: Inventory Sync"),
    BROADCAST_CHAT       (0x34, "Broadcast: Chat"),
    BROADCAST_PLAYER_JOIN  (0x35, "Broadcast: Player Joined"),
    BROADCAST_PLAYER_LEAVE (0x36, "Broadcast: Player Left"),

    // === 控制 ===
    ROLLBACK             (0x40, "Rollback"),
    FREEZE               (0x41, "Freeze"),
    KICK                 (0x42, "Kick"),

    // === 心跳 ===
    PING                 (0x50, "Ping"),
    PONG                 (0x51, "Pong"),

    // === 其他 ===
    DISCONNECT           (0xFF, "Disconnect"),
    CHAT_MESSAGE         (0x28, "Chat Message");

    public final byte code;
    public final String description;

    PacketType(int code, String description) {
        this.code = (byte) code;
        this.description = description;
    }

    public static PacketType fromCode(byte code) {
        for (PacketType type : values()) {
            if (type.code == code) return type;
        }
        return null;
    }
}
