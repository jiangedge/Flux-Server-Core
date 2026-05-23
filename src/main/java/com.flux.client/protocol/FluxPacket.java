package com.flux.client.protocol;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

// Flux数据包编解码器

//数据包结构：
//+----------+--------+-------------+------------------+------------+
//| Magic(2B)| Type(1B)| Length(4B)  |    IV (12B)      | 加密载荷... |
// +----------+--------+-------------+------------------+------------+
// 加密载荷内部：
//  +----------------+---------------------------+-----------------+
// | SeqID (4B)     | 游戏数据 (N B)            | GCM Tag (16B)   |
//+----------------+---------------------------+-----------------+

public class FluxPacket {

    public static final short MAGIC = 0x4658;           // "FX" (Flux)
    public static final int HEADER_SIZE = 19;            // Magic(2) + Type(1) + Length(4) + IV(12)
    public static final int GCM_TAG_SIZE = 16;
    public static final int SEQ_ID_SIZE = 4;

    private final PacketType type;
    private final byte[] payload;
    private final byte[] iv;
    private final int seqId;

    //发送
    public FluxPacket(PacketType type, byte[] payload, byte[] iv, int seqId) {
        this.type = type;
        this.payload = payload;
        this.iv = iv;
        this.seqId = seqId;
    }

    //接收
    public FluxPacket(PacketType type, byte[] payload, int seqId) {
        this.type = type;
        this.payload = payload;
        this.iv = null;
        this.seqId = seqId;
    }

    public byte[] encodePayload() {
        ByteBuffer buf = ByteBuffer.allocate(SEQ_ID_SIZE + payload.length);
        buf.order(ByteOrder.BIG_ENDIAN);
        buf.putInt(seqId);
        buf.put(payload);
        return buf.array();
    }

    public byte[] encodeWire(byte[] encryptedPayload) {
        ByteBuffer buf = ByteBuffer.allocate(HEADER_SIZE + encryptedPayload.length);
        buf.order(ByteOrder.BIG_ENDIAN);
        buf.putShort(MAGIC);
        buf.put(type.code);
        buf.putInt(encryptedPayload.length);
        buf.put(iv);
        buf.put(encryptedPayload);
        return buf.array();
    }

    public static HeaderInfo decodeHeader(ByteBuffer buf) {
        if (buf.remaining() < HEADER_SIZE) return null;

        int mark = buf.position();
        short magic = buf.getShort();
        if (magic != MAGIC) {
            buf.position(mark + 1);
            return null;
        }

        byte typeCode = buf.get();
        int length = buf.getInt();
        byte[] iv = new byte[12];
        buf.get(iv);

        PacketType type = PacketType.fromCode(typeCode);
        if (type == null) {
            return null;
        }

        return new HeaderInfo(type, length, iv, buf.position());
    }

    public static DecodedPayload decodePayload(byte[] plaintext) {
        if (plaintext.length < SEQ_ID_SIZE) return null;
        ByteBuffer buf = ByteBuffer.wrap(plaintext);
        buf.order(ByteOrder.BIG_ENDIAN);
        int seqId = buf.getInt();
        byte[] payload = new byte[buf.remaining()];
        buf.get(payload);
        return new DecodedPayload(seqId, payload);
    }

    public PacketType getType() { return type; }
    public byte[] getPayload() { return payload; }
    public byte[] getIv() { return iv; }
    public int getSeqId() { return seqId; }

    public record HeaderInfo(PacketType type, int payloadLength, byte[] iv, int dataOffset) {}
    public record DecodedPayload(int seqId, byte[] payload) {}

    //快捷构建方法

    public static byte[] encodeMovement(double x, double y, double z, float yaw, float pitch) {
        ByteBuffer buf = ByteBuffer.allocate(20);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        buf.putFloat((float) x);
        buf.putFloat((float) y);
        buf.putFloat((float) z);
        buf.putFloat(yaw);
        buf.putFloat(pitch);
        return buf.array();
    }

    public static byte[] encodeBlockEvent(int x, int y, int z, int blockStateId) {
        ByteBuffer buf = ByteBuffer.allocate(16);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(x);
        buf.putInt(y);
        buf.putInt(z);
        buf.putInt(blockStateId);
        return buf.array();
    }

    public static byte[] encodeAttack(int targetEntityId, float damage) {
        ByteBuffer buf = ByteBuffer.allocate(8);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(targetEntityId);
        buf.putFloat(damage);
        return buf.array();
    }

    public static byte[] encodeInventoryChange(short slot, int itemId, byte count) {
        ByteBuffer buf = ByteBuffer.allocate(7);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        buf.putShort(slot);
        buf.putInt(itemId);
        buf.put(count);
        return buf.array();
    }

    public static byte[] encodeAuthRequest(java.util.UUID uuid, String username) {
        byte[] nameBytes = username.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        ByteBuffer buf = ByteBuffer.allocate(16 + nameBytes.length);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        buf.putLong(uuid.getMostSignificantBits());
        buf.putLong(uuid.getLeastSignificantBits());
        buf.put(nameBytes);
        return buf.array();
    }
}
