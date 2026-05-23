"""
Flux Server - 二进制协议层
处理包的解析、构建、编解码

协议线格式（大端序，所有包统一格式）:
  Magic(2B) + Type(1B) + Length(4B) + IV(12B) + Payload/EncryptedPayload(Length B)

  Length = 载荷长度（不含 IV）：
    - 非加密包: Length = 原始载荷字节数
    - 加密包:   Length = SeqID(4) + 游戏数据 + GCM Tag(16)

  IV 始终存在:
    - 非加密包: IV = 12 字节零（不参与加解密，仅占位）
    - 加密包:   IV = 随机 12 字节（AES-GCM nonce）

  SeqID 由加密层（CryptoEngine）统一处理，游戏载荷中不含 SeqID。
"""

import struct
from enum import IntEnum
from dataclasses import dataclass, field
from typing import Optional

from config import (
    PROTOCOL_MAGIC, PROTOCOL_HEADER_SIZE, PROTOCOL_IV_SIZE,
    PROTOCOL_GCM_TAG_SIZE, PROTOCOL_SEQID_SIZE, MAX_PAYLOAD_SIZE
)


# ═══════════════════════════════════════════════════════════════
#  包类型枚举
# ═══════════════════════════════════════════════════════════════

class PacketType(IntEnum):
    # 握手阶段 (0x01-0x0F)
    CLIENT_HELLO       = 0x01   # 客户端 → 服务端: ECDH 公钥（非加密）
    SERVER_HELLO       = 0x02   # 服务端 → 客户端: ECDH 公钥（非加密）
    AUTH_REQUEST        = 0x03   # 客户端 → 服务端: UUID + 用户名（加密）
    AUTH_SUCCESS        = 0x04   # 服务端 → 客户端: 认证成功（加密）
    AUTH_FAIL           = 0x05   # 服务端 → 客户端: 认证失败（加密）

    # 世界同步 (0x10-0x1F) — 与 Java 客户端 PacketType 对齐
    SEED_SYNC           = 0x10   # 服务端 → 客户端: 世界种子
    CHUNK_LOG_ENTRY     = 0x11   # 服务端 → 客户端: 事件回放
    ENTITY_SNAPSHOT     = 0x12   # 服务端 → 客户端: 实体快照
    SYNC_COMPLETE       = 0x13   # 服务端 → 客户端: 同步完成

    # 游戏事件 (0x20-0x2F, 客户端 → 服务端)
    PLAYER_MOVE         = 0x20   # 位置更新
    BLOCK_BREAK         = 0x21   # 破坏方块
    BLOCK_PLACE         = 0x22   # 放置方块
    ENTITY_INTERACT     = 0x23   # 攻击/交互实体
    INVENTORY_CHANGE    = 0x24   # 物品栏变更
    CHEST_OPEN          = 0x25   # 打开容器
    CHEST_MODIFY        = 0x26   # 修改容器内容
    CHUNK_TRANSFER      = 0x27   # 实体跨界传输

    # 广播 (0x30-0x3F, 服务端 → 所有客户端)
    BROADCAST_MOVE      = 0x30
    BROADCAST_BLOCK     = 0x31
    BROADCAST_ENTITY    = 0x32
    BROADCAST_INVENTORY = 0x33

    # 控制 (0x40-0x4F)
    ROLLBACK            = 0x40   # 回滚
    FREEZE              = 0x41   # 冻结
    KICK                = 0x42   # 踢出

    # 心跳 (0x50-0x5F)
    PING                = 0x50
    PONG                = 0x51


# ═══════════════════════════════════════════════════════════════
#  非加密握手包类型（不走 GCM 解密，IV 全零）
# ═══════════════════════════════════════════════════════════════

UNENCRYPTED_PACKET_TYPES = {
    PacketType.CLIENT_HELLO,
    PacketType.SERVER_HELLO,
}


# ═══════════════════════════════════════════════════════════════
#  数据包载荷结构体
#  注意：SeqID 由加密层（CryptoEngine）统一处理，
#  游戏载荷中不含 SeqID，与 Java 客户端 encode*() 方法对齐。
# ═══════════════════════════════════════════════════════════════

@dataclass
class PlayerMovePayload:
    """玩家移动包 — Java encodeMovement: 5×float LE = 20 字节"""
    x: float = 0.0
    y: float = 0.0
    z: float = 0.0
    yaw: float = 0.0
    pitch: float = 0.0

    FORMAT = "<fffff"
    SIZE = 20

    @classmethod
    def unpack(cls, data: bytes) -> 'PlayerMovePayload':
        fields = struct.unpack(cls.FORMAT, data[:cls.SIZE])
        return cls(*fields)

    def pack(self) -> bytes:
        return struct.pack(self.FORMAT,
                           self.x, self.y, self.z,
                           self.yaw, self.pitch)


@dataclass
class BlockBreakPayload:
    """方块破坏包 — Java encodeBlockEvent: 4×int LE = 16 字节"""
    x: int = 0
    y: int = 0
    z: int = 0
    block_id: int = 0

    FORMAT = "<iiii"
    SIZE = 16

    @classmethod
    def unpack(cls, data: bytes) -> 'BlockBreakPayload':
        fields = struct.unpack(cls.FORMAT, data[:cls.SIZE])
        return cls(*fields)

    def pack(self) -> bytes:
        return struct.pack(self.FORMAT,
                           self.x, self.y, self.z,
                           self.block_id)


@dataclass
class BlockPlacePayload:
    """方块放置包 — Java encodeBlockEvent: 4×int LE = 16 字节"""
    x: int = 0
    y: int = 0
    z: int = 0
    block_id: int = 0

    FORMAT = "<iiii"
    SIZE = 16

    @classmethod
    def unpack(cls, data: bytes) -> 'BlockPlacePayload':
        fields = struct.unpack(cls.FORMAT, data[:cls.SIZE])
        return cls(*fields)

    def pack(self) -> bytes:
        return struct.pack(self.FORMAT,
                           self.x, self.y, self.z,
                           self.block_id)


@dataclass
class EntityInteractPayload:
    """实体交互包 — Java encodeAttack: int+float LE = 8 字节"""
    entity_id: int = 0
    damage: float = 0.0

    FORMAT = "<If"
    SIZE = 8

    @classmethod
    def unpack(cls, data: bytes) -> 'EntityInteractPayload':
        fields = struct.unpack(cls.FORMAT, data[:cls.SIZE])
        return cls(*fields)

    def pack(self) -> bytes:
        return struct.pack(self.FORMAT,
                           self.entity_id, self.damage)


@dataclass
class InventoryChangePayload:
    """物品栏变更包 — Java encodeInventoryChange: short+int+byte LE = 7 字节"""
    slot_index: int = 0
    item_id: int = 0
    count: int = 0

    FORMAT = "<HiB"
    SIZE = 7

    @classmethod
    def unpack(cls, data: bytes) -> 'InventoryChangePayload':
        fields = struct.unpack(cls.FORMAT, data[:cls.SIZE])
        return cls(*fields)

    def pack(self) -> bytes:
        return struct.pack(self.FORMAT,
                           self.slot_index, self.item_id,
                           self.count)


@dataclass
class ChestModifyPayload:
    """容器修改包 — 按文档: 3×int + byte + short + byte = 16 字节"""
    x: int = 0
    y: int = 0
    z: int = 0
    slot_index: int = 0
    item_id: int = 0
    count: int = 0

    FORMAT = "<iiiBHB"
    SIZE = 16

    @classmethod
    def unpack(cls, data: bytes) -> 'ChestModifyPayload':
        fields = struct.unpack(cls.FORMAT, data[:cls.SIZE])
        return cls(*fields)

    def pack(self) -> bytes:
        return struct.pack(self.FORMAT,
                           self.x, self.y, self.z,
                           self.slot_index, self.item_id,
                           self.count)


@dataclass
class ChunkTransferPayload:
    """区块传输包 — 按文档: int + 6×float + byte + float = 33 字节"""
    entity_id: int = 0
    x: float = 0.0
    y: float = 0.0
    z: float = 0.0
    vel_x: float = 0.0
    vel_y: float = 0.0
    vel_z: float = 0.0
    entity_type: int = 0
    health: float = 0.0

    FORMAT = "<IffffffBf"
    SIZE = 33

    @classmethod
    def unpack(cls, data: bytes) -> 'ChunkTransferPayload':
        fields = struct.unpack(cls.FORMAT, data[:cls.SIZE])
        return cls(*fields)

    def pack(self) -> bytes:
        return struct.pack(self.FORMAT,
                           self.entity_id,
                           self.x, self.y, self.z,
                           self.vel_x, self.vel_y, self.vel_z,
                           self.entity_type, self.health)


@dataclass
class AuthRequestPayload:
    """认证请求包 — Java encodeAuthRequest: UUID(16B) + username(变长)"""
    uuid: bytes = b'\x00' * 16
    username: str = ""

    @classmethod
    def unpack(cls, data: bytes) -> 'AuthRequestPayload':
        uuid = data[:16]
        # username 不一定以 \x00 结尾（Java 端无 padding）
        username_raw = data[16:]
        username = username_raw.decode('utf-8', errors='replace')
        return cls(uuid=uuid, username=username)

    def pack(self) -> bytes:
        name_bytes = self.username.encode('utf-8')[:16].ljust(16, b'\x00')
        return self.uuid + name_bytes


# ═══════════════════════════════════════════════════════════════
#  包头解析/构建
#
#  线格式: Magic(2B, 大端) + Type(1B) + Length(4B, 大端) = 7 字节
#
#  紧跟包头的是 IV(12B)，然后是 Payload/EncryptedPayload(Length B)。
#  Length 不含 IV，仅表示 IV 之后的数据长度。
#
#  非加密包: Header(7) + IV(12, 全零) + Payload(Length)
#  加密包:   Header(7) + IV(12, 随机) + Ciphertext+Tag(Length)
# ═══════════════════════════════════════════════════════════════

@dataclass
class PacketHeader:
    magic: int = PROTOCOL_MAGIC
    pkt_type: int = 0
    length: int = 0

    # 大端序: Magic(2) + Type(1) + Length(4) = 7 字节
    FORMAT = ">HBI"
    SIZE = PROTOCOL_HEADER_SIZE  # 7

    def pack(self) -> bytes:
        return struct.pack(self.FORMAT, self.magic, self.pkt_type, self.length)

    @classmethod
    def unpack(cls, data: bytes) -> Optional['PacketHeader']:
        if len(data) < cls.SIZE:
            return None
        magic, pkt_type, length = struct.unpack(cls.FORMAT, data[:cls.SIZE])
        if magic != PROTOCOL_MAGIC:
            return None
        return cls(magic=magic, pkt_type=pkt_type, length=length)


class PacketParseError(Exception):
    pass


class PacketReader:
    """
    从字节流中解析完整数据包，处理 TCP 粘包/拆包。

    统一线格式:
      Header(7) + IV(12) + Payload/EncryptedPayload(Length)

    Length 字段 = IV 之后的数据长度（不含 IV 本身）。

    返回值: (header, iv, payload_data, raw_bytes)
      - 非加密包: iv = 12 字节零, payload_data = 原始载荷
      - 加密包:   iv = 12 字节随机, payload_data = 密文+Tag
    """

    def __init__(self):
        self._buffer = bytearray()

    def feed(self, data: bytes):
        """喂入接收到的原始字节"""
        self._buffer.extend(data)

    def read_packet(self) -> Optional[tuple[PacketHeader, bytes, bytes, bytes]]:
        """
        尝试从缓冲区读取一个完整包。
        返回 (header, iv, payload_data, raw_bytes) 或 None。
        """
        if len(self._buffer) < PacketHeader.SIZE:
            return None

        header = PacketHeader.unpack(bytes(self._buffer[:PacketHeader.SIZE]))
        if header is None:
            # 魔数不匹配，跳过一个字节重试
            self._buffer.pop(0)
            return self.read_packet()

        # 统一格式: Header(7) + IV(12) + Payload/EncryptedPayload(Length)
        total_size = PacketHeader.SIZE + PROTOCOL_IV_SIZE + header.length
        if len(self._buffer) < total_size:
            return None

        raw = bytes(self._buffer[:total_size])
        iv = raw[PacketHeader.SIZE:PacketHeader.SIZE + PROTOCOL_IV_SIZE]
        payload_data = raw[PacketHeader.SIZE + PROTOCOL_IV_SIZE:]

        self._buffer = self._buffer[total_size:]
        return header, iv, payload_data, raw
