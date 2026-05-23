"""
Flux Server - 中继引擎
客户端管理 + 区块所有权 + 盲转发广播
"""

import time
import struct
import logging
from enum import IntEnum
from dataclasses import dataclass, field
from typing import Optional, Callable, Dict, List

from config import MAX_CLIENTS, CLIENT_TIMEOUT_SEC, TTL_VOLATILE_MS
from crypto_engine import CryptoSession

logger = logging.getLogger("flux.relay")


class ClientState(IntEnum):
    DISCONNECTED   = 0
    HANDSHAKE      = 1    # 等待 CLIENT_HELLO
    AUTHENTICATED  = 2    # 等待 AUTH_REQUEST
    SYNCING        = 3    # 正在同步世界
    ACTIVE         = 4    # 正常游戏中
    FROZEN         = 5    # 被冻结
    KICKED         = 6    # 被踢出


@dataclass
class ClientInfo:
    """每个客户端的连接信息"""
    state: ClientState = ClientState.DISCONNECTED
    crypto: CryptoSession = field(default_factory=CryptoSession)
    name: str = ""
    uuid: bytes = b'\x00' * 16
    x: float = 0.0
    y: float = 0.0
    z: float = 0.0
    last_seen: float = 0.0   # time.monotonic()
    in_use: bool = False
    address: str = ""        # "ip:port"
    sync_offset: int = 0     # 事件回放偏移

    def touch(self):
        self.last_seen = time.monotonic()

    def is_active(self) -> bool:
        return self.in_use and self.state == ClientState.ACTIVE


@dataclass
class ChunkOwner:
    """区块所有权"""
    cx: int = 0
    cz: int = 0
    owner_id: int = -1
    last_update: float = 0.0


class RelayEngine:
    """中继引擎 - 管理客户端、区块所有权、广播"""

    CHUNK_SIZE_BITS = 4  # 16x16 格
    CHUNK_SIZE = 1 << CHUNK_SIZE_BITS

    def __init__(self, max_clients: int = MAX_CLIENTS):
        self._max_clients = max_clients
        self._clients: List[ClientInfo] = [
            ClientInfo() for _ in range(max_clients)
        ]
        self._chunk_owners: Dict[tuple[int, int], ChunkOwner] = {}

        # 回调: client_id → send_fn
        self._send_fn: Optional[Callable[[int, bytes], None]] = None

    def set_send_callback(self, fn: Callable[[int, bytes], None]):
        """设置底层发送函数（由 server 提供）"""
        self._send_fn = fn

    # ─────────────────────────────────────────────────────────
    #  客户端 Slot 管理
    # ─────────────────────────────────────────────────────────

    def allocate_client(self, address: str) -> Optional[int]:
        """分配一个客户端 slot，返回 client_id"""
        for i, c in enumerate(self._clients):
            if not c.in_use:
                c.in_use = True
                c.state = ClientState.HANDSHAKE
                c.address = address
                c.last_seen = time.monotonic()
                c.crypto = CryptoSession()
                logger.info(f"Allocated client slot {i} for {address}")
                return i
        logger.warning("No free client slots!")
        return None

    def release_client(self, client_id: int):
        """释放客户端 slot"""
        if 0 <= client_id < self._max_clients:
            c = self._clients[client_id]
            c.in_use = False
            c.state = ClientState.DISCONNECTED
            c.crypto.reset()
            logger.info(f"Released client slot {client_id}")

    def get_client(self, client_id: int) -> Optional[ClientInfo]:
        if 0 <= client_id < self._max_clients:
            c = self._clients[client_id]
            if c.in_use:
                return c
        return None

    def get_all_active_clients(self) -> list[tuple[int, ClientInfo]]:
        """获取所有活跃客户端"""
        result = []
        for i, c in enumerate(self._clients):
            if c.in_use and c.state >= ClientState.ACTIVE:
                result.append((i, c))
        return result

    # ─────────────────────────────────────────────────────────
    #  状态机
    # ─────────────────────────────────────────────────────────

    def transition(self, client_id: int, new_state: ClientState):
        """客户端状态转换"""
        c = self.get_client(client_id)
        if c is None:
            return
        old = c.state
        c.state = new_state
        logger.info(f"Client {client_id}: {old.name} → {new_state.name}")

    # ─────────────────────────────────────────────────────────
    #  区块所有权
    # ─────────────────────────────────────────────────────────

    def get_chunk_coord(self, x: float, z: float) -> tuple[int, int]:
        """世界坐标 → 区块坐标"""
        return (int(x) >> self.CHUNK_SIZE_BITS,
                int(z) >> self.CHUNK_SIZE_BITS)

    def update_chunk_owner(self, client_id: int, x: float, z: float):
        """更新区块所有权（谁距离最近谁拥有）"""
        cx, cz = self.get_chunk_coord(x, z)
        key = (cx, cz)

        if key in self._chunk_owners:
            owner = self._chunk_owners[key]
            # 检查是否需要重新分配
            if owner.owner_id != client_id:
                old_owner = self.get_client(owner.owner_id)
                if old_owner and old_owner.is_active():
                    # 计算距离，选择更近的
                    old_dist = self._chunk_distance(old_owner.x, old_owner.z, cx, cz)
                    new_dist = self._chunk_distance(x, z, cx, cz)
                    if new_dist < old_dist:
                        owner.owner_id = client_id
                else:
                    owner.owner_id = client_id
            owner.last_update = time.monotonic()
        else:
            self._chunk_owners[key] = ChunkOwner(
                cx=cx, cz=cz,
                owner_id=client_id,
                last_update=time.monotonic()
            )

    def _chunk_distance(self, x: float, z: float, cx: int, cz: int) -> float:
        """玩家到区块中心的距离"""
        center_x = (cx << self.CHUNK_SIZE_BITS) + 8
        center_z = (cz << self.CHUNK_SIZE_BITS) + 8
        dx = x - center_x
        dz = z - center_z
        return dx * dx + dz * dz  # 不需要开方，比较大小即可

    def gc_chunk_owners(self):
        """清理超时的区块所有权"""
        now = time.monotonic()
        expired = [k for k, v in self._chunk_owners.items()
                   if now - v.last_update > TTL_VOLATILE_MS / 1000.0]
        for k in expired:
            del self._chunk_owners[k]

    # ─────────────────────────────────────────────────────────
    #  超时检测
    # ─────────────────────────────────────────────────────────

    def check_timeouts(self) -> list[int]:
        """检查所有客户端超时，返回超时的 client_id 列表"""
        now = time.monotonic()
        timed_out = []
        for i, c in enumerate(self._clients):
            if c.in_use and c.state >= ClientState.AUTHENTICATED:
                if now - c.last_seen > CLIENT_TIMEOUT_SEC:
                    timed_out.append(i)
                    logger.warning(f"Client {i} timed out ({c.address})")
        return timed_out

    # ─────────────────────────────────────────────────────────
    #  盲转发广播
    # ─────────────────────────────────────────────────────────

    def broadcast(self, sender_id: int, pkt_type: int,
                  payload: bytes):
        """
        将数据包广播给所有活跃客户端（除发送者外）。
        每个客户端使用各自会话密钥加密。
        """
        if self._send_fn is None:
            logger.error("No send callback registered!")
            return

        from crypto_engine import CryptoEngine

        sent_count = 0
        for i, c in enumerate(self._clients):
            if i == sender_id:
                continue
            if not c.in_use:
                continue
            if c.state < ClientState.ACTIVE:
                continue
            if c.state == ClientState.FROZEN:
                continue

            encrypted = CryptoEngine.encrypt_packet(c.crypto, pkt_type, payload)
            if encrypted:
                try:
                    self._send_fn(i, encrypted)
                    sent_count += 1
                except Exception as e:
                    logger.error(f"Failed to send to client {i}: {e}")

        if sent_count > 0:
            logger.debug(f"Broadcast 0x{pkt_type:02X} from {sender_id} "
                         f"to {sent_count} clients")
