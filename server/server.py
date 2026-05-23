"""
Flux Server - 主服务端
Decentralized Minecraft Server - Hardware Validator
TCP 服务器 + 完整数据处理流程
"""

import asyncio
import struct
import time
import logging
import signal
from typing import Optional

from config import (
    SERVER_HOST, SERVER_PORT, MAX_CLIENTS, PROTOCOL_MAGIC,
    PROTOCOL_IV_SIZE,
    PING_INTERVAL_SEC, PING_TIMEOUT_SEC,
    SYNC_BATCH_SIZE, SYNC_BATCH_DELAY_MS
)
from protocol import (
    PacketType, PacketHeader, PacketReader, PacketParseError,
    PlayerMovePayload, BlockBreakPayload, BlockPlacePayload,
    EntityInteractPayload, InventoryChangePayload,
    ChestModifyPayload, ChunkTransferPayload,
    AuthRequestPayload
)
from crypto_engine import CryptoEngine
from packet_validator import PacketValidator, ViolationAction
from event_logger import EventLogger
from relay_engine import RelayEngine, ClientState

logger = logging.getLogger("flux.server")


class ClientSession:
    """单个客户端的会话上下文"""

    def __init__(self, client_id: int, address: str):
        self.client_id = client_id
        self.address = address
        self.reader = PacketReader()
        self.writer: Optional[asyncio.StreamWriter] = None
        self.connected = True


class FluxServer:
    """Flux TCP 服务端主类"""

    def __init__(self):
        self.crypto_engine = CryptoEngine()
        self.validator = PacketValidator()
        self.event_logger = EventLogger()
        self.relay = RelayEngine(MAX_CLIENTS)
        self.relay.set_send_callback(self._send_to_client)

        self._sessions: dict[int, ClientSession] = {}
        self._server: Optional[asyncio.AbstractServer] = None
        self._running = False

    # ═══════════════════════════════════════════════════════════
    #  启动 / 关闭
    # ═══════════════════════════════════════════════════════════

    async def start(self):
        """启动服务器"""
        print("=" * 56)
        print("  Flux - Decentralized MC Server (PC Edition)")
        print("  synergyedge Team")
        print("=" * 56)

        # [1] 加密引擎初始化
        print("[1/4] Initializing crypto engine...")
        self.crypto_engine.generate_keypair()

        # [2] 事件日志初始化
        print("[2/4] Initializing event logger...")
        if not self.event_logger.init():
            logger.error("Event logger init failed!")
            return

        # [3] 包校验器
        print("[3/4] Initializing packet validator...")
        # validator 无需额外初始化

        # [4] 启动 TCP 服务
        print(f"[4/4] Starting TCP server on {SERVER_HOST}:{SERVER_PORT}...")
        self._server = await asyncio.start_server(
            self._handle_client, SERVER_HOST, SERVER_PORT
        )
        self._running = True

        print("=" * 56)
        print(f"Flux ready. Listening on {SERVER_HOST}:{SERVER_PORT}")
        print(f"Max clients: {MAX_CLIENTS}")
        print(f"World seed: {self.event_logger.get_world_seed()}")
        print(f"Events loaded: {self.event_logger.get_event_count()}")
        print("=" * 56)

        # 启动维护任务
        asyncio.create_task(self._maintenance_loop())
        asyncio.create_task(self._ping_loop())

        async with self._server:
            await self._server.serve_forever()

    async def shutdown(self):
        """优雅关闭"""
        logger.info("Shutting down Flux server...")
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    # ═══════════════════════════════════════════════════════════
    #  客户端连接处理
    # ═══════════════════════════════════════════════════════════

    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter):
        """处理一个客户端连接"""
        addr = writer.get_extra_info('peername')
        address_str = f"{addr[0]}:{addr[1]}"

        # 分配 slot
        client_id = self.relay.allocate_client(address_str)
        if client_id is None:
            logger.warning(f"Rejected connection from {address_str} (no free slots)")
            writer.close()
            return

        session = ClientSession(client_id, address_str)
        session.writer = writer
        self._sessions[client_id] = session

        logger.info(f"Client {client_id} connected from {address_str}")

        try:
            while self._running and session.connected:
                data = await reader.read(4096)
                if not data:
                    break

                session.reader.feed(data)

                # 尝试解析所有完整包
                while True:
                    result = session.reader.read_packet()
                    if result is None:
                        break
                    header, iv, ciphertext, raw = result
                    await self._process_packet(session, header, iv, ciphertext)

        except asyncio.CancelledError:
            pass
        except ConnectionResetError:
            logger.info(f"Client {client_id} connection reset")
        except Exception as e:
            logger.error(f"Client {client_id} error: {e}", exc_info=True)
        finally:
            # 清理
            self.relay.release_client(client_id)
            self.validator.reset_player(client_id)
            self._sessions.pop(client_id, None)
            writer.close()
            logger.info(f"Client {client_id} disconnected")

    # ═══════════════════════════════════════════════════════════
    #  数据包处理主流程
    # ═══════════════════════════════════════════════════════════

    async def _process_packet(self, session: ClientSession,
                              header: PacketHeader,
                              iv: bytes, ciphertext: bytes):
        """处理一个完整的数据包"""
        client_id = session.client_id
        client = self.relay.get_client(client_id)
        if client is None:
            return

        client.touch()
        pkt_type = header.pkt_type

        # ─── 前握手阶段（密钥未就绪）───
        if pkt_type == PacketType.CLIENT_HELLO:
            await self._handle_client_hello(session, iv, ciphertext)
            return

        if pkt_type == PacketType.AUTH_REQUEST:
            await self._handle_auth_request(session, header, iv, ciphertext)
            return

        # ─── 后握手阶段（密钥就绪）───
        if not client.crypto.key_ready:
            logger.warning(f"Client {client_id} sent encrypted packet "
                           f"before key exchange")
            return

        # 解密
        payload = CryptoEngine.decrypt_packet(
            client.crypto, header, iv, ciphertext)
        if payload is None:
            logger.warning(f"Client {client_id}: decryption failed, "
                           f"pkt_type=0x{pkt_type:02X}")
            return

        # 分发处理
        await self._dispatch_game_packet(session, pkt_type, payload)

    # ═══════════════════════════════════════════════════════════
    #  握手处理
    # ═══════════════════════════════════════════════════════════

    async def _handle_client_hello(self, session: ClientSession,
                                   iv: bytes, ciphertext: bytes):
        """
        处理 CLIENT_HELLO: 提取客户端 ECDH 公钥，派生会话密钥，返回匹配的公钥。
        非加密包，PacketReader 返回 iv=12 字节零, payload_data=客户端公钥。
        """
        client_id = session.client_id
        client = self.relay.get_client(client_id)

        # CLIENT_HELLO 为非加密包，payload_data 即客户端公钥
        client_pubkey = ciphertext  # 参数名沿用旧接口，实际是 payload_data

        if len(client_pubkey) < 32:
            logger.error(f"Client {client_id}: CLIENT_HELLO too short "
                         f"({len(client_pubkey)} < 32)")
            return

        # 派生会话密钥（自动检测 X25519 或 P-256）
        if not self.crypto_engine.derive_session_key(client.crypto, client_pubkey):
            logger.error(f"Client {client_id}: key derivation failed")
            return

        # 根据客户端密钥类型，返回匹配的服务端公钥
        # Java 客户端使用 P-256 (91 字节 DER SubjectPublicKeyInfo)
        # 必须返回 P-256 公钥，否则客户端无法解析
        if len(client_pubkey) == 32:
            # 客户端发送 X25519 原始公钥 → 返回 X25519
            server_pubkey = self.crypto_engine._server_x25519_public_bytes
            logger.info(f"Client {client_id}: using X25519 key exchange")
        else:
            # 客户端发送 P-256 (DER/Flux格式) → 返回 P-256 DER SubjectPublicKeyInfo
            server_pubkey = self.crypto_engine._server_p256_der_bytes
            logger.info(f"Client {client_id}: using P-256 key exchange "
                        f"({len(server_pubkey)} bytes)")

        header = PacketHeader(
            magic=PROTOCOL_MAGIC,
            pkt_type=PacketType.SERVER_HELLO,
            length=len(server_pubkey)  # Length = payload 长度（不含 IV）
        )
        zero_iv = b'\x00' * PROTOCOL_IV_SIZE
        response = header.pack() + zero_iv + server_pubkey
        await self._send_raw(session, response)

        # 状态转换
        self.relay.transition(client_id, ClientState.AUTHENTICATED)
        logger.info(f"Client {client_id}: handshake complete, "
                    f"waiting for AUTH_REQUEST")

    async def _handle_auth_request(self, session: ClientSession,
                                   header: PacketHeader,
                                   iv: bytes, ciphertext: bytes):
        """处理 AUTH_REQUEST: 解密 + 认证"""
        client_id = session.client_id
        client = self.relay.get_client(client_id)

        # 解密认证请求
        payload = CryptoEngine.decrypt_packet(
            client.crypto, header, iv, ciphertext)
        if payload is None:
            logger.error(f"Client {client_id}: AUTH_REQUEST decrypt failed")
            self._send_auth_fail(session, "Authentication failed")
            return

        # 解析 UUID + 用户名
        auth = AuthRequestPayload.unpack(payload)
        client.uuid = auth.uuid
        client.name = auth.username
        logger.info(f"Client {client_id} authenticated as '{auth.username}' "
                    f"(UUID={auth.uuid.hex()[:16]}...)")

        # 认证成功
        self._send_auth_success(session)
        self.relay.transition(client_id, ClientState.SYNCING)

        # 开始世界同步
        await self._sync_world_to_client(session)

    async def _sync_world_to_client(self, session: ClientSession):
        """
        三阶段世界同步:
        1. 发送世界种子
        2. 回放事件日志
        3. 发送同步完成
        """
        client_id = session.client_id

        # 阶段 1: 种子
        seed = struct.pack("<q", self.event_logger.get_world_seed())
        encrypted = CryptoEngine.encrypt_packet(
            self.relay.get_client(client_id).crypto,
            PacketType.SEED_SYNC, seed)
        if encrypted:
            await self._send_raw(session, encrypted)
            logger.info(f"Client {client_id}: sent world seed")

        # 阶段 2: 事件回放
        events = self.event_logger.get_events_since(0)
        sent = 0
        for i, entry in enumerate(events):
            # 打包事件: type(1) + data
            event_data = struct.pack("B", entry.event_type) + entry.data
            encrypted = CryptoEngine.encrypt_packet(
                self.relay.get_client(client_id).crypto,
                PacketType.CHUNK_LOG_ENTRY, event_data)
            if encrypted:
                await self._send_raw(session, encrypted)
                sent += 1

            # 每 SYNC_BATCH_SIZE 条暂停一下，防止发送过快
            if sent % SYNC_BATCH_SIZE == 0:
                await asyncio.sleep(SYNC_BATCH_DELAY_MS / 1000.0)

        logger.info(f"Client {client_id}: replayed {sent} events")

        # 阶段 3: 同步完成
        encrypted = CryptoEngine.encrypt_packet(
            self.relay.get_client(client_id).crypto,
            PacketType.SYNC_COMPLETE, b'')
        if encrypted:
            await self._send_raw(session, encrypted)

        # 状态转换为 ACTIVE
        self.relay.transition(client_id, ClientState.ACTIVE)
        logger.info(f"Client {client_id}: world sync complete, now ACTIVE")

    def _send_auth_success(self, session: ClientSession):
        client = self.relay.get_client(session.client_id)
        encrypted = CryptoEngine.encrypt_packet(
            client.crypto, PacketType.AUTH_SUCCESS, b'')
        if encrypted:
            asyncio.ensure_future(self._send_raw(session, encrypted))

    def _send_auth_fail(self, session: ClientSession, reason: str):
        client = self.relay.get_client(session.client_id)
        encrypted = CryptoEngine.encrypt_packet(
            client.crypto, PacketType.AUTH_FAIL,
            reason.encode('utf-8'))
        if encrypted:
            asyncio.ensure_future(self._send_raw(session, encrypted))

    # ═══════════════════════════════════════════════════════════
    #  游戏事件分发
    # ═══════════════════════════════════════════════════════════

    async def _dispatch_game_packet(self, session: ClientSession,
                                    pkt_type: int, payload: bytes):
        """分发已解密的游戏事件包"""
        client_id = session.client_id
        client = self.relay.get_client(client_id)

        # 冻结客户端只允许心跳
        if client.state == ClientState.FROZEN:
            if pkt_type not in (PacketType.PING, PacketType.PONG):
                logger.debug(f"Frozen client {client_id} sent 0x{pkt_type:02X}, ignored")
                return

        handlers = {
            PacketType.PLAYER_MOVE: self._handle_player_move,
            PacketType.BLOCK_BREAK: self._handle_block_break,
            PacketType.BLOCK_PLACE: self._handle_block_place,
            PacketType.ENTITY_INTERACT: self._handle_entity_interact,
            PacketType.INVENTORY_CHANGE: self._handle_inventory_change,
            PacketType.CHEST_MODIFY: self._handle_chest_modify,
            PacketType.CHUNK_TRANSFER: self._handle_chunk_transfer,
            PacketType.PING: self._handle_ping,
        }

        handler = handlers.get(pkt_type)
        if handler:
            await handler(session, payload)
        else:
            logger.warning(f"Unknown packet type 0x{pkt_type:02X} "
                           f"from client {client_id}")

    # ─────────────────────────────────────────────────────────
    #  各类游戏事件处理
    # ─────────────────────────────────────────────────────────

    async def _handle_player_move(self, session: ClientSession, payload: bytes):
        """处理玩家移动"""
        client_id = session.client_id
        try:
            pkt = PlayerMovePayload.unpack(payload)
        except Exception as e:
            logger.error(f"Invalid move packet from {client_id}: {e}")
            return

        # 规则一: 速度校验
        result = self.validator.check_speed(
            client_id, pkt.x, pkt.y, pkt.z)
        if not result.ok:
            await self._handle_violation(session, result)
            return

        # 更新区块所有权
        client = self.relay.get_client(client_id)
        if client:
            client.x, client.y, client.z = pkt.x, pkt.y, pkt.z
            self.relay.update_chunk_owner(client_id, pkt.x, pkt.z)

        # 广播给其他玩家
        self.relay.broadcast(client_id, PacketType.BROADCAST_MOVE, payload)

    async def _handle_block_break(self, session: ClientSession, payload: bytes):
        """处理方块破坏"""
        client_id = session.client_id
        try:
            pkt = BlockBreakPayload.unpack(payload)
        except Exception as e:
            logger.error(f"Invalid block_break from {client_id}: {e}")
            return

        # 规则二: 距离校验
        result = self.validator.check_interaction_distance(
            client_id, float(pkt.x), float(pkt.y), float(pkt.z))
        if not result.ok:
            await self._handle_violation(session, result)
            return

        # 规则四: 方块存在性校验
        result = self.validator.check_block_event(
            client_id, pkt.x, pkt.y, pkt.z, pkt.block_id, is_break=True)
        if not result.ok:
            await self._handle_violation(session, result)
            return

        # 记录事件日志
        self.event_logger.log_event(client_id, PacketType.BLOCK_BREAK, payload)

        # 广播
        self.relay.broadcast(client_id, PacketType.BROADCAST_BLOCK, payload)

    async def _handle_block_place(self, session: ClientSession, payload: bytes):
        """处理方块放置"""
        client_id = session.client_id
        try:
            pkt = BlockPlacePayload.unpack(payload)
        except Exception as e:
            logger.error(f"Invalid block_place from {client_id}: {e}")
            return

        result = self.validator.check_interaction_distance(
            client_id, float(pkt.x), float(pkt.y), float(pkt.z))
        if not result.ok:
            await self._handle_violation(session, result)
            return

        result = self.validator.check_block_event(
            client_id, pkt.x, pkt.y, pkt.z, pkt.block_id, is_break=False)
        if not result.ok:
            await self._handle_violation(session, result)
            return

        self.event_logger.log_event(client_id, PacketType.BLOCK_PLACE, payload)
        self.relay.broadcast(client_id, PacketType.BROADCAST_BLOCK, payload)

    async def _handle_entity_interact(self, session: ClientSession, payload: bytes):
        """处理实体交互"""
        client_id = session.client_id
        try:
            pkt = EntityInteractPayload.unpack(payload)
        except Exception as e:
            logger.error(f"Invalid entity_interact from {client_id}: {e}")
            return

        is_attack = (pkt.action == 0)
        result = self.validator.check_interaction_distance(
            client_id, pkt.player_x, pkt.player_y, pkt.player_z,
            is_attack=is_attack)
        if not result.ok:
            await self._handle_violation(session, result)
            return

        self.event_logger.log_event(
            client_id, PacketType.ENTITY_INTERACT, payload)
        self.relay.broadcast(
            client_id, PacketType.BROADCAST_ENTITY, payload)

    async def _handle_inventory_change(self, session: ClientSession,
                                       payload: bytes):
        """处理物品栏变更"""
        client_id = session.client_id
        try:
            pkt = InventoryChangePayload.unpack(payload)
        except Exception as e:
            logger.error(f"Invalid inventory_change from {client_id}: {e}")
            return

        # 物品守恒校验（无容器时跳过）
        result = self.validator.check_inventory_operation(
            client_id, None, pkt.slot_index,
            pkt.item_id, pkt.count, pkt.action)
        if not result.ok:
            await self._handle_violation(session, result)
            return

        self.event_logger.log_event(
            client_id, PacketType.INVENTORY_CHANGE, payload)
        self.relay.broadcast(
            client_id, PacketType.BROADCAST_INVENTORY, payload)

    async def _handle_chest_modify(self, session: ClientSession,
                                   payload: bytes):
        """处理容器修改"""
        client_id = session.client_id
        try:
            pkt = ChestModifyPayload.unpack(payload)
        except Exception as e:
            logger.error(f"Invalid chest_modify from {client_id}: {e}")
            return

        container_pos = (pkt.x, pkt.y, pkt.z)
        result = self.validator.check_inventory_operation(
            client_id, container_pos, pkt.slot_index,
            pkt.item_id, pkt.count, action=1)  # 1=放入
        if not result.ok:
            await self._handle_violation(session, result)
            return

        self.validator.update_container(
            container_pos, pkt.slot_index, pkt.item_id, pkt.count)
        self.event_logger.log_event(
            client_id, PacketType.CHEST_MODIFY, payload)
        self.relay.broadcast(
            client_id, PacketType.BROADCAST_INVENTORY, payload)

    async def _handle_chunk_transfer(self, session: ClientSession,
                                     payload: bytes):
        """处理区块跨界传输"""
        client_id = session.client_id
        try:
            pkt = ChunkTransferPayload.unpack(payload)
        except Exception as e:
            logger.error(f"Invalid chunk_transfer from {client_id}: {e}")
            return

        self.event_logger.log_event(
            client_id, PacketType.CHUNK_TRANSFER, payload)
        self.relay.broadcast(
            client_id, PacketType.BROADCAST_ENTITY, payload)

    async def _handle_ping(self, session: ClientSession, payload: bytes):
        """处理心跳"""
        client_id = session.client_id
        client = self.relay.get_client(client_id)
        encrypted = CryptoEngine.encrypt_packet(
            client.crypto, PacketType.PONG, payload)
        if encrypted:
            await self._send_raw(session, encrypted)

    # ═══════════════════════════════════════════════════════════
    #  违规处理
    # ═══════════════════════════════════════════════════════════

    async def _handle_violation(self, session: ClientSession,
                                result):
        """根据违规等级执行惩罚"""
        client_id = session.client_id
        client = self.relay.get_client(client_id)

        if result.action == ViolationAction.ROLLBACK:
            # 回滚: 发送 ROLLBACK 包
            encrypted = CryptoEngine.encrypt_packet(
                client.crypto, PacketType.ROLLBACK, b'')
            if encrypted:
                await self._send_raw(session, encrypted)
            logger.info(f"Client {client_id}: ROLLBACK - {result.reason}")

        elif result.action == ViolationAction.FREEZE:
            # 冻结
            client.state = ClientState.FROZEN
            encrypted = CryptoEngine.encrypt_packet(
                client.crypto, PacketType.FREEZE, b'')
            if encrypted:
                await self._send_raw(session, encrypted)
            logger.warning(f"Client {client_id}: FROZEN - {result.reason}")

        elif result.action == ViolationAction.KICK:
            # 踢出
            encrypted = CryptoEngine.encrypt_packet(
                client.crypto, PacketType.KICK,
                result.reason.encode('utf-8'))
            if encrypted:
                await self._send_raw(session, encrypted)
            logger.warning(f"Client {client_id}: KICK - {result.reason}")
            session.connected = False  # 断开连接

    # ═══════════════════════════════════════════════════════════
    #  网络 I/O
    # ═══════════════════════════════════════════════════════════

    async def _send_raw(self, session: ClientSession, data: bytes):
        """发送原始字节到客户端"""
        if session.writer is None:
            return
        try:
            session.writer.write(data)
            await session.writer.drain()
        except Exception as e:
            logger.error(f"Send to {session.client_id} failed: {e}")
            session.connected = False

    def _send_to_client(self, client_id: int, data: bytes):
        """同步发送接口（供 relay.broadcast 回调使用）"""
        session = self._sessions.get(client_id)
        if session and session.writer:
            try:
                session.writer.write(data)
                # drain 在事件循环中异步完成
                asyncio.ensure_future(session.writer.drain())
            except Exception as e:
                logger.error(f"Relay send to {client_id} failed: {e}")

    # ═══════════════════════════════════════════════════════════
    #  维护任务
    # ═══════════════════════════════════════════════════════════

    async def _maintenance_loop(self):
        """定期维护: 超时检测、区块 GC"""
        while self._running:
            await asyncio.sleep(5)

            # 超时检测
            timed_out = self.relay.check_timeouts()
            for cid in timed_out:
                session = self._sessions.get(cid)
                if session:
                    session.connected = False

            # 区块所有权 GC
            self.relay.gc_chunk_owners()

    async def _ping_loop(self):
        """定期发送心跳"""
        while self._running:
            await asyncio.sleep(PING_INTERVAL_SEC)
            for cid, client in self.relay.get_all_active_clients():
                session = self._sessions.get(cid)
                if session and session.connected:
                    ping_data = struct.pack("<f", time.monotonic())
                    encrypted = CryptoEngine.encrypt_packet(
                        client.crypto, PacketType.PING, ping_data)
                    if encrypted:
                        await self._send_raw(session, encrypted)
