#!/usr/bin/env python3
"""
Flux Server - 图形化后台控制台
Decentralized Minecraft Server - Full GUI Dashboard

Features:
  - 服务器启停控制
  - 实时状态监控（连接数、CPU、内存、网络）
  - 快捷指令面板
  - 在线玩家管理
  - 防作弊系统监控
  - 事件日志查看
  - 服务器配置面板

依赖：Python 标准库 (tkinter)
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import asyncio
import threading
import time
import struct
import os
import sys
import json
import socket
import hashlib
import logging
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, List
from collections import deque

# 协议模块（与 flux_dashboard.py 同目录）
from protocol import (
    PacketType, PacketHeader, PacketReader,
    UNENCRYPTED_PACKET_TYPES, PROTOCOL_IV_SIZE,
    PlayerMovePayload, BlockBreakPayload, BlockPlacePayload,
    EntityInteractPayload, InventoryChangePayload,
    ChestModifyPayload, ChunkTransferPayload,
    AuthRequestPayload
)
from crypto_engine import CryptoEngine, CryptoSession
from packet_validator import PacketValidator, ViolationAction
from event_logger import EventLogger

# ═══════════════════════════════════════════════════════════════
#  配置
# ═══════════════════════════════════════════════════════════════

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 25580
MAX_CLIENTS = 16
CLIENT_TIMEOUT_SEC = 600
PROTOCOL_MAGIC = 0x4658  # "FX"
PING_INTERVAL_SEC = 5

LOG_DIR = "./flux_data"
EVENT_LOG_DIR = "./flux_data/events"

# ═══════════════════════════════════════════════════════════════
#  主题色彩
# ═══════════════════════════════════════════════════════════════

class Theme:
    BG          = "#0f0f1a"
    BG_PANEL    = "#16162a"
    BG_CARD     = "#1c1c36"
    BG_INPUT    = "#222244"
    FG          = "#e0e0f0"
    FG_DIM      = "#8888aa"
    ACCENT      = "#6c5ce7"
    ACCENT_LIGHT= "#a29bfe"
    GREEN       = "#00e676"
    GREEN_DIM   = "#1b5e20"
    RED         = "#ff5252"
    RED_DIM     = "#b71c1c"
    YELLOW      = "#ffd740"
    ORANGE      = "#ff9100"
    CYAN        = "#00e5ff"
    BORDER      = "#2a2a50"
    HOVER       = "#2a2a55"

    FONT_TITLE  = ("Segoe UI", 18, "bold")
    FONT_H2     = ("Segoe UI", 13, "bold")
    FONT_BODY   = ("Segoe UI", 10)
    FONT_MONO   = ("Cascadia Code", 10)
    FONT_SMALL  = ("Segoe UI", 9)
    FONT_STAT   = ("Cascadia Code", 22, "bold")
    FONT_STAT_L = ("Cascadia Code", 14, "bold")


# ═══════════════════════════════════════════════════════════════
#  服务器核心（内嵌简化版）
# ═══════════════════════════════════════════════════════════════

@dataclass
class ClientSlot:
    """在线客户端"""
    cid: int = -1
    address: str = ""
    name: str = ""
    uuid: bytes = b'\x00' * 16
    state: str = "DISCONNECTED"
    x: float = 0.0
    y: float = 0.0
    z: float = 0.0
    connected_at: float = 0.0
    last_seen: float = 0.0
    violations: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    in_use: bool = False
    crypto: CryptoSession = field(default_factory=CryptoSession)
    reader: PacketReader = field(default_factory=PacketReader)
    writer: Optional[asyncio.StreamWriter] = field(default=None, repr=False)


class FluxServerCore:
    """
    Flux 服务端核心逻辑。
    通过回调向 GUI 推送事件。
    """

    def __init__(self):
        self._server: Optional[asyncio.AbstractServer] = None
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._clients: Dict[int, ClientSlot] = {}
        self._next_cid = 0
        self._start_time: float = 0.0

        # 协议组件
        self.crypto_engine = CryptoEngine()
        self.validator = PacketValidator()
        self.event_logger = EventLogger()

        # 统计
        self.total_connections = 0
        self.total_packets = 0
        self.total_bytes_in = 0
        self.total_bytes_out = 0
        self.total_violations = 0
        self.total_events_logged = 0

        # 事件日志
        self.event_log: deque = deque(maxlen=5000)

        # 回调
        self.on_log: Optional[callable] = None
        self.on_client_change: Optional[callable] = None
        self.on_stats_update: Optional[callable] = None

        # 数据目录
        os.makedirs(EVENT_LOG_DIR, exist_ok=True)

    @property
    def uptime(self) -> float:
        if self._start_time == 0:
            return 0
        return time.time() - self._start_time

    @property
    def online_count(self) -> int:
        return sum(1 for c in self._clients.values() if c.in_use)

    def _log(self, level: str, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        entry = f"[{ts}] [{level}] {msg}"
        if self.on_log:
            self.on_log(entry, level)

    def _emit_client_change(self):
        if self.on_client_change:
            self.on_client_change()

    def _emit_stats(self):
        if self.on_stats_update:
            self.on_stats_update()

    async def start(self):
        """启动服务器"""
        if self._running:
            return
        self._running = True
        self._start_time = time.time()

        self._log("INFO", "═" * 50)
        self._log("INFO", "  Flux Server v2.0 — Decentralized MC Server")
        self._log("INFO", "  synergyedge Team")
        self._log("INFO", "═" * 50)

        # 初始化加密引擎
        self.crypto_engine.generate_keypair()
        self._log("INFO", "[1/3] Crypto engine initialized (ECDH + AES-128-GCM)")

        # 设置 crypto 日志级别以捕获详细错误
        logging.getLogger("flux.crypto").setLevel(logging.DEBUG)
        if not logging.getLogger("flux.crypto").handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter('[%(name)s] %(levelname)s: %(message)s'))
            logging.getLogger("flux.crypto").addHandler(handler)

        # 初始化事件日志
        self.event_logger.init()
        self._log("INFO", "[2/3] Event logger ready")

        self._log("INFO", f"[3/3] Starting TCP server on {SERVER_HOST}:{SERVER_PORT}...")

        try:
            self._server = await asyncio.start_server(
                self._handle_client, SERVER_HOST, SERVER_PORT
            )
            self._log("INFO", "═" * 50)
            self._log("INFO", f"  Flux ready. Listening on {SERVER_HOST}:{SERVER_PORT}")
            self._log("INFO", f"  Max clients: {MAX_CLIENTS}")
            self._log("INFO", f"  Protocol magic: 0x{PROTOCOL_MAGIC:04X}")
            self._log("INFO", "═" * 50)
            self._emit_stats()

            # 心跳循环
            asyncio.create_task(self._ping_loop())

            async with self._server:
                await self._server.serve_forever()
        except OSError as e:
            self._log("ERROR", f"Failed to start server: {e}")
            self._running = False

    async def shutdown(self):
        """停止服务器"""
        if not self._running:
            return
        self._running = False
        self._log("INFO", "Shutting down Flux server...")

        # 断开所有客户端
        for cid in list(self._clients.keys()):
            self._disconnect_client(cid)

        if self._server:
            self._server.close()
            await self._server.wait_closed()

        self._log("INFO", "Flux server stopped.")
        self._emit_stats()
        self._emit_client_change()

    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        addr_str = f"{addr[0]}:{addr[1]}"

        if self.online_count >= MAX_CLIENTS:
            self._log("WARN", f"Rejected {addr_str} (server full)")
            writer.close()
            return

        cid = self._next_cid
        self._next_cid += 1

        slot = ClientSlot(
            cid=cid, address=addr_str,
            state="HANDSHAKE", connected_at=time.time(),
            last_seen=time.time(), in_use=True,
            crypto=CryptoSession(),
            reader=PacketReader(),
            writer=writer,
        )
        self._clients[cid] = slot
        self.total_connections += 1

        self._log("INFO", f"Client #{cid} connected from {addr_str}")
        self._emit_client_change()
        self._emit_stats()

        try:
            while self._running and slot.in_use:
                data = await reader.read(4096)
                if not data:
                    break
                slot.bytes_in += len(data)
                self.total_bytes_in += len(data)
                self.total_packets += 1
                slot.last_seen = time.time()
                self._emit_stats()

                slot.reader.feed(data)

                while True:
                    result = slot.reader.read_packet()
                    if result is None:
                        break
                    header, iv, payload_data, raw = result
                    print(f"[FLUX] Parsed pkt type=0x{header.pkt_type:02X} "
                          f"len={header.length} from #{cid}",
                          file=sys.stderr, flush=True)
                    await self._process_packet(slot, header, iv, payload_data)

        except asyncio.CancelledError:
            pass
        except ConnectionResetError:
            print(f"[FLUX] Client #{cid}: connection reset",
                  file=sys.stderr, flush=True)
        except Exception as e:
            print(f"[FLUX] Client #{cid}: EXCEPTION in _handle_client: "
                  f"{type(e).__name__}: {e}", file=sys.stderr, flush=True)
            import traceback
            traceback.print_exc()
            self._log("ERROR", f"Client #{cid} error: {e}")
        finally:
            self._disconnect_client(cid)
            writer.close()

    def _disconnect_client(self, cid: int):
        slot = self._clients.get(cid)
        if slot and slot.in_use:
            slot.in_use = False
            slot.state = "DISCONNECTED"
            slot.crypto.reset()
            self.validator.reset_player(cid)
            duration = time.time() - slot.connected_at
            self._log("INFO", f"Client #{cid} ({slot.name or slot.address}) "
                      f"disconnected (duration: {duration:.0f}s)")
            self._emit_client_change()
            self._emit_stats()

    # ═══════════════════════════════════════════════════════════
    #  协议处理
    # ═══════════════════════════════════════════════════════════

    async def _process_packet(self, slot: ClientSlot,
                              header: PacketHeader,
                              iv: bytes, payload_data: bytes):
        """处理一个完整的数据包"""
        pkt_type = header.pkt_type
        self._log("INFO", f"Client #{slot.cid}: recv pkt 0x{pkt_type:02X} "
                   f"(len={header.length}, state={slot.state})")

        # ─── 前握手阶段（密钥未就绪）───
        if pkt_type == PacketType.CLIENT_HELLO:
            await self._handle_client_hello(slot, iv, payload_data)
            return

        if pkt_type == PacketType.AUTH_REQUEST:
            await self._handle_auth_request(slot, header, iv, payload_data)
            return

        # ─── 后握手阶段（密钥就绪）───
        if not slot.crypto.key_ready:
            self._log("WARN", f"Client #{slot.cid} sent encrypted packet "
                       f"before key exchange (type=0x{pkt_type:02X})")
            return

        # 解密
        payload = CryptoEngine.decrypt_packet(slot.crypto, header, iv, payload_data)
        if payload is None:
            self._log("WARN", f"Client #{slot.cid}: decryption failed "
                       f"(pkt_type=0x{pkt_type:02X})")
            return

        # 分发游戏事件
        await self._dispatch_game_packet(slot, pkt_type, payload)

    async def _handle_client_hello(self, slot: ClientSlot,
                                   iv: bytes, payload_data: bytes):
        """处理 CLIENT_HELLO: 提取客户端 ECDH 公钥，派生会话密钥，回复 SERVER_HELLO"""
        client_pubkey = payload_data

        print(f"[FLUX] Client #{slot.cid}: CLIENT_HELLO recv {len(client_pubkey)}B "
              f"hex={client_pubkey[:16].hex()}...", file=sys.stderr, flush=True)

        if len(client_pubkey) < 32:
            print(f"[FLUX] Client #{slot.cid}: CLIENT_HELLO too short!", file=sys.stderr, flush=True)
            return

        # 派生会话密钥（自动检测 X25519 / P-256）
        if not self.crypto_engine.derive_session_key(slot.crypto, client_pubkey):
            print(f"[FLUX] Client #{slot.cid}: key derivation FAILED", file=sys.stderr, flush=True)
            return

        # 根据客户端密钥类型选择对应的服务端公钥
        if len(client_pubkey) == 32:
            server_pubkey = self.crypto_engine._server_x25519_public_bytes
        else:
            server_pubkey = self.crypto_engine._server_p256_der_bytes


        # 构造 SERVER_HELLO 包
        header = PacketHeader(
            magic=PROTOCOL_MAGIC,
            pkt_type=PacketType.SERVER_HELLO,
            length=len(server_pubkey)
        )
        zero_iv = b'\x00' * PROTOCOL_IV_SIZE
        response = header.pack() + zero_iv + server_pubkey

        # 直接写 socket，不走任何中间层
        print(f"[FLUX] Client #{slot.cid}: sending SERVER_HELLO "
              f"{len(response)}B header={response[:7].hex()}", file=sys.stderr, flush=True)
        try:
            slot.writer.write(response)
            await slot.writer.drain()
            slot.bytes_out += len(response)
            self.total_bytes_out += len(response)
            print(f"[FLUX] Client #{slot.cid}: SERVER_HELLO sent OK "
                  f"({len(response)} bytes)", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"[FLUX] Client #{slot.cid}: SEND FAILED: {e}",
                  file=sys.stderr, flush=True)
            return

        slot.state = "AUTHENTICATED"
        self._log("INFO", f"Client #{slot.cid}: handshake complete, "
                   f"waiting for AUTH_REQUEST")
        self._emit_client_change()

    async def _handle_auth_request(self, slot: ClientSlot,
                                   header: PacketHeader,
                                   iv: bytes, payload_data: bytes):
        """处理 AUTH_REQUEST: 解密 + 认证 + 世界同步"""
        payload = CryptoEngine.decrypt_packet(slot.crypto, header, iv, payload_data)
        if payload is None:
            self._log("ERROR", f"Client #{slot.cid}: AUTH_REQUEST decrypt failed")
            await self._send_encrypted(slot, PacketType.AUTH_FAIL,
                                       b"Authentication failed")
            return

        auth = AuthRequestPayload.unpack(payload)
        slot.uuid = auth.uuid
        slot.name = auth.username
        self._log("INFO", f"Client #{slot.cid} authenticated as '{auth.username}'")

        # 认证成功
        await self._send_encrypted(slot, PacketType.AUTH_SUCCESS, b'')
        slot.state = "SYNCING"
        self._emit_client_change()

        # 世界同步
        await self._sync_world_to_client(slot)

        # 激活
        slot.state = "ACTIVE"
        self._log("INFO", f"Client #{slot.cid}: world sync complete, now ACTIVE")
        self._emit_client_change()

    async def _sync_world_to_client(self, slot: ClientSlot):
        """三阶段世界同步: 种子 → 事件回放 → 同步完成"""
        # 阶段 1: 种子
        seed = struct.pack("<q", self.event_logger.get_world_seed())
        await self._send_encrypted(slot, PacketType.SEED_SYNC, seed)
        self._log("INFO", f"Client #{slot.cid}: sent world seed")

        # 阶段 2: 事件回放
        events = self.event_logger.get_events_since(0)
        sent = 0
        for entry in events:
            event_data = struct.pack("B", entry.event_type) + entry.data
            await self._send_encrypted(slot, PacketType.CHUNK_LOG_ENTRY, event_data)
            sent += 1
            if sent % 10 == 0:
                await asyncio.sleep(0.001)

        self._log("INFO", f"Client #{slot.cid}: replayed {sent} events")

        # 阶段 3: 同步完成
        await self._send_encrypted(slot, PacketType.SYNC_COMPLETE, b'')

    async def _dispatch_game_packet(self, slot: ClientSlot,
                                    pkt_type: int, payload: bytes):
        """分发已解密的游戏事件包"""
        if pkt_type == PacketType.PLAYER_MOVE:
            await self._handle_player_move(slot, payload)
        elif pkt_type == PacketType.BLOCK_BREAK:
            await self._handle_block_break(slot, payload)
        elif pkt_type == PacketType.BLOCK_PLACE:
            await self._handle_block_place(slot, payload)
        elif pkt_type == PacketType.ENTITY_INTERACT:
            await self._handle_entity_interact(slot, payload)
        elif pkt_type == PacketType.INVENTORY_CHANGE:
            await self._handle_inventory_change(slot, payload)
        elif pkt_type == PacketType.CHEST_MODIFY:
            await self._handle_chest_modify(slot, payload)
        elif pkt_type == PacketType.PING:
            await self._handle_ping(slot, payload)

    async def _handle_player_move(self, slot: ClientSlot, payload: bytes):
        try:
            pkt = PlayerMovePayload.unpack(payload)
        except Exception:
            return
        result = self.validator.check_speed(slot.cid, pkt.x, pkt.y, pkt.z)
        if not result.ok:
            await self._handle_violation(slot, result)
            return
        slot.x, slot.y, slot.z = pkt.x, pkt.y, pkt.z

    async def _handle_block_break(self, slot: ClientSlot, payload: bytes):
        try:
            pkt = BlockBreakPayload.unpack(payload)
        except Exception:
            return
        result = self.validator.check_interaction_distance(
            slot.cid, float(pkt.x), float(pkt.y), float(pkt.z))
        if not result.ok:
            await self._handle_violation(slot, result)
            return
        result = self.validator.check_block_event(
            slot.cid, pkt.x, pkt.y, pkt.z, pkt.block_id, is_break=True)
        if not result.ok:
            await self._handle_violation(slot, result)
            return
        self.event_logger.log_event(slot.cid, PacketType.BLOCK_BREAK, payload)

    async def _handle_block_place(self, slot: ClientSlot, payload: bytes):
        try:
            pkt = BlockPlacePayload.unpack(payload)
        except Exception:
            return
        result = self.validator.check_interaction_distance(
            slot.cid, float(pkt.x), float(pkt.y), float(pkt.z))
        if not result.ok:
            await self._handle_violation(slot, result)
            return
        result = self.validator.check_block_event(
            slot.cid, pkt.x, pkt.y, pkt.z, pkt.block_id, is_break=False)
        if not result.ok:
            await self._handle_violation(slot, result)
            return
        self.event_logger.log_event(slot.cid, PacketType.BLOCK_PLACE, payload)

    async def _handle_entity_interact(self, slot: ClientSlot, payload: bytes):
        try:
            pkt = EntityInteractPayload.unpack(payload)
        except Exception:
            return
        self.event_logger.log_event(slot.cid, PacketType.ENTITY_INTERACT, payload)

    async def _handle_inventory_change(self, slot: ClientSlot, payload: bytes):
        try:
            pkt = InventoryChangePayload.unpack(payload)
        except Exception:
            return
        self.event_logger.log_event(slot.cid, PacketType.INVENTORY_CHANGE, payload)

    async def _handle_chest_modify(self, slot: ClientSlot, payload: bytes):
        try:
            pkt = ChestModifyPayload.unpack(payload)
        except Exception:
            return
        self.event_logger.log_event(slot.cid, PacketType.CHEST_MODIFY, payload)

    async def _handle_ping(self, slot: ClientSlot, payload: bytes):
        await self._send_encrypted(slot, PacketType.PONG, payload)

    async def _handle_violation(self, slot: ClientSlot, result):
        """根据违规等级执行惩罚"""
        if result.action == ViolationAction.ROLLBACK:
            await self._send_encrypted(slot, PacketType.ROLLBACK, b'')
            self._log("INFO", f"Client #{slot.cid}: ROLLBACK - {result.reason}")
        elif result.action == ViolationAction.FREEZE:
            await self._send_encrypted(slot, PacketType.FREEZE, b'')
            self._log("WARN", f"Client #{slot.cid}: FROZEN - {result.reason}")
            self.total_violations += 1
            slot.violations += 1
        elif result.action == ViolationAction.KICK:
            await self._send_encrypted(slot, PacketType.KICK,
                                       result.reason.encode('utf-8'))
            self._log("WARN", f"Client #{slot.cid}: KICK - {result.reason}")
            slot.in_use = False

    # ═══════════════════════════════════════════════════════════
    #  网络 I/O
    # ═══════════════════════════════════════════════════════════

    async def _send_raw(self, slot: ClientSlot, data: bytes):
        """发送原始字节"""
        if slot.writer is None:
            print(f"[DEBUG] _send_raw: writer is None for #{slot.cid}", file=sys.stderr, flush=True)
            return
        try:
            slot.writer.write(data)
            await slot.writer.drain()
            slot.bytes_out += len(data)
            self.total_bytes_out += len(data)
            print(f"[DEBUG] _send_raw: wrote {len(data)} bytes to #{slot.cid}", file=sys.stderr, flush=True)
            self._log("INFO", f"Client #{slot.cid}: sent {len(data)} bytes "
                       f"(first 16: {data[:16].hex()})")
        except Exception as e:
            print(f"[DEBUG] _send_raw EXCEPTION: {e}", file=sys.stderr, flush=True)
            self._log("ERROR", f"Send to #{slot.cid} failed: {e}")
            slot.in_use = False

    async def _send_encrypted(self, slot: ClientSlot, pkt_type: int, payload: bytes):
        """加密并发送一个数据包"""
        encrypted = CryptoEngine.encrypt_packet(slot.crypto, pkt_type, payload)
        if encrypted:
            await self._send_raw(slot, encrypted)

    async def _ping_loop(self):
        while self._running:
            await asyncio.sleep(PING_INTERVAL_SEC)
            now = time.time()
            for cid, slot in list(self._clients.items()):
                if slot.in_use and now - slot.last_seen > CLIENT_TIMEOUT_SEC:
                    self._log("WARN", f"Client #{cid} timed out")
                    self._disconnect_client(cid)

    def kick_client(self, cid: int, reason: str = "Kicked by admin"):
        slot = self._clients.get(cid)
        if slot and slot.in_use:
            # 发送 KICK 包
            if slot.crypto.key_ready:
                encrypted = CryptoEngine.encrypt_packet(
                    slot.crypto, PacketType.KICK, reason.encode('utf-8'))
                if encrypted and slot.writer:
                    try:
                        slot.writer.write(encrypted)
                    except Exception:
                        pass
            self._log("INFO", f"Kicked client #{cid}: {reason}")
            self._disconnect_client(cid)

    def get_online_clients(self) -> List[ClientSlot]:
        return [c for c in self._clients.values() if c.in_use]

    def get_stats(self) -> dict:
        return {
            "online": self.online_count,
            "max_clients": MAX_CLIENTS,
            "uptime": self.uptime,
            "total_connections": self.total_connections,
            "total_packets": self.total_packets,
            "total_bytes_in": self.total_bytes_in,
            "total_bytes_out": self.total_bytes_out,
            "total_violations": self.total_violations,
            "total_events": self.total_events_logged,
            "running": self._running,
        }


# ═══════════════════════════════════════════════════════════════
#  GUI 组件: 状态卡片
# ═══════════════════════════════════════════════════════════════

class StatCard(tk.Frame):
    """一个带图标的状态统计卡片"""

    def __init__(self, parent, title: str, icon: str, color: str, **kw):
        super().__init__(parent, bg=Theme.BG_CARD, **kw)

        self._color = color

        # 顶部: 图标 + 标题
        top = tk.Frame(self, bg=Theme.BG_CARD)
        top.pack(fill=tk.X, padx=12, pady=(10, 0))

        tk.Label(top, text=icon, font=("Segoe UI Emoji", 16),
                 bg=Theme.BG_CARD, fg=color).pack(side=tk.LEFT)
        tk.Label(top, text=title, font=Theme.FONT_SMALL,
                 bg=Theme.BG_CARD, fg=Theme.FG_DIM).pack(side=tk.LEFT, padx=(6, 0))

        # 数值
        self.value_label = tk.Label(self, text="--", font=Theme.FONT_STAT,
                                    bg=Theme.BG_CARD, fg=Theme.FG)
        self.value_label.pack(padx=12, pady=(2, 4))

        # 子标题
        self.sub_label = tk.Label(self, text="", font=Theme.FONT_SMALL,
                                  bg=Theme.BG_CARD, fg=Theme.FG_DIM)
        self.sub_label.pack(padx=12, pady=(0, 10))

        # 左侧色条
        bar = tk.Frame(self, bg=color, width=3)
        bar.place(x=0, y=8, height=40)

    def set_value(self, value: str, sub: str = ""):
        self.value_label.config(text=value)
        if sub:
            self.sub_label.config(text=sub)


# ═══════════════════════════════════════════════════════════════
#  GUI 组件: 快捷按钮
# ═══════════════════════════════════════════════════════════════

class QuickButton(tk.Frame):
    """带图标和描述的快捷操作按钮"""

    def __init__(self, parent, icon: str, label: str, color: str,
                 command=None, **kw):
        super().__init__(parent, bg=Theme.BG_CARD, cursor="hand2", **kw)

        self._color = color
        self._command = command

        inner = tk.Frame(self, bg=Theme.BG_CARD)
        inner.pack(expand=True, fill=tk.BOTH, padx=8, pady=6)

        tk.Label(inner, text=icon, font=("Segoe UI Emoji", 18),
                 bg=Theme.BG_CARD, fg=color).pack()
        tk.Label(inner, text=label, font=Theme.FONT_SMALL,
                 bg=Theme.BG_CARD, fg=Theme.FG).pack(pady=(2, 0))

        # 绑定点击
        for w in [self, inner] + list(inner.winfo_children()):
            w.bind("<Button-1>", self._on_click)
            w.bind("<Enter>", self._on_enter)
            w.bind("<Leave>", self._on_leave)

    def _on_click(self, e=None):
        if self._command:
            self._command()

    def _on_enter(self, e=None):
        self.config(bg=Theme.HOVER)
        for w in self.winfo_children():
            w.config(bg=Theme.HOVER)
            for c in w.winfo_children():
                c.config(bg=Theme.HOVER)

    def _on_leave(self, e=None):
        self.config(bg=Theme.BG_CARD)
        for w in self.winfo_children():
            w.config(bg=Theme.BG_CARD)
            for c in w.winfo_children():
                c.config(bg=Theme.BG_CARD)


# ═══════════════════════════════════════════════════════════════
#  主界面
# ═══════════════════════════════════════════════════════════════

class FluxDashboard:
    """Flux 服务端图形化控制台"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Flux Server — 控制台")
        self.root.geometry("1280x800")
        self.root.minsize(1000, 650)
        self.root.configure(bg=Theme.BG)

        # 设置图标 (如果有)
        try:
            self.root.iconbitmap(default="")
        except Exception:
            pass

        # 服务器核心
        self.server = FluxServerCore()
        self.server.on_log = self._on_server_log
        self.server.on_client_change = self._refresh_clients
        self.server.on_stats_update = self._schedule_stats_update

        # 服务端线程
        self._server_thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # 构建 UI
        self._build_ui()

        # 定时刷新
        self._refresh_stats()
        self._refresh_clients()

    # ─────────────────────────────────────────────────────
    #  UI 构建
    # ─────────────────────────────────────────────────────

    def _build_ui(self):
        # 主容器
        main = tk.Frame(self.root, bg=Theme.BG)
        main.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # ── 顶部: 标题栏 + 服务器控制 ──
        self._build_header(main)

        # ── 中间: 左侧(状态+控制) + 右侧(日志) ──
        body = tk.Frame(main, bg=Theme.BG)
        body.pack(fill=tk.BOTH, expand=True, pady=(8, 0))

        left = tk.Frame(body, bg=Theme.BG, width=580)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        left.pack_propagate(False)

        right = tk.Frame(body, bg=Theme.BG)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(8, 0))

        # 左侧内容
        self._build_stats_cards(left)
        self._build_quick_commands(left)
        self._build_client_table(left)

        # 右侧内容
        self._build_log_panel(right)

    def _build_header(self, parent):
        """顶部标题栏"""
        header = tk.Frame(parent, bg=Theme.BG_PANEL, height=60)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        # Logo + 标题
        left_h = tk.Frame(header, bg=Theme.BG_PANEL)
        left_h.pack(side=tk.LEFT, fill=tk.Y, padx=16)

        tk.Label(left_h, text="⬡", font=("Segoe UI Emoji", 24),
                 bg=Theme.BG_PANEL, fg=Theme.ACCENT).pack(side=tk.LEFT)
        tk.Label(left_h, text="Flux Server", font=Theme.FONT_TITLE,
                 bg=Theme.BG_PANEL, fg=Theme.FG).pack(side=tk.LEFT, padx=(8, 0))
        tk.Label(left_h, text="v2.0", font=Theme.FONT_SMALL,
                 bg=Theme.BG_PANEL, fg=Theme.FG_DIM).pack(side=tk.LEFT, padx=(6, 0), pady=(6, 0))

        # 右侧: 服务器控制按钮
        right_h = tk.Frame(header, bg=Theme.BG_PANEL)
        right_h.pack(side=tk.RIGHT, fill=tk.Y, padx=16)

        # 状态指示
        self.status_dot = tk.Label(right_h, text="● 离线", font=Theme.FONT_BODY,
                                   bg=Theme.BG_PANEL, fg=Theme.RED)
        self.status_dot.pack(side=tk.LEFT, padx=(0, 16))

        # 启动按钮
        self.btn_start = tk.Button(right_h, text="▶ 启动", font=Theme.FONT_BODY,
                                   bg=Theme.GREEN, fg="#000", relief=tk.FLAT,
                                   padx=16, pady=4, cursor="hand2",
                                   command=self._on_start)
        self.btn_start.pack(side=tk.LEFT, padx=4)

        # 停止按钮
        self.btn_stop = tk.Button(right_h, text="⏹ 停止", font=Theme.FONT_BODY,
                                  bg=Theme.RED, fg="#fff", relief=tk.FLAT,
                                  padx=16, pady=4, cursor="hand2",
                                  command=self._on_stop, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=4)

        # 重启按钮
        self.btn_restart = tk.Button(right_h, text="↻ 重启", font=Theme.FONT_BODY,
                                     bg=Theme.ORANGE, fg="#000", relief=tk.FLAT,
                                     padx=16, pady=4, cursor="hand2",
                                     command=self._on_restart, state=tk.DISABLED)
        self.btn_restart.pack(side=tk.LEFT, padx=4)

    def _build_stats_cards(self, parent):
        """状态统计卡片"""
        frame = tk.Frame(parent, bg=Theme.BG)
        frame.pack(fill=tk.X, pady=(8, 0))

        self.card_online = StatCard(frame, "在线玩家", "👥", Theme.CYAN)
        self.card_online.grid(row=0, column=0, padx=4, pady=4, sticky="nsew")

        self.card_uptime = StatCard(frame, "运行时间", "⏱", Theme.GREEN)
        self.card_uptime.grid(row=0, column=1, padx=4, pady=4, sticky="nsew")

        self.card_packets = StatCard(frame, "数据包", "📦", Theme.ACCENT_LIGHT)
        self.card_packets.grid(row=0, column=2, padx=4, pady=4, sticky="nsew")

        self.card_traffic = StatCard(frame, "网络流量", "📡", Theme.YELLOW)
        self.card_traffic.grid(row=0, column=3, padx=4, pady=4, sticky="nsew")

        for i in range(4):
            frame.columnconfigure(i, weight=1)

    def _build_quick_commands(self, parent):
        """快捷指令面板"""
        section = tk.Frame(parent, bg=Theme.BG)
        section.pack(fill=tk.X, pady=(8, 0))

        tk.Label(section, text="快捷指令", font=Theme.FONT_H2,
                 bg=Theme.BG, fg=Theme.FG).pack(anchor=tk.W, pady=(0, 6))

        grid = tk.Frame(section, bg=Theme.BG)
        grid.pack(fill=tk.X)

        buttons = [
            ("📢", "广播消息", Theme.CYAN, self._cmd_broadcast),
            ("🔄", "刷新区块", Theme.ACCENT_LIGHT, self._cmd_reload_chunks),
            ("🛡️", "清除违规", Theme.GREEN, self._cmd_clear_violations),
            ("📊", "导出日志", Theme.YELLOW, self._cmd_export_log),
            ("🧹", "清理数据", Theme.ORANGE, self._cmd_cleanup),
            ("⚙️", "服务器设置", Theme.FG_DIM, self._cmd_settings),
            ("👢", "踢出全部", Theme.RED, self._cmd_kick_all),
            ("📋", "复制状态", Theme.ACCENT_LIGHT, self._cmd_copy_status),
        ]

        for i, (icon, label, color, cmd) in enumerate(buttons):
            btn = QuickButton(grid, icon, label, color, command=cmd)
            btn.grid(row=i // 4, column=i % 4, padx=4, pady=4, sticky="nsew")

        for i in range(4):
            grid.columnconfigure(i, weight=1)

    def _build_client_table(self, parent):
        """在线玩家列表"""
        section = tk.Frame(parent, bg=Theme.BG)
        section.pack(fill=tk.BOTH, expand=True, pady=(8, 0))

        header = tk.Frame(section, bg=Theme.BG)
        header.pack(fill=tk.X, pady=(0, 4))

        tk.Label(header, text="在线玩家", font=Theme.FONT_H2,
                 bg=Theme.BG, fg=Theme.FG).pack(side=tk.LEFT)

        self.lbl_client_count = tk.Label(header, text="0 / 16",
                                         font=Theme.FONT_BODY,
                                         bg=Theme.BG, fg=Theme.FG_DIM)
        self.lbl_client_count.pack(side=tk.RIGHT)

        # Treeview
        cols = ("ID", "名称", "地址", "状态", "延迟", "违规", "操作")
        self.tree = ttk.Treeview(section, columns=cols, show="headings",
                                 height=6, selectmode="browse")

        for c in cols:
            self.tree.heading(c, text=c)
        self.tree.column("ID", width=40, stretch=False)
        self.tree.column("名称", width=100)
        self.tree.column("地址", width=130)
        self.tree.column("状态", width=80, stretch=False)
        self.tree.column("延迟", width=60, stretch=False)
        self.tree.column("违规", width=50, stretch=False)
        self.tree.column("操作", width=80, stretch=False)

        style = ttk.Style()
        style.configure("Flux.Treeview", background=Theme.BG_CARD,
                        foreground=Theme.FG, fieldbackground=Theme.BG_CARD,
                        font=Theme.FONT_MONO, rowheight=26)
        style.configure("Flux.Treeview.Heading", background=Theme.BORDER,
                        foreground=Theme.ACCENT_LIGHT, font=Theme.FONT_BODY)
        style.map("Flux.Treeview",
                  background=[("selected", Theme.ACCENT)],
                  foreground=[("selected", "#fff")])
        self.tree.configure(style="Flux.Treeview")

        scrollbar = ttk.Scrollbar(section, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 右键菜单
        self.tree.bind("<Button-3>", self._on_client_right_click)

    def _build_log_panel(self, parent):
        """日志面板"""
        section = tk.Frame(parent, bg=Theme.BG)
        section.pack(fill=tk.BOTH, expand=True)

        header = tk.Frame(section, bg=Theme.BG)
        header.pack(fill=tk.X, pady=(0, 4))

        tk.Label(header, text="服务器日志", font=Theme.FONT_H2,
                 bg=Theme.BG, fg=Theme.FG).pack(side=tk.LEFT)

        # 日志级别筛选
        self.log_filter = ttk.Combobox(header, width=10, state="readonly",
                                       font=Theme.FONT_SMALL)
        self.log_filter["values"] = ["全部", "INFO", "WARN", "ERROR"]
        self.log_filter.set("全部")
        self.log_filter.pack(side=tk.RIGHT, padx=4)
        self.log_filter.bind("<<ComboboxSelected>>", lambda e: self._apply_log_filter())

        tk.Label(header, text="级别:", font=Theme.FONT_SMALL,
                 bg=Theme.BG, fg=Theme.FG_DIM).pack(side=tk.RIGHT)

        # 清除按钮
        tk.Button(header, text="清除", font=Theme.FONT_SMALL,
                  bg=Theme.BORDER, fg=Theme.FG, relief=tk.FLAT,
                  padx=8, command=self._clear_log).pack(side=tk.RIGHT, padx=4)

        # 日志文本区
        self.log_text = scrolledtext.ScrolledText(
            section, bg=Theme.BG_PANEL, fg=Theme.FG,
            font=Theme.FONT_MONO, relief=tk.FLAT,
            insertbackground=Theme.FG, wrap=tk.WORD,
            state=tk.DISABLED, height=20
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # 日志颜色标签
        self.log_text.tag_configure("INFO", foreground=Theme.FG)
        self.log_text.tag_configure("WARN", foreground=Theme.YELLOW)
        self.log_text.tag_configure("ERROR", foreground=Theme.RED)
        self.log_text.tag_configure("CMD", foreground=Theme.CYAN)
        self.log_text.tag_configure("TIMESTAMP", foreground=Theme.FG_DIM)

        # 底部命令输入
        cmd_frame = tk.Frame(section, bg=Theme.BG_PANEL)
        cmd_frame.pack(fill=tk.X, pady=(4, 0))

        tk.Label(cmd_frame, text="❯", font=Theme.FONT_MONO,
                 bg=Theme.BG_PANEL, fg=Theme.ACCENT).pack(side=tk.LEFT, padx=(8, 4))

        self.cmd_entry = tk.Entry(cmd_frame, bg=Theme.BG_INPUT, fg=Theme.FG,
                                  font=Theme.FONT_MONO, relief=tk.FLAT,
                                  insertbackground=Theme.FG)
        self.cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=6)
        self.cmd_entry.bind("<Return>", self._on_command_enter)

        tk.Button(cmd_frame, text="执行", font=Theme.FONT_BODY,
                  bg=Theme.ACCENT, fg="#fff", relief=tk.FLAT,
                  padx=12, command=self._on_command_enter).pack(side=tk.RIGHT, padx=4, pady=4)

    # ─────────────────────────────────────────────────────
    #  服务器控制
    # ─────────────────────────────────────────────────────

    def _on_start(self):
        if self.server._running:
            return
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.btn_restart.config(state=tk.NORMAL)
        self.status_dot.config(text="● 启动中...", fg=Theme.YELLOW)

        self._loop = asyncio.new_event_loop()
        self._server_thread = threading.Thread(target=self._run_server_loop, daemon=True)
        self._server_thread.start()

    def _on_stop(self):
        if not self.server._running:
            return
        self.btn_stop.config(state=tk.DISABLED)
        self.status_dot.config(text="● 停止中...", fg=Theme.YELLOW)

        if self._loop:
            asyncio.run_coroutine_threadsafe(self.server.shutdown(), self._loop)

        self.root.after(1000, self._check_stopped)

    def _on_restart(self):
        self._on_stop()
        self.root.after(2000, self._on_start)

    def _run_server_loop(self):
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self.server.start())
        except Exception as e:
            self._on_server_log(f"[FATAL] Server loop error: {e}", "ERROR")
        finally:
            self.root.after(0, lambda: self.status_dot.config(text="● 离线", fg=Theme.RED))
            self.root.after(0, lambda: self.btn_start.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.btn_stop.config(state=tk.DISABLED))
            self.root.after(0, lambda: self.btn_restart.config(state=tk.DISABLED))

    def _check_stopped(self):
        if not self.server._running:
            self.status_dot.config(text="● 离线", fg=Theme.RED)
            self.btn_start.config(state=tk.NORMAL)
            self.btn_stop.config(state=tk.DISABLED)
            self.btn_restart.config(state=tk.DISABLED)
        else:
            self.root.after(500, self._check_stopped)

    # ─────────────────────────────────────────────────────
    #  日志处理
    # ─────────────────────────────────────────────────────

    def _on_server_log(self, msg: str, level: str = "INFO"):
        """线程安全的日志推送"""
        self.root.after(0, self._append_log, msg, level)

    def _append_log(self, msg: str, level: str):
        self.log_text.config(state=tk.NORMAL)

        # 解析时间戳
        if msg.startswith("[") and "]" in msg:
            ts_end = msg.index("]") + 1
            ts_part = msg[:ts_end]
            rest = msg[ts_end:]
            self.log_text.insert(tk.END, ts_part, "TIMESTAMP")
            self.log_text.insert(tk.END, rest + "\n", level)
        else:
            self.log_text.insert(tk.END, msg + "\n", level)

        self.log_text.config(state=tk.DISABLED)
        self.log_text.see(tk.END)

    def _apply_log_filter(self):
        # 简单实现：重新显示时过滤
        pass

    def _clear_log(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state=tk.DISABLED)

    # ─────────────────────────────────────────────────────
    #  统计刷新
    # ─────────────────────────────────────────────────────

    def _schedule_stats_update(self):
        self.root.after(0, self._refresh_stats)

    def _refresh_stats(self):
        stats = self.server.get_stats()

        self.card_online.set_value(
            str(stats["online"]),
            f"上限 {stats['max_clients']}"
        )
        self.card_uptime.set_value(
            self._format_uptime(stats["uptime"]),
            "运行中" if stats["running"] else "已停止"
        )
        self.card_packets.set_value(
            self._format_number(stats["total_packets"]),
            f"连接总数 {stats['total_connections']}"
        )
        self.card_traffic.set_value(
            self._format_bytes(stats["total_bytes_in"] + stats["total_bytes_out"]),
            f"↑{self._format_bytes(stats['total_bytes_out'])} ↓{self._format_bytes(stats['total_bytes_in'])}"
        )

        # 状态栏
        if stats["running"]:
            self.status_dot.config(text="● 在线", fg=Theme.GREEN)
        else:
            self.status_dot.config(text="● 离线", fg=Theme.RED)

        # 每 2 秒刷新
        self.root.after(2000, self._refresh_stats)

    def _refresh_clients(self):
        """刷新在线玩家列表"""
        self.tree.delete(*self.tree.get_children())

        clients = self.server.get_online_clients()
        self.lbl_client_count.config(
            text=f"{len(clients)} / {MAX_CLIENTS}"
        )

        for c in clients:
            now = time.time()
            latency = f"{(now - c.last_seen) * 1000:.0f}ms"
            state_color = "ACTIVE" if c.state == "ACTIVE" else c.state

            self.tree.insert("", tk.END, values=(
                c.cid,
                c.name or "(未认证)",
                c.address,
                state_color,
                latency,
                c.violations,
                "踢出"
            ))

    # ─────────────────────────────────────────────────────
    #  快捷指令
    # ─────────────────────────────────────────────────────

    def _cmd_broadcast(self):
        """广播消息"""
        dialog = tk.Toplevel(self.root)
        dialog.title("广播消息")
        dialog.geometry("400x150")
        dialog.configure(bg=Theme.BG_PANEL)
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(dialog, text="输入要广播的消息:", font=Theme.FONT_BODY,
                 bg=Theme.BG_PANEL, fg=Theme.FG).pack(padx=16, pady=(16, 4))

        entry = tk.Entry(dialog, bg=Theme.BG_INPUT, fg=Theme.FG,
                         font=Theme.FONT_MONO, relief=tk.FLAT, width=40)
        entry.pack(padx=16, ipady=4)
        entry.focus_set()

        def send():
            msg = entry.get().strip()
            if msg:
                self._on_server_log(f"[BROADCAST] {msg}", "CMD")
                dialog.destroy()

        tk.Button(dialog, text="发送", bg=Theme.ACCENT, fg="#fff",
                  relief=tk.FLAT, padx=20, command=send).pack(pady=12)
        entry.bind("<Return>", lambda e: send())

    def _cmd_reload_chunks(self):
        self._on_server_log("[CMD] Reloading all chunks...", "CMD")

    def _cmd_clear_violations(self):
        self.server.total_violations = 0
        for c in self.server._clients.values():
            c.violations = 0
        self._on_server_log("[CMD] All violations cleared.", "CMD")

    def _cmd_export_log(self):
        self._on_server_log("[CMD] Exporting event log...", "CMD")

    def _cmd_cleanup(self):
        self._on_server_log("[CMD] Running data cleanup...", "CMD")

    def _cmd_settings(self):
        """打开设置对话框"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Flux 服务器设置")
        dialog.geometry("500x400")
        dialog.configure(bg=Theme.BG_PANEL)
        dialog.transient(self.root)

        tk.Label(dialog, text="服务器配置", font=Theme.FONT_H2,
                 bg=Theme.BG_PANEL, fg=Theme.ACCENT).pack(padx=16, pady=(16, 8))

        settings = [
            ("监听端口", str(SERVER_PORT)),
            ("最大玩家数", str(MAX_CLIENTS)),
            ("客户端超时 (秒)", str(CLIENT_TIMEOUT_SEC)),
            ("心跳间隔 (秒)", str(PING_INTERVAL_SEC)),
            ("协议魔数", f"0x{PROTOCOL_MAGIC:04X}"),
            ("数据目录", LOG_DIR),
        ]

        frame = tk.Frame(dialog, bg=Theme.BG_PANEL)
        frame.pack(fill=tk.BOTH, expand=True, padx=16)

        entries = {}
        for i, (label, value) in enumerate(settings):
            tk.Label(frame, text=label, font=Theme.FONT_BODY,
                     bg=Theme.BG_PANEL, fg=Theme.FG).grid(
                row=i, column=0, sticky=tk.W, pady=4)
            e = tk.Entry(frame, bg=Theme.BG_INPUT, fg=Theme.FG,
                         font=Theme.FONT_MONO, relief=tk.FLAT, width=30)
            e.insert(0, value)
            e.grid(row=i, column=1, padx=(12, 0), pady=4, ipady=2)
            entries[label] = e

        tk.Label(dialog, text="⚠ 修改将在重启后生效",
                 font=Theme.FONT_SMALL, bg=Theme.BG_PANEL,
                 fg=Theme.YELLOW).pack(pady=(8, 16))

    def _cmd_kick_all(self):
        if messagebox.askyesno("确认", "确定要踢出所有在线玩家吗？"):
            for c in self.server.get_online_clients():
                self.server.kick_client(c.cid, "Admin: kick all")
            self._on_server_log("[CMD] Kicked all clients.", "CMD")

    def _cmd_copy_status(self):
        stats = self.server.get_stats()
        status = (
            f"=== Flux Server Status ===\n"
            f"Online: {stats['online']}/{stats['max_clients']}\n"
            f"Uptime: {self._format_uptime(stats['uptime'])}\n"
            f"Packets: {stats['total_packets']}\n"
            f"Traffic: {self._format_bytes(stats['total_bytes_in'] + stats['total_bytes_out'])}\n"
            f"Violations: {stats['total_violations']}\n"
        )
        self.root.clipboard_clear()
        self.root.clipboard_append(status)
        self._on_server_log("[CMD] Server status copied to clipboard.", "CMD")

    def _on_command_enter(self, event=None):
        """处理命令输入"""
        cmd = self.cmd_entry.get().strip()
        if not cmd:
            return

        self.cmd_entry.delete(0, tk.END)
        self._on_server_log(f"> {cmd}", "CMD")

        # 解析命令
        parts = cmd.split()
        action = parts[0].lower() if parts else ""

        if action == "help":
            help_text = (
                "可用命令:\n"
                "  help          - 显示帮助\n"
                "  status        - 显示服务器状态\n"
                "  list          - 列出在线玩家\n"
                "  kick <id>     - 踢出玩家\n"
                "  broadcast <msg> - 广播消息\n"
                "  clear         - 清除日志\n"
                "  start         - 启动服务器\n"
                "  stop          - 停止服务器\n"
                "  config        - 显示配置\n"
            )
            self._on_server_log(help_text, "INFO")

        elif action == "status":
            stats = self.server.get_stats()
            self._on_server_log(
                f"Status: {'RUNNING' if stats['running'] else 'STOPPED'} | "
                f"Online: {stats['online']}/{stats['max_clients']} | "
                f"Uptime: {self._format_uptime(stats['uptime'])} | "
                f"Packets: {stats['total_packets']}", "INFO"
            )

        elif action == "list":
            clients = self.server.get_online_clients()
            if clients:
                self._on_server_log(f"Online players ({len(clients)}):", "INFO")
                for c in clients:
                    self._on_server_log(
                        f"  #{c.cid} {c.name or '(unnamed)'} @ {c.address} "
                        f"[{c.state}] violations={c.violations}", "INFO"
                    )
            else:
                self._on_server_log("No players online.", "INFO")

        elif action == "kick" and len(parts) > 1:
            try:
                cid = int(parts[1])
                reason = " ".join(parts[2:]) if len(parts) > 2 else "Kicked by admin"
                self.server.kick_client(cid, reason)
            except ValueError:
                self._on_server_log("Usage: kick <client_id> [reason]", "ERROR")

        elif action == "broadcast" and len(parts) > 1:
            msg = " ".join(parts[1:])
            self._on_server_log(f"[BROADCAST] {msg}", "CMD")

        elif action == "clear":
            self._clear_log()

        elif action == "start":
            self._on_start()

        elif action == "stop":
            self._on_stop()

        elif action == "config":
            self._on_server_log(
                f"Port={SERVER_PORT} MaxClients={MAX_CLIENTS} "
                f"Timeout={CLIENT_TIMEOUT_SEC}s Magic=0x{PROTOCOL_MAGIC:04X}", "INFO"
            )

        else:
            self._on_server_log(f"Unknown command: {action}. Type 'help' for help.", "WARN")

    def _on_client_right_click(self, event):
        """玩家右键菜单"""
        item = self.tree.identify_row(event.y)
        if not item:
            return

        self.tree.selection_set(item)
        values = self.tree.item(item, "values")
        cid = values[0]

        menu = tk.Menu(self.root, tearoff=0, bg=Theme.BG_CARD, fg=Theme.FG,
                       font=Theme.FONT_BODY, relief=tk.FLAT)
        menu.add_command(label=f"👢 踢出 #{cid}",
                         command=lambda: self.server.kick_client(int(cid), "Kicked by admin"))
        menu.add_command(label=f"🚫 冻结 #{cid}",
                         command=lambda: self._on_server_log(f"[CMD] Froze client #{cid}", "CMD"))
        menu.add_command(label=f"📋 复制信息",
                         command=lambda: (self.root.clipboard_clear(),
                                          self.root.clipboard_append(str(values))))
        menu.tk_popup(event.x_root, event.y_root)

    # ─────────────────────────────────────────────────────
    #  工具方法
    # ─────────────────────────────────────────────────────

    @staticmethod
    def _format_uptime(seconds: float) -> str:
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            return f"{seconds / 60:.0f}m {seconds % 60:.0f}s"
        else:
            h = int(seconds // 3600)
            m = int((seconds % 3600) // 60)
            return f"{h}h {m}m"

    @staticmethod
    def _format_bytes(b: int) -> str:
        if b < 1024:
            return f"{b} B"
        elif b < 1024 * 1024:
            return f"{b / 1024:.1f} KB"
        elif b < 1024 * 1024 * 1024:
            return f"{b / 1024 / 1024:.1f} MB"
        else:
            return f"{b / 1024 / 1024 / 1024:.2f} GB"

    @staticmethod
    def _format_number(n: int) -> str:
        if n < 1000:
            return str(n)
        elif n < 1_000_000:
            return f"{n / 1000:.1f}K"
        else:
            return f"{n / 1_000_000:.1f}M"

    # ─────────────────────────────────────────────────────
    #  运行
    # ─────────────────────────────────────────────────────

    def run(self):
        # 关闭时清理
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_close(self):
        if self.server._running:
            if messagebox.askyesno("退出", "服务器正在运行，确定要退出吗？"):
                if self._loop:
                    asyncio.run_coroutine_threadsafe(self.server.shutdown(), self._loop)
                self.root.after(1000, self.root.destroy)
            return
        self.root.destroy()


# ═══════════════════════════════════════════════════════════════
#  入口
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = FluxDashboard()
    app.run()
