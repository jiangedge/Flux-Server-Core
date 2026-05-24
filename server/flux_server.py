#!/usr/bin/env python3
"""
Flux Server

  python flux_server.py              # 启动图形化控制台（默认）
  python flux_server.py --cli        # 命令行模式
"""

import asyncio
import hashlib
import logging
import math
import os
import signal
import struct
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from pathlib import Path
from typing import Callable, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# ═══════════════════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════════════════

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 25580
MAX_CLIENTS = 16
CLIENT_TIMEOUT_SEC = 600

PROTOCOL_MAGIC = 0x4658
PROTOCOL_HEADER_SIZE = 7
PROTOCOL_IV_SIZE = 12
PROTOCOL_GCM_TAG_SIZE = 16
PROTOCOL_SEQID_SIZE = 4
MAX_PAYLOAD_SIZE = 512

AES_KEY_SIZE = 16

MAX_SPEED_BLOCKS_PER_SEC = 10.0
MAX_INTERACTION_DISTANCE = 6.0
MAX_ATTACK_DISTANCE = 4.5
VIOLATION_FREEZE_COUNT = 3
VIOLATION_KICK_COUNT = 5

TTL_VOLATILE_MS = 3000

LOG_DIR = "./flux_data"
EVENT_LOG_DIR = "./flux_data/events"
WORLD_SEED_FILE = "./flux_data/seed.bin"
MAX_LOG_FILE_SIZE = 4 * 1024 * 1024

SYNC_BATCH_SIZE = 10
SYNC_BATCH_DELAY_MS = 1
PING_INTERVAL_SEC = 5

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(name)s %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("flux.server")

# ═══════════════════════════════════════════════════════════════════
#  PROTOCOL
# ═══════════════════════════════════════════════════════════════════


class PacketType(IntEnum):
    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02
    AUTH_REQUEST = 0x03
    AUTH_SUCCESS = 0x04
    AUTH_FAIL = 0x05
    SEED_SYNC = 0x10
    CHUNK_LOG_ENTRY = 0x11
    ENTITY_SNAPSHOT = 0x12
    SYNC_COMPLETE = 0x13
    PLAYER_MOVE = 0x20
    BLOCK_BREAK = 0x21
    BLOCK_PLACE = 0x22
    ENTITY_INTERACT = 0x23
    INVENTORY_CHANGE = 0x24
    CHEST_OPEN = 0x25
    CHEST_MODIFY = 0x26
    CHUNK_TRANSFER = 0x27
    CHAT_MESSAGE = 0x28
    BROADCAST_MOVE = 0x30
    BROADCAST_BLOCK = 0x31
    BROADCAST_ENTITY = 0x32
    BROADCAST_INVENTORY = 0x33
    BROADCAST_CHAT = 0x34
    BROADCAST_PLAYER_JOIN = 0x35
    BROADCAST_PLAYER_LEAVE = 0x36
    ROLLBACK = 0x40
    FREEZE = 0x41
    KICK = 0x42
    PING = 0x50
    PONG = 0x51


@dataclass
class PlayerMovePayload:
    x: float = 0.0; y: float = 0.0; z: float = 0.0; yaw: float = 0.0; pitch: float = 0.0
    FORMAT = "<fffff"; SIZE = 20
    @classmethod
    def unpack(cls, data): return cls(*struct.unpack(cls.FORMAT, data[:cls.SIZE]))

@dataclass
class BlockBreakPayload:
    x: int = 0; y: int = 0; z: int = 0; block_id: int = 0
    FORMAT = "<iiii"; SIZE = 16
    @classmethod
    def unpack(cls, data): return cls(*struct.unpack(cls.FORMAT, data[:cls.SIZE]))

@dataclass
class BlockPlacePayload:
    x: int = 0; y: int = 0; z: int = 0; block_id: int = 0
    FORMAT = "<iiii"; SIZE = 16
    @classmethod
    def unpack(cls, data): return cls(*struct.unpack(cls.FORMAT, data[:cls.SIZE]))

@dataclass
class EntityInteractPayload:
    entity_id: int = 0; damage: float = 0.0
    FORMAT = "<If"; SIZE = 8
    @classmethod
    def unpack(cls, data): return cls(*struct.unpack(cls.FORMAT, data[:cls.SIZE]))

@dataclass
class InventoryChangePayload:
    slot_index: int = 0; item_id: int = 0; count: int = 0
    FORMAT = "<HiB"; SIZE = 7
    @classmethod
    def unpack(cls, data): return cls(*struct.unpack(cls.FORMAT, data[:cls.SIZE]))

@dataclass
class ChestModifyPayload:
    x: int = 0; y: int = 0; z: int = 0; slot_index: int = 0; item_id: int = 0; count: int = 0
    FORMAT = "<iiiBHB"; SIZE = 16
    @classmethod
    def unpack(cls, data): return cls(*struct.unpack(cls.FORMAT, data[:cls.SIZE]))

@dataclass
class ChunkTransferPayload:
    entity_id: int = 0; x: float = 0.0; y: float = 0.0; z: float = 0.0
    vel_x: float = 0.0; vel_y: float = 0.0; vel_z: float = 0.0; entity_type: int = 0; health: float = 0.0
    FORMAT = "<IffffffBf"; SIZE = 33
    @classmethod
    def unpack(cls, data): return cls(*struct.unpack(cls.FORMAT, data[:cls.SIZE]))

@dataclass
class AuthRequestPayload:
    uuid: bytes = b'\x00' * 16; username: str = ""
    @classmethod
    def unpack(cls, data):
        return cls(uuid=data[:16], username=data[16:].decode('utf-8', errors='replace'))

@dataclass
class PacketHeader:
    magic: int = PROTOCOL_MAGIC; pkt_type: int = 0; length: int = 0
    FORMAT = ">HBI"; SIZE = PROTOCOL_HEADER_SIZE
    def pack(self): return struct.pack(self.FORMAT, self.magic, self.pkt_type, self.length)
    @classmethod
    def unpack(cls, data):
        if len(data) < cls.SIZE: return None
        m, t, l = struct.unpack(cls.FORMAT, data[:cls.SIZE])
        if m != PROTOCOL_MAGIC: return None
        return cls(magic=m, pkt_type=t, length=l)

class PacketReader:
    def __init__(self): self._buf = bytearray()
    def feed(self, data): self._buf.extend(data)
    def read_packet(self):
        if len(self._buf) < PacketHeader.SIZE: return None
        h = PacketHeader.unpack(bytes(self._buf[:PacketHeader.SIZE]))
        if h is None: self._buf.pop(0); return self.read_packet()
        total = PacketHeader.SIZE + PROTOCOL_IV_SIZE + h.length
        if len(self._buf) < total: return None
        raw = bytes(self._buf[:total])
        iv = raw[PacketHeader.SIZE:PacketHeader.SIZE + PROTOCOL_IV_SIZE]
        payload = raw[PacketHeader.SIZE + PROTOCOL_IV_SIZE:]
        self._buf = self._buf[total:]
        return h, iv, payload, raw

# ═══════════════════════════════════════════════════════════════════
#  CRYPTO
# ═══════════════════════════════════════════════════════════════════

@dataclass
class CryptoSession:
    x25519_private_key: Optional[X25519PrivateKey] = None
    p256_private_key: Optional[ec.EllipticCurvePrivateKey] = None
    peer_public_bytes: bytes = b''
    session_key: bytes = b''
    tx_seq: int = -1; rx_seq: int = -1; key_ready: bool = False
    def reset(self):
        self.x25519_private_key = None; self.p256_private_key = None
        self.peer_public_bytes = b''; self.session_key = b''
        self.tx_seq = -1; self.rx_seq = -1; self.key_ready = False

class CryptoEngine:
    def __init__(self):
        self._s_x25519_priv = None; self._s_x25519_pub = b''
        self._s_p256_priv = None; self._s_p256_der = b''

    def generate_keypair(self):
        self._s_x25519_priv = X25519PrivateKey.generate()
        self._s_x25519_pub = self._s_x25519_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        self._s_p256_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
        p256_pub = self._s_p256_priv.public_key()
        self._s_p256_der = p256_pub.public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    def derive_session_key(self, session, peer_pub):
        """自动检测密钥类型并派生会话密钥（4层降级）"""
        try:
            key_type, raw = self._detect_key(peer_pub)
            if key_type == "x25519":
                return self._derive_x25519(session, raw)
            elif key_type == "p256":
                return self._derive_p256(session, raw)
            logger.error(f"Unsupported key format: {len(peer_pub)} bytes")
            return False
        except Exception as e:
            logger.error(f"Key derivation failed: {e}")
            return False

    def _detect_key(self, data):
        """4 层降级检测：X25519 → Flux P-256 → DER → 0x04 扫描"""
        dl = len(data)

        # 1. X25519: 原始 32 字节
        if dl == 32:
            return "x25519", data

        # 2. Flux 自定义 P-256 格式: 91 字节
        if dl == 91:
            pt = self._extract_flux_point(data)
            if pt is not None:
                return "p256", pt
            # 91 字节但 OID 不匹配，继续降级

        # 3. P-256 未压缩点: 0x04 + X(32) + Y(32) = 65 字节
        if dl == 65 and data[0] == 0x04:
            return "p256", data

        # 4. 标准 DER SubjectPublicKeyInfo
        if dl >= 65:
            try:
                pk = serialization.load_der_public_key(data, backend=default_backend())
                if isinstance(pk, ec.EllipticCurvePublicKey):
                    raw = pk.public_bytes(
                        encoding=serialization.Encoding.X962,
                        format=serialization.PublicFormat.UncompressedPoint)
                    return "p256", raw
            except: pass

        # 5. 扫描 0x04 前缀
        if dl >= 65:
            for i in range(min(20, dl - 64)):
                if data[i] == 0x04 and i + 65 <= dl:
                    return "p256", data[i:i+65]

        return "unknown", data

    def _derive_x25519(self, session, raw):
        peer = X25519PublicKey.from_public_bytes(raw)
        ss = self._s_x25519_priv.exchange(peer)
        session.session_key = hashlib.sha256(ss).digest()[:AES_KEY_SIZE]
        session.key_ready = True
        return True

    def _derive_p256(self, session, raw):
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
        ss = self._s_p256_priv.exchange(ec.ECDH(), peer)
        session.session_key = hashlib.sha256(ss).digest()[:AES_KEY_SIZE]
        session.key_ready = True
        return True

    @staticmethod
    def _extract_flux_point(data):
        if len(data) < 91: return None
        oid = bytes([0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07])
        if data[1:11] != oid: return None
        return b'\x04' + data[15:79]

    @staticmethod
    def encrypt_packet(session, pkt_type, payload):
        if not session.key_ready: return None
        session.tx_seq += 1
        cleartext = struct.pack(">I", session.tx_seq) + payload
        iv = os.urandom(PROTOCOL_IV_SIZE)
        ct = AESGCM(session.session_key).encrypt(iv, cleartext, None)
        h = PacketHeader(magic=PROTOCOL_MAGIC, pkt_type=pkt_type, length=len(ct))
        return h.pack() + iv + ct

    @staticmethod
    def decrypt_packet(session, header, iv, ct):
        if not session.key_ready: return None
        try:
            pt = AESGCM(session.session_key).decrypt(iv, ct, None)
            seq = struct.unpack(">I", pt[:4])[0]
            if seq <= session.rx_seq: return None
            session.rx_seq = seq
            return pt[4:]
        except: return None

# ═══════════════════════════════════════════════════════════════════
#  EVENT LOGGER
# ═══════════════════════════════════════════════════════════════════

@dataclass
class EventEntry:
    timestamp_ms: int = 0; client_id: int = 0; event_type: int = 0
    data: bytes = b''; hash: bytes = b'\x00'*32
    FMT = "<IBBH"; SZ = 8
    def pack(self, prev=b'\x00'*32):
        self.timestamp_ms = int(time.time()*1000) & 0xFFFFFFFF
        hdr = struct.pack(self.FMT, self.timestamp_ms, self.client_id, self.event_type, len(self.data))
        h = hashlib.sha256(prev + hdr + self.data).digest()
        self.hash = h
        return hdr + self.data + h
    @classmethod
    def unpack(cls, d):
        if len(d) < cls.SZ+32: return None
        t,c,e,dl = struct.unpack(cls.FMT, d[:cls.SZ])
        return cls(timestamp_ms=t, client_id=c, event_type=e, data=d[cls.SZ:cls.SZ+dl],
                   hash=d[cls.SZ+dl:cls.SZ+dl+32])
    @property
    def packed_size(self): return self.SZ + len(self.data) + 32

class EventLogger:
    def __init__(self):
        self._events=[]; self._last_hash=b'\x00'*32
        self._file_idx=0; self._file_sz=0; self._seed=0
    def init(self):
        Path(EVENT_LOG_DIR).mkdir(parents=True, exist_ok=True)
        self._load_seed(); self._load_events(); return True
    def _load_seed(self):
        if os.path.exists(WORLD_SEED_FILE):
            with open(WORLD_SEED_FILE,'rb') as f:
                d=f.read(8)
                if len(d)==8: self._seed=struct.unpack("<q",d)[0]; return
        self._seed=int.from_bytes(os.urandom(8),'little',signed=True)
        with open(WORLD_SEED_FILE,'wb') as f: f.write(struct.pack("<q",self._seed))
    def _load_events(self):
        self._events.clear(); self._last_hash=b'\x00'*32; idx=0
        while True:
            p=os.path.join(EVENT_LOG_DIR,f"events_{idx:04d}.bin")
            if not os.path.exists(p): break
            self._load_file(p); idx+=1
        self._file_idx=idx; self._file_sz=self._events[-1].packed_size if self._events else 0
    def _load_file(self, p):
        try:
            with open(p,'rb') as f: data=f.read()
            off=0
            while off+EventEntry.SZ+32<=len(data):
                _,_,_,dl=struct.unpack(EventEntry.FMT,data[off:off+EventEntry.SZ])
                esz=EventEntry.SZ+dl+32
                if off+esz>len(data): break
                e=EventEntry.unpack(data[off:off+esz])
                if e: self._events.append(e); self._last_hash=e.hash
                off+=esz
        except: pass
    def log_event(self, cid, etype, data):
        e=EventEntry(client_id=cid, event_type=etype, data=data)
        packed=e.pack(self._last_hash); self._events.append(e); self._last_hash=e.hash
        fp=os.path.join(EVENT_LOG_DIR,f"events_{self._file_idx:04d}.bin")
        if self._file_sz+len(packed)>MAX_LOG_FILE_SIZE:
            self._file_idx+=1; self._file_sz=0
            fp=os.path.join(EVENT_LOG_DIR,f"events_{self._file_idx:04d}.bin")
        with open(fp,'ab') as f: f.write(packed)
        self._file_sz+=len(packed)
    def get_world_seed(self): return self._seed
    def get_events_since(self, i=0): return self._events[i:]
    def get_event_count(self): return len(self._events)

# ═══════════════════════════════════════════════════════════════════
#  PACKET VALIDATOR
# ═══════════════════════════════════════════════════════════════════

class ViolationAction:
    NONE=0; ROLLBACK=1; FREEZE=2; KICK=3

@dataclass
class PlayerState:
    x:float=0;y:float=0;z:float=0;last_t:float=0
    con_v:int=0;tot_v:int=0

@dataclass
class ValidationResult:
    ok:bool=True; action:int=0; reason:str=""

class PacketValidator:
    def __init__(self):
        self._players:Dict[int,PlayerState]={}
        self._blocks:Dict[tuple,int]={}
        self._containers:Dict[tuple,Dict]={}
    def get_ps(self, cid):
        if cid not in self._players: self._players[cid]=PlayerState()
        return self._players[cid]
    def reset_player(self, cid): self._players.pop(cid,None)
    def check_speed(self, cid, x, y, z):
        ps=self.get_ps(cid); now=time.monotonic()
        if ps.last_t==0: ps.x,ps.y,ps.z=x,y,z; ps.last_t=now; return ValidationResult()
        dt=now-ps.last_t
        if dt<0.001: return ValidationResult()
        d=math.sqrt((x-ps.x)**2+(y-ps.y)**2+(z-ps.z)**2)
        spd=d/dt
        if spd>MAX_SPEED_BLOCKS_PER_SEC:
            ps.con_v+=1;ps.tot_v+=1
            return ValidationResult(ok=False,action=self._da(ps),reason=f"Speed {spd:.1f}")
        ps.con_v=0;ps.x,ps.y,ps.z=x,y,z;ps.last_t=now; return ValidationResult()
    def check_dist(self, cid, tx, ty, tz, atk=False):
        ps=self.get_ps(cid)
        if ps.last_t==0: return ValidationResult()
        d=math.sqrt((tx-ps.x)**2+(ty-ps.y)**2+(tz-ps.z)**2)
        mx=MAX_ATTACK_DISTANCE if atk else MAX_INTERACTION_DISTANCE
        if d>mx: ps.con_v+=1;ps.tot_v+=1
        return ValidationResult(ok=d<=mx, action=self._da(ps), reason=f"Dist {d:.1f}")
    def check_inv(self, cid, cpos, slot, iid, cnt, act):
        ps=self.get_ps(cid)
        if cpos:
            if cpos not in self._containers: self._containers[cpos]={}
            sl=self._containers[cpos]
            if act==0:
                if slot not in sl: ps.con_v+=1;ps.tot_v+=1
                return ValidationResult(ok=slot in sl, action=self._da(ps), reason="Empty slot")
            elif act==1:
                sl[slot]=(iid,cnt)
        return ValidationResult()
    def check_block(self, cid, x, y, z, bid, is_break):
        ps=self.get_ps(cid); pos=(x,y,z)
        if is_break:
            if pos not in self._blocks: self._blocks[pos]=0; return ValidationResult()
            if self._blocks[pos]==0: ps.con_v+=1;ps.tot_v+=1
            return ValidationResult(ok=self._blocks[pos]!=0, action=self._da(ps), reason="Already air")
        else:
            if pos in self._blocks and self._blocks[pos]!=0: ps.con_v+=1;ps.tot_v+=1
            return ValidationResult(ok=pos not in self._blocks or self._blocks[pos]==0,
                                     action=self._da(ps), reason="Occupied")
    def update_block(self, x, y, z, bid): self._blocks[(x,y,z)]=bid
    def update_container(self, cpos, slot, iid, cnt):
        if cpos not in self._containers: self._containers[cpos]={}
        self._containers[cpos][slot]=(iid,cnt)
    def get_block_snapshot(self): return dict(self._blocks)
    def _da(self, ps):
        if ps.con_v>=VIOLATION_KICK_COUNT: return ViolationAction.KICK
        if ps.con_v>=VIOLATION_FREEZE_COUNT: return ViolationAction.FREEZE
        return ViolationAction.ROLLBACK

# ═══════════════════════════════════════════════════════════════════
#  CLIENT SLOT（对齐 dashboard 的 ClientSlot）
# ═══════════════════════════════════════════════════════════════════

@dataclass
class ClientSlot:
    cid: int = -1
    address: str = ""
    name: str = ""
    uuid: bytes = b'\x00' * 16
    state: str = "DISCONNECTED"
    x: float = 0.0; y: float = 0.0; z: float = 0.0
    connected_at: float = 0.0; last_seen: float = 0.0
    violations: int = 0
    bytes_in: int = 0; bytes_out: int = 0
    in_use: bool = False
    crypto: CryptoSession = field(default_factory=CryptoSession)
    reader: PacketReader = field(default_factory=PacketReader)
    writer: Optional[asyncio.StreamWriter] = field(default=None, repr=False)

# ═══════════════════════════════════════════════════════════════════
#  FLUX SERVER CORE（对齐 dashboard 的 FluxServerCore）
# ═══════════════════════════════════════════════════════════════════

class FluxServerCore:
    def __init__(self):
        self._server = None; self._running = False; self._loop = None
        self._clients: Dict[int, ClientSlot] = {}
        self._next_cid = 0; self._start_time = 0.0
        self.crypto_engine = CryptoEngine()
        self.validator = PacketValidator()
        self.event_logger = EventLogger()
        self.total_connections = 0; self.total_packets = 0
        self.total_bytes_in = 0; self.total_bytes_out = 0
        self.total_violations = 0; self.total_events_logged = 0
        self.event_log: deque = deque(maxlen=5000)
        self.on_log = None; self.on_client_change = None; self.on_stats_update = None

    @property
    def uptime(self):
        return time.time() - self._start_time if self._start_time else 0
    @property
    def online_count(self):
        return sum(1 for c in self._clients.values() if c.in_use)

    def _log(self, level, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        entry = f"[{ts}] [{level}] {msg}"
        if self.on_log: self.on_log(entry, level)
    def _emit(self):
        if self.on_client_change: self.on_client_change()
    def _emit_stats(self):
        if self.on_stats_update: self.on_stats_update()

    async def start(self):
        if self._running: return
        self._running = True; self._start_time = time.time()
        self._log("INFO", "═" * 50)
        self._log("INFO", "  Flux Server v2.0 — Decentralized MC Server")
        self._log("INFO", "  synergyedge Team")
        self._log("INFO", "═" * 50)
        self.crypto_engine.generate_keypair()
        self._log("INFO", "[1/3] Crypto engine initialized")
        self.event_logger.init()
        self._log("INFO", f"[2/3] Event logger ready ({self.event_logger.get_event_count()} events)")
        self._log("INFO", f"[3/3] Starting TCP on {SERVER_HOST}:{SERVER_PORT}...")
        try:
            self._server = await asyncio.start_server(self._handle_client, SERVER_HOST, SERVER_PORT)
            self._log("INFO", "═" * 50)
            self._log("INFO", f"  Flux ready on {SERVER_HOST}:{SERVER_PORT}")
            self._log("INFO", f"  Seed: {self.event_logger.get_world_seed()}")
            self._log("INFO", "═" * 50)
            self._emit_stats()
            asyncio.create_task(self._ping_loop())
            async with self._server: await self._server.serve_forever()
        except OSError as e:
            self._log("ERROR", f"Start failed: {e}"); self._running = False

    async def shutdown(self):
        if not self._running: return
        self._running = False
        for cid in list(self._clients.keys()): self._disconnect(cid)
        if self._server: self._server.close(); await self._server.wait_closed()
        self._log("INFO", "Server stopped")

    async def _handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        addr_s = f"{addr[0]}:{addr[1]}"
        if self.online_count >= MAX_CLIENTS:
            self._log("WARN", f"Rejected {addr_s} (full)"); writer.close(); return
        cid = self._next_cid; self._next_cid += 1
        slot = ClientSlot(cid=cid, address=addr_s, state="HANDSHAKE",
                          connected_at=time.time(), last_seen=time.time(),
                          in_use=True, crypto=CryptoSession(), reader=PacketReader(), writer=writer)
        self._clients[cid] = slot; self.total_connections += 1
        self._log("INFO", f"#{cid} connected from {addr_s}")
        self._emit(); self._emit_stats()
        try:
            while self._running and slot.in_use:
                data = await reader.read(4096)
                if not data: break
                slot.bytes_in += len(data); self.total_bytes_in += len(data)
                self.total_packets += 1; slot.last_seen = time.time()
                slot.reader.feed(data)
                while True:
                    result = slot.reader.read_packet()
                    if result is None: break
                    header, iv, payload_data, raw = result
                    await self._process(slot, header, iv, payload_data)
        except asyncio.CancelledError: pass
        except ConnectionResetError: pass
        except Exception as e:
            self._log("ERROR", f"#{cid} error: {e}")
        finally:
            self._disconnect(cid); writer.close()

    def _disconnect(self, cid):
        slot = self._clients.get(cid)
        if slot and slot.in_use:
            slot.in_use = False; slot.state = "DISCONNECTED"; slot.crypto.reset()
            self.validator.reset_player(cid)
            dur = time.time() - slot.connected_at
            self._log("INFO", f"#{cid} ({slot.name or slot.address}) disconnected ({dur:.0f}s)")
            self._emit(); self._emit_stats()

    # ── 包处理（对齐 dashboard）──

    async def _process(self, slot, header, iv, payload_data):
        pt = header.pkt_type
        if pt == PacketType.CLIENT_HELLO:
            await self._handle_hello(slot, iv, payload_data); return
        if pt == PacketType.AUTH_REQUEST:
            await self._handle_auth(slot, header, iv, payload_data); return
        if not slot.crypto.key_ready:
            self._log("WARN", f"#{slot.cid} sent 0x{pt:02X} before key exchange"); return
        payload = CryptoEngine.decrypt_packet(slot.crypto, header, iv, payload_data)
        if payload is None:
            self._log("WARN", f"#{slot.cid} decrypt failed 0x{pt:02X}"); return
        await self._dispatch(slot, pt, payload)

    async def _handle_hello(self, slot, iv, payload_data):
        pubkey = payload_data
        self._log("INFO", f"#{slot.cid}: CLIENT_HELLO {len(pubkey)}B "
                  f"(first 8: {pubkey[:8].hex()})")
        if len(pubkey) < 32:
            self._log("ERROR", f"#{slot.cid}: CLIENT_HELLO too short ({len(pubkey)}B)")
            return
        if not self.crypto_engine.derive_session_key(slot.crypto, pubkey):
            self._log("ERROR", f"#{slot.cid}: key derivation FAILED")
            return
        spub = self.crypto_engine._s_x25519_pub if len(pubkey)==32 else self.crypto_engine._s_p256_der
        h = PacketHeader(magic=PROTOCOL_MAGIC, pkt_type=PacketType.SERVER_HELLO, length=len(spub))
        resp = h.pack() + b'\x00'*PROTOCOL_IV_SIZE + spub
        await self._send_raw(slot, resp)
        slot.state = "AUTHENTICATED"
        self._log("INFO", f"#{slot.cid}: handshake OK, key derived (first 8: {slot.crypto.session_key[:4].hex()})")
        self._emit()

    async def _handle_auth(self, slot, header, iv, payload_data):
        self._log("INFO", f"#{slot.cid}: AUTH_REQUEST recv (iv={iv[:4].hex()}, len={len(payload_data)})")
        payload = CryptoEngine.decrypt_packet(slot.crypto, header, iv, payload_data)
        if payload is None:
            self._log("ERROR", f"#{slot.cid}: AUTH decrypt failed! "
                      f"key_ready={slot.crypto.key_ready}, "
                      f"session_key={slot.crypto.session_key[:4].hex() if slot.crypto.session_key else 'none'}")
            await self._send_encrypted(slot, PacketType.AUTH_FAIL, b"Decrypt failed")
            return
        auth = AuthRequestPayload.unpack(payload)
        slot.uuid = auth.uuid; slot.name = auth.username
        self._log("INFO", f"#{slot.cid} auth as '{auth.username}'")
        await self._send_encrypted(slot, PacketType.AUTH_SUCCESS, b'')
        slot.state = "SYNCING"; self._emit()
        await self._sync_world(slot)
        slot.state = "ACTIVE"
        self._log("INFO", f"#{slot.cid}: sync complete, ACTIVE")
        self._emit()
        # 广播玩家加入
        await self._broadcast_player_join(slot)
        # 向新玩家发送已有玩家位置
        await self._send_existing_players(slot)
        # 向新玩家同步方块世界
        await self._send_world_state(slot)

    async def _sync_world(self, slot):
        seed = struct.pack("<q", self.event_logger.get_world_seed())
        await self._send_encrypted(slot, PacketType.SEED_SYNC, seed)
        self._log("INFO", f"#{slot.cid}: sent seed")
        events = self.event_logger.get_events_since(0)
        sent = 0
        for entry in events:
            edata = struct.pack("B", entry.event_type) + entry.data
            await self._send_encrypted(slot, PacketType.CHUNK_LOG_ENTRY, edata)
            sent += 1
            if sent % SYNC_BATCH_SIZE == 0: await asyncio.sleep(SYNC_BATCH_DELAY_MS/1000)
        self._log("INFO", f"#{slot.cid}: replayed {sent} events")
        await self._send_encrypted(slot, PacketType.SYNC_COMPLETE, b'')

    async def _broadcast_player_join(self, slot):
        name_b = slot.name.encode('utf-8')
        payload = slot.uuid + struct.pack("<H", len(name_b)) + name_b
        for cid, c in self._clients.items():
            if cid == slot.cid or not c.in_use or c.state != "ACTIVE": continue
            await self._send_encrypted(c, PacketType.BROADCAST_PLAYER_JOIN, payload)

    async def _send_existing_players(self, slot):
        for cid, c in self._clients.items():
            if cid == slot.cid or not c.in_use or c.state != "ACTIVE": continue
            name_b = c.name.encode('utf-8')
            payload = struct.pack("<fffff", c.x, c.y, c.z, 0.0, 0.0) + \
                       c.uuid + struct.pack("<H", len(name_b)) + name_b
            await self._send_encrypted(slot, PacketType.BROADCAST_MOVE, payload)

    async def _send_world_state(self, slot):
        sent = 0
        for (x,y,z), bid in self.validator.get_block_snapshot().items():
            etype = PacketType.BLOCK_BREAK if bid==0 else PacketType.BLOCK_PLACE
            edata = struct.pack("B", etype) + struct.pack("<iiii", x, y, z, bid)
            await self._send_encrypted(slot, PacketType.CHUNK_LOG_ENTRY, edata)
            sent += 1
            if sent % SYNC_BATCH_SIZE == 0: await asyncio.sleep(SYNC_BATCH_DELAY_MS/1000)
        if sent > 0: self._log("INFO", f"#{slot.cid}: synced {sent} world blocks")

    # ── 游戏事件分发（对齐 dashboard：不内联广播）──

    async def _dispatch(self, slot, pt, payload):
        if slot.state == "FROZEN" and pt not in (PacketType.PING, PacketType.PONG): return
        handlers = {
            PacketType.PLAYER_MOVE: self._on_move,
            PacketType.BLOCK_BREAK: self._on_break,
            PacketType.BLOCK_PLACE: self._on_place,
            PacketType.ENTITY_INTERACT: self._on_entity,
            PacketType.INVENTORY_CHANGE: self._on_inv,
            PacketType.CHEST_MODIFY: self._on_chest,
            PacketType.PING: self._on_ping,
        }
        h = handlers.get(pt)
        if h: await h(slot, payload)

    async def _on_move(self, slot, payload):
        try: pkt = PlayerMovePayload.unpack(payload)
        except: return
        r = self.validator.check_speed(slot.cid, pkt.x, pkt.y, pkt.z)
        if not r.ok: await self._violation(slot, r); return
        slot.x, slot.y, slot.z = pkt.x, pkt.y, pkt.z
        # 广播给其他玩家（追加 UUID + 用户名）
        await self._broadcast_move(slot, payload)

    async def _on_break(self, slot, payload):
        try: pkt = BlockBreakPayload.unpack(payload)
        except: return
        r = self.validator.check_dist(slot.cid, float(pkt.x), float(pkt.y), float(pkt.z))
        if not r.ok: await self._violation(slot, r); return
        r = self.validator.check_block(slot.cid, pkt.x, pkt.y, pkt.z, pkt.block_id, True)
        if not r.ok: await self._violation(slot, r); return
        self.validator.update_block(pkt.x, pkt.y, pkt.z, 0)
        self.event_logger.log_event(slot.cid, PacketType.BLOCK_BREAK, payload)
        await self._broadcast_block(slot, payload)

    async def _on_place(self, slot, payload):
        try: pkt = BlockPlacePayload.unpack(payload)
        except: return
        r = self.validator.check_dist(slot.cid, float(pkt.x), float(pkt.y), float(pkt.z))
        if not r.ok: await self._violation(slot, r); return
        r = self.validator.check_block(slot.cid, pkt.x, pkt.y, pkt.z, pkt.block_id, False)
        if not r.ok: await self._violation(slot, r); return
        self.validator.update_block(pkt.x, pkt.y, pkt.z, pkt.block_id)
        self.event_logger.log_event(slot.cid, PacketType.BLOCK_PLACE, payload)
        await self._broadcast_block(slot, payload)

    async def _on_entity(self, slot, payload):
        self.event_logger.log_event(slot.cid, PacketType.ENTITY_INTERACT, payload)
        await self._broadcast_raw(slot, PacketType.BROADCAST_ENTITY, payload)

    async def _on_inv(self, slot, payload):
        self.event_logger.log_event(slot.cid, PacketType.INVENTORY_CHANGE, payload)
        await self._broadcast_raw(slot, PacketType.BROADCAST_INVENTORY, payload)

    async def _on_chest(self, slot, payload):
        self.event_logger.log_event(slot.cid, PacketType.CHEST_MODIFY, payload)
        await self._broadcast_raw(slot, PacketType.BROADCAST_INVENTORY, payload)

    async def _on_ping(self, slot, payload):
        await self._send_encrypted(slot, PacketType.PONG, payload)

    # ── 广播方法 ──

    async def _broadcast_move(self, sender, payload):
        """广播移动，追加 UUID + 用户名"""
        name_b = sender.name.encode('utf-8')
        full = payload + sender.uuid + struct.pack("<H", len(name_b)) + name_b
        for cid, c in self._clients.items():
            if cid == sender.cid or not c.in_use or c.state != "ACTIVE": continue
            await self._send_encrypted(c, PacketType.BROADCAST_MOVE, full)

    async def _broadcast_block(self, sender, payload):
        """广播方块变更，原样转发"""
        for cid, c in self._clients.items():
            if cid == sender.cid or not c.in_use or c.state != "ACTIVE": continue
            await self._send_encrypted(c, PacketType.BROADCAST_BLOCK, payload)

    async def _broadcast_raw(self, sender, pkt_type, payload):
        for cid, c in self._clients.items():
            if cid == sender.cid or not c.in_use or c.state != "ACTIVE": continue
            await self._send_encrypted(c, pkt_type, payload)

    # ── 违规 ──

    async def _violation(self, slot, r):
        if r.action == ViolationAction.ROLLBACK:
            await self._send_encrypted(slot, PacketType.ROLLBACK, b'')
        elif r.action == ViolationAction.FREEZE:
            await self._send_encrypted(slot, PacketType.FREEZE, b'')
            self.total_violations += 1; slot.violations += 1
        elif r.action == ViolationAction.KICK:
            await self._send_encrypted(slot, PacketType.KICK, r.reason.encode('utf-8'))
            slot.in_use = False

    # ── 网络 I/O（对齐 dashboard：async await）──

    async def _send_raw(self, slot, data):
        if slot.writer is None: return
        try:
            slot.writer.write(data); await slot.writer.drain()
            slot.bytes_out += len(data); self.total_bytes_out += len(data)
        except Exception as e:
            self._log("ERROR", f"Send to #{slot.cid} failed: {e}")
            slot.in_use = False

    async def _send_encrypted(self, slot, pkt_type, payload):
        enc = CryptoEngine.encrypt_packet(slot.crypto, pkt_type, payload)
        if enc: await self._send_raw(slot, enc)

    async def _ping_loop(self):
        while self._running:
            await asyncio.sleep(PING_INTERVAL_SEC)
            now = time.time()
            for cid, slot in list(self._clients.items()):
                if slot.in_use and now - slot.last_seen > CLIENT_TIMEOUT_SEC:
                    self._log("WARN", f"#{cid} timed out"); self._disconnect(cid)
            for cid, slot in list(self._clients.items()):
                if slot.in_use and slot.state == "ACTIVE":
                    await self._send_encrypted(slot, PacketType.PING,
                                               struct.pack("<f", time.monotonic()))

    def get_online_clients(self): return [c for c in self._clients.values() if c.in_use]
    def get_stats(self):
        return {"online":self.online_count,"max":MAX_CLIENTS,"uptime":self.uptime,
                "conns":self.total_connections,"pkts":self.total_packets,
                "bin":self.total_bytes_in,"bout":self.total_bytes_out,
                "viol":self.total_violations,"events":self.event_logger.get_event_count()}

# ═══════════════════════════════════════════════════════════════════
#  GUI
# ═══════════════════════════════════════════════════════════════════

class Theme:
    BG="#0f0f1a"; PANEL="#16162a"; CARD="#1c1c36"; INPUT="#222244"
    FG="#e0e0f0"; DIM="#8888aa"; ACCENT="#6c5ce7"; GREEN="#00e676"
    RED="#ff5252"; YELLOW="#ffd740"; CYAN="#00e5ff"; BORDER="#2a2a50"
    FONT=("Segoe UI",10); MONO=("Cascadia Code",10)

class FluxDashboard:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Flux Server — 控制台")
        self.root.geometry("1280x800")
        self.root.configure(bg=Theme.BG)
        self.core = FluxServerCore()
        self.core.on_log = self._on_log
        self.core.on_client_change = self._refresh_clients
        self.core.on_stats_update = self._refresh_stats
        self._build_ui()
        self._running = False

    def _build_ui(self):
        # 顶部
        top = tk.Frame(self.root, bg=Theme.PANEL, height=60)
        top.pack(fill=tk.X); top.pack_propagate(False)
        tk.Label(top, text="⚡ Flux Server", font=("Segoe UI",16,"bold"),
                 bg=Theme.PANEL, fg=Theme.ACCENT).pack(side=tk.LEFT, padx=15)
        self._status_lbl = tk.Label(top, text="● 已停止", font=Theme.FONT,
                                     bg=Theme.PANEL, fg=Theme.RED)
        self._status_lbl.pack(side=tk.LEFT, padx=10)
        self._start_btn = tk.Button(top, text="▶ 启动", command=self._start,
                                     bg="#1a5c2a", fg="white", relief=tk.FLAT, font=Theme.FONT)
        self._start_btn.pack(side=tk.LEFT, padx=5)
        self._stop_btn = tk.Button(top, text="■ 停止", command=self._stop,
                                    bg="#5c1a1a", fg="white", relief=tk.FLAT, font=Theme.FONT,
                                    state=tk.DISABLED)
        self._stop_btn.pack(side=tk.LEFT, padx=5)

        # 统计卡片
        cards = tk.Frame(self.root, bg=Theme.BG)
        cards.pack(fill=tk.X, padx=10, pady=5)
        self._card_online = self._card(cards, "👥 在线", "0")
        self._card_conns = self._card(cards, "📊 总连接", "0")
        self._card_pkts = self._card(cards, "📦 数据包", "0")
        self._card_events = self._card(cards, "📝 事件", "0")
        self._card_uptime = self._card(cards, "⏱ 运行", "0s")

        # 中部：日志 + 玩家列表
        mid = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, bg=Theme.BG, sashwidth=3)
        mid.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # 日志
        log_frame = tk.Frame(mid, bg=Theme.CARD)
        mid.add(log_frame, width=800)
        tk.Label(log_frame, text="📋 服务日志", bg=Theme.CARD, fg=Theme.FG,
                 font=("Segoe UI",11,"bold")).pack(anchor=tk.W, padx=10, pady=5)
        self._log_text = tk.Text(log_frame, bg="#0a0a1a", fg=Theme.FG,
                                  font=Theme.MONO, relief=tk.FLAT, wrap=tk.WORD,
                                  state=tk.DISABLED)
        self._log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self._log_text.tag_configure("INFO", foreground=Theme.FG)
        self._log_text.tag_configure("WARN", foreground=Theme.YELLOW)
        self._log_text.tag_configure("ERROR", foreground=Theme.RED)

        # 玩家列表
        pl_frame = tk.Frame(mid, bg=Theme.CARD)
        mid.add(pl_frame, width=460)
        tk.Label(pl_frame, text="👥 在线玩家", bg=Theme.CARD, fg=Theme.FG,
                 font=("Segoe UI",11,"bold")).pack(anchor=tk.W, padx=10, pady=5)
        cols = ("cid","name","state","pos","viol")
        self._tree = ttk.Treeview(pl_frame, columns=cols, show="headings", height=15)
        self._tree.heading("cid", text="#"); self._tree.column("cid", width=30)
        self._tree.heading("name", text="名称"); self._tree.column("name", width=100)
        self._tree.heading("state", text="状态"); self._tree.column("state", width=80)
        self._tree.heading("pos", text="位置"); self._tree.column("pos", width=180)
        self._tree.heading("viol", text="违规"); self._tree.column("viol", width=40)
        self._tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 底部
        bot = tk.Frame(self.root, bg=Theme.PANEL, height=30)
        bot.pack(fill=tk.X)
        self._addr_lbl = tk.Label(bot, text=f"监听: {SERVER_HOST}:{SERVER_PORT}",
                                   bg=Theme.PANEL, fg=Theme.DIM, font=("Segoe UI",9))
        self._addr_lbl.pack(side=tk.LEFT, padx=10)

    def _card(self, parent, title, val):
        f = tk.Frame(parent, bg=Theme.CARD, height=60)
        f.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3)
        f.pack_propagate(False)
        tk.Label(f, text=title, bg=Theme.CARD, fg=Theme.DIM, font=("Segoe UI",9)).pack(anchor=tk.W, padx=10, pady=(8,0))
        lbl = tk.Label(f, text=val, bg=Theme.CARD, fg=Theme.FG, font=("Cascadia Code",16,"bold"))
        lbl.pack(padx=10, pady=(0,5))
        return lbl

    def _on_log(self, entry, level):
        self.root.after(0, self._append_log, entry, level)

    def _append_log(self, entry, level):
        self._log_text.config(state=tk.NORMAL)
        self._log_text.insert(tk.END, entry + "\n", level)
        self._log_text.see(tk.END)
        self._log_text.config(state=tk.DISABLED)

    def _refresh_clients(self):
        self.root.after(0, self._do_refresh_clients)

    def _do_refresh_clients(self):
        self._tree.delete(*self._tree.get_children())
        for c in self.core.get_online_clients():
            pos = f"({c.x:.1f}, {c.y:.1f}, {c.z:.1f})"
            self._tree.insert("", tk.END, values=(c.cid, c.name, c.state, pos, c.violations))

    def _refresh_stats(self):
        self.root.after(0, self._do_refresh_stats)

    def _do_refresh_stats(self):
        s = self.core.get_stats()
        self._card_online.config(text=str(s["online"]))
        self._card_conns.config(text=str(s["conns"]))
        self._card_pkts.config(text=str(s["pkts"]))
        self._card_events.config(text=str(s["events"]))
        m, sec = divmod(int(s["uptime"]), 60)
        h, m = divmod(m, 60)
        self._card_uptime.config(text=f"{h:02d}:{m:02d}:{sec:02d}")

    def _start(self):
        if self._running: return
        self._running = True
        self._status_lbl.config(text="● 运行中", fg=Theme.GREEN)
        self._start_btn.config(state=tk.DISABLED)
        self._stop_btn.config(state=tk.NORMAL)
        self._loop = asyncio.new_event_loop()
        threading.Thread(target=self._run_loop, daemon=True).start()

    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        try: self._loop.run_until_complete(self.core.start())
        except: pass

    def _stop(self):
        if not self._running: return
        self._running = False
        if self._loop: self._loop.call_soon_threadsafe(
            lambda: self._loop.create_task(self.core.shutdown()))
        self._status_lbl.config(text="● 已停止", fg=Theme.RED)
        self._start_btn.config(state=tk.NORMAL)
        self._stop_btn.config(state=tk.DISABLED)

    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_close(self):
        if self._running: self._stop()
        self.root.destroy()

# ═══════════════════════════════════════════════════════════════════
#  CLI 模式
# ═══════════════════════════════════════════════════════════════════

def run_cli():
    core = FluxServerCore()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    def sig(): loop.create_task(core.shutdown())
    for s in (signal.SIGINT, signal.SIGTERM):
        try: loop.add_signal_handler(s, sig)
        except: signal.signal(s, lambda *_: sig())
    try: loop.run_until_complete(core.start())
    except KeyboardInterrupt: loop.run_until_complete(core.shutdown())
    finally: loop.close()

# ═══════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    if "--cli" in sys.argv:
        run_cli()
    else:
        app = FluxDashboard()
        app.run()

if __name__ == "__main__":
    main()
