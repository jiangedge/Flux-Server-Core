#!/usr/bin/env python3
"""
Flux Protocol Analyzer
实时记录展示 0x01-0x51 所有二进制协议事件

"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import struct
import os
import sys
import time
import threading
import socket
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, Dict, List, Callable

# ═══════════════════════════════════════════════════════════════
#  协议定义
# ═══════════════════════════════════════════════════════════════

PROTOCOL_MAGIC = 0x4658
PROTOCOL_HEADER_SIZE = 7
PROTOCOL_IV_SIZE = 12

PACKET_NAMES: Dict[int, str] = {
    0x01: "CLIENT_HELLO", 0x02: "SERVER_HELLO",
    0x03: "AUTH_REQUEST", 0x04: "AUTH_SUCCESS",
    0x10: "WORLD_SEED", 0x11: "EVENT_LOG_ENTRY",
    0x12: "SYNC_COMPLETE",
    0x20: "PLAYER_MOVE", 0x21: "BLOCK_BREAK",
    0x22: "BLOCK_PLACE", 0x23: "ENTITY_INTERACT",
    0x24: "INVENTORY_CHANGE", 0x26: "CHEST_MODIFY",
    0x27: "CHUNK_TRANSFER",
    0x30: "BROADCAST_MOVE", 0x31: "BROADCAST_BLOCK",
    0x32: "BROADCAST_ENTITY", 0x33: "BROADCAST_INVENTORY",
    0x40: "ROLLBACK", 0x41: "FREEZE",
    0x42: "KICK",
    0x50: "PING", 0x51: "PONG",
}

PACKET_COLORS: Dict[int, str] = {
    0x01: "#4A90D9", 0x02: "#4A90D9", 0x03: "#5B9BD5", 0x04: "#6BAED6",
    0x10: "#9B59B6", 0x11: "#8E44AD", 0x12: "#BB8FCE",
    0x20: "#27AE60", 0x21: "#E67E22", 0x22: "#2ECC71", 0x23: "#F39C12",
    0x24: "#1ABC9C", 0x26: "#2980B9", 0x27: "#3498DB",
    0x30: "#F1C40F", 0x31: "#E74C3C", 0x32: "#E67E22", 0x33: "#D68910",
    0x40: "#E74C3C", 0x41: "#C0392B", 0x42: "#922B21",
    0x50: "#95A5A6", 0x51: "#7F8C8D",
}

PHASE_NAMES: Dict[int, str] = {
    0x01: "握手", 0x02: "握手", 0x03: "握手", 0x04: "握手",
    0x10: "同步", 0x11: "同步", 0x12: "同步",
    0x20: "事件", 0x21: "事件", 0x22: "事件", 0x23: "事件", 0x24: "事件",
    0x26: "事件", 0x27: "事件",
    0x30: "广播", 0x31: "广播", 0x32: "广播", 0x33: "广播",
    0x40: "控制", 0x41: "控制", 0x42: "控制",
    0x50: "心跳", 0x51: "心跳",
}


# ═══════════════════════════════════════════════════════════════
#  数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class PacketRecord:
    index: int = 0
    timestamp: float = 0.0
    direction: str = ""
    pkt_type: int = 0
    payload_size: int = 0
    raw_payload: bytes = b""
    decoded: str = ""
    phase: str = ""

    @property
    def time_str(self) -> str:
        dt = datetime.fromtimestamp(self.timestamp)
        return dt.strftime("%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"

    @property
    def type_name(self) -> str:
        return PACKET_NAMES.get(self.pkt_type, f"0x{self.pkt_type:02X}")

    @property
    def color(self) -> str:
        return PACKET_COLORS.get(self.pkt_type, "#FFFFFF")


# ═══════════════════════════════════════════════════════════════
#  载荷解码器 (完整解析 0x01 - 0x51)
# ═══════════════════════════════════════════════════════════════

class PayloadDecoder:
    @staticmethod
    def decode(pkt_type: int, data: bytes) -> str:
        dlen = len(data)
        if dlen == 0 and pkt_type not in (0x04, 0x12, 0x40, 0x41):
            return "(空载荷 - 可能异常)"

        try:
            # === 握手层 ===
            if pkt_type in (0x01, 0x02):  # 32B 公钥
                return f"ECDH 公钥: {data[:16].hex()}..."
            elif pkt_type == 0x03:  # 32B UUID+Name
                uuid_hex = data[:16].hex()
                name = data[16:].decode("utf-8", errors="ignore").strip("\x00")
                return f"UUID={uuid_hex[:8]}... 用户名={name}"
            elif pkt_type == 0x04:
                return "认证成功"

            # === 同步层 ===
            elif pkt_type == 0x10:  # 8B 种子
                if dlen >= 8:
                    seed = struct.unpack("<q", data[:8])[0]
                    return f"世界种子 Seed={seed}"
            elif pkt_type == 0x11:  # 可变长 历史日志
                return f"历史事件记录包 ({dlen} 字节)"
            elif pkt_type == 0x12:
                return "同步完成，进入活跃状态"

            # === 游戏事件层 ===
            elif pkt_type in (0x20, 0x30):  # 25B 移动包
                if dlen >= 20:  # 安全解析前20字节坐标和视角
                    seq, x, y, z, yaw, pitch = struct.unpack("<Ifffff", data[:24]) if dlen >= 24 else (0, 0, 0, 0, 0, 0)
                    return f"Seq={seq} 坐标({x:.2f}, {y:.2f}, {z:.2f}) 偏航={yaw:.1f}° 俯仰={pitch:.1f}°"
            elif pkt_type == 0x21:  # 18B 方块破坏
                if dlen >= 18:
                    seq, x, y, z, block_id, face = struct.unpack("<IiiiiBB", data[:18])
                    return f"Seq={seq} 破坏({x},{y},{z}) 目标方块ID={block_id}"
            elif pkt_type == 0x22:  # 30B 方块放置
                if dlen >= 18:
                    seq, x, y, z, block_id = struct.unpack("<Iiiii", data[:20])
                    return f"Seq={seq} 放置({x},{y},{z}) 目标方块ID={block_id} (全长30B)"
            elif pkt_type == 0x23:  # 21B 实体交互
                if dlen >= 21:
                    seq, entity_id, action = struct.unpack("<IIB", data[:9])
                    return f"Seq={seq} 交互实体ID={entity_id} 动作码={action}"
            elif pkt_type == 0x24:  # 9B 物品栏变更
                if dlen >= 9:
                    seq, slot, item_id, count = struct.unpack("<IHHB", data[:9])
                    return f"Seq={seq} 槽位={slot} 物品ID={item_id} 数量={count}"
            elif pkt_type == 0x26:  # 20B 容器修改
                return f"容器状态修改 ({dlen} 字节) 原始十六进制: {data.hex()[:16]}..."
            elif pkt_type == 0x27:  # 37B 区块/实体完整传输
                if dlen >= 8:
                    seq, entity_id = struct.unpack("<II", data[:8])
                    return f"Seq={seq} 实体状态快照 ID={entity_id} (全长37B)"

            # === 广播层 (除0x30外长度可变) ===
            elif pkt_type in (0x31, 0x32, 0x33):
                return f"服务器广播包 ({dlen} 字节)"

            # === 控制层 ===
            elif pkt_type == 0x40:
                return "强制回滚位置 (防作弊触发)"
            elif pkt_type == 0x41:
                return "冻结客户端操作 (防作弊触发)"
            elif pkt_type == 0x42:  # 踢出原因
                reason = data.decode("utf-8", errors="ignore")
                return f"踢出连接, 原因: {reason}"

            # === 心跳层 ===
            elif pkt_type in (0x50, 0x51):  # 4B
                if dlen >= 4:
                    ts = struct.unpack("<f", data[:4])[0]
                    return f"系统时钟={ts:.3f}"

            # 兜底显示
            return f"[{PACKET_NAMES.get(pkt_type, '未知')}] 数据体长 {dlen}B Hex: {data[:16].hex()}"
        except struct.error:
            return f"结构体解析异常 (数据长度: {dlen}B) Hex: {data.hex()[:16]}"
        except Exception as e:
            return f"解码错误: {e}"


# ═══════════════════════════════════════════════════════════════
#  事件日志解析器
# ═══════════════════════════════════════════════════════════════

class EventLogParser:
    HEADER_FORMAT = "<IBBH"
    HEADER_SIZE = 8

    @classmethod
    def parse_file(cls, filepath: str) -> List[PacketRecord]:
        records = []
        try:
            with open(filepath, "rb") as f:
                data = f.read()
        except Exception:
            return records

        offset = 0;
        index = 0
        while offset + cls.HEADER_SIZE + 32 <= len(data):
            ts, cid, etype, dlen = struct.unpack(
                cls.HEADER_FORMAT, data[offset:offset + cls.HEADER_SIZE])
            entry_size = cls.HEADER_SIZE + dlen + 32
            if offset + entry_size > len(data): break
            ev_data = data[offset + cls.HEADER_SIZE: offset + cls.HEADER_SIZE + dlen]
            ts_sec = ts / 1000.0 if ts > 1_000_000_000 else ts
            records.append(PacketRecord(
                index=index, timestamp=ts_sec, direction=f"C#{cid}",
                pkt_type=etype, payload_size=dlen, raw_payload=ev_data,
                decoded=PayloadDecoder.decode(etype, ev_data),
                phase=PHASE_NAMES.get(etype, "未知")))
            offset += entry_size;
            index += 1
        return records

    @classmethod
    def parse_directory(cls, dirpath: str) -> List[PacketRecord]:
        all_records = []
        idx = 0
        while True:
            fp = os.path.join(dirpath, f"events_{idx:04d}.bin")
            if not os.path.exists(fp): break
            all_records.extend(cls.parse_file(fp))
            idx += 1
        return all_records

    @classmethod
    def find_log_dir(cls) -> Optional[str]:
        candidates = [
            "./flux_data/events",
            "../flux_data/events",
            "./server/flux_data/events",
            os.path.expanduser("~/.flux/events"),
        ]
        for c in candidates:
            if os.path.isdir(c) and any(f.endswith(".bin") for f in os.listdir(c)):
                return os.path.abspath(c)
        return None


# ═══════════════════════════════════════════════════════════════
#  实时日志监控器
# ═══════════════════════════════════════════════════════════════

class LogWatcher:
    def __init__(self, log_dir: str, callback: Callable):
        self.log_dir = log_dir
        self.callback = callback
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._file_offsets: Dict[str, int] = {}
        self._known_files: set = set()

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._watch_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _watch_loop(self):
        self._scan_existing()
        while self._running:
            time.sleep(0.5)
            self._check_new_data()

    def _scan_existing(self):
        for f in sorted(os.listdir(self.log_dir)):
            if f.endswith(".bin"):
                fp = os.path.join(self.log_dir, f)
                self._known_files.add(f)
                self._file_offsets[fp] = os.path.getsize(fp)

    def _check_new_data(self):
        try:
            files = set(os.listdir(self.log_dir))
        except OSError:
            return

        for f in sorted(files):
            if not f.endswith(".bin"): continue
            fp = os.path.join(self.log_dir, f)

            if f not in self._known_files:
                self._known_files.add(f)
                self._file_offsets[fp] = 0

            try:
                current_size = os.path.getsize(fp)
            except OSError:
                continue

            last_offset = self._file_offsets.get(fp, 0)
            if current_size > last_offset:
                self._read_new_entries(fp, last_offset)
                self._file_offsets[fp] = current_size

    def _read_new_entries(self, filepath: str, offset: int):
        try:
            with open(filepath, "rb") as f:
                f.seek(offset)
                data = f.read()
        except Exception:
            return

        local_off = 0;
        index = 0
        while local_off + EventLogParser.HEADER_SIZE + 32 <= len(data):
            ts, cid, etype, dlen = struct.unpack(
                EventLogParser.HEADER_FORMAT,
                data[local_off:local_off + EventLogParser.HEADER_SIZE])
            entry_size = EventLogParser.HEADER_SIZE + dlen + 32
            if local_off + entry_size > len(data): break
            ev_data = data[local_off + EventLogParser.HEADER_SIZE:
                           local_off + EventLogParser.HEADER_SIZE + dlen]
            ts_sec = ts / 1000.0 if ts > 1_000_000_000 else ts
            record = PacketRecord(
                index=index, timestamp=ts_sec, direction=f"C#{cid}",
                pkt_type=etype, payload_size=dlen, raw_payload=ev_data,
                decoded=PayloadDecoder.decode(etype, ev_data),
                phase=PHASE_NAMES.get(etype, "未知"))
            self.callback(record)
            local_off += entry_size;
            index += 1


# ═══════════════════════════════════════════════════════════════
#  TCP 代理捕获器
# ═══════════════════════════════════════════════════════════════

class FluxPacketReader:
    def __init__(self):
        self._buf = bytearray()

    def feed(self, data):
        self._buf.extend(data)

    def read_packet(self):
        if len(self._buf) < PROTOCOL_HEADER_SIZE: return None
        magic, pkt_type, length = struct.unpack(">HBI", self._buf[:PROTOCOL_HEADER_SIZE])
        if magic != PROTOCOL_MAGIC:
            self._buf.pop(0);
            return self.read_packet()
        total = PROTOCOL_HEADER_SIZE + PROTOCOL_IV_SIZE + length
        if len(self._buf) < total: return None
        raw = bytes(self._buf[:total])
        iv = raw[PROTOCOL_HEADER_SIZE:PROTOCOL_HEADER_SIZE + PROTOCOL_IV_SIZE]
        payload = raw[PROTOCOL_HEADER_SIZE + PROTOCOL_IV_SIZE:]
        self._buf = self._buf[total:]
        return type('H', (), {'pkt_type': pkt_type})(), iv, payload


class PacketCapture:
    def __init__(self, listen_port, target_host, target_port):
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self._callback: Optional[Callable] = None
        self._running = False
        self._index = 0

    def set_callback(self, cb):
        self._callback = cb

    def start(self):
        self._running = True
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self):
        self._running = False

    def _run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.listen_port));
        srv.listen(1);
        srv.settimeout(1)
        while self._running:
            try:
                cs, addr = srv.accept()
                threading.Thread(target=self._session, args=(cs,), daemon=True).start()
            except socket.timeout:
                continue
        srv.close()

    def _session(self, cs):
        try:
            rs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            rs.connect((self.target_host, self.target_port))
        except:
            cs.close(); return
        t1 = threading.Thread(target=self._relay, args=(cs, rs, "C→S"), daemon=True)
        t2 = threading.Thread(target=self._relay, args=(rs, cs, "S→C"), daemon=True)
        t1.start();
        t2.start();
        t1.join();
        t2.join()
        cs.close();
        rs.close()

    def _relay(self, src, dst, direction):
        reader = FluxPacketReader()
        try:
            while self._running:
                data = src.recv(4096)
                if not data: break
                dst.sendall(data);
                reader.feed(data)
                while True:
                    r = reader.read_packet()
                    if r is None: break
                    h, iv, payload = r
                    record = PacketRecord(
                        index=self._index, timestamp=time.time(),
                        direction=direction, pkt_type=h.pkt_type,
                        payload_size=len(payload), raw_payload=payload,
                        decoded=PayloadDecoder.decode(h.pkt_type, payload),
                        phase=PHASE_NAMES.get(h.pkt_type, "未知"))
                    self._index += 1
                    if self._callback: self._callback(record)
        except:
            pass


# ═══════════════════════════════════════════════════════════════
#  GUI
# ═══════════════════════════════════════════════════════════════

class FluxProtocolAnalyzer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Flux Protocol Analyzer — 0x01-0x51 事件记录器")
        self.geometry("1400x850")
        self.configure(bg="#1a1a2e")
        self._records: List[PacketRecord] = []
        self._filtered: List[PacketRecord] = []
        self._stats: Dict[int, int] = {}
        self._watcher: Optional[LogWatcher] = None
        self._paused = False
        self._watching = False
        self._global_idx = 0
        self._build_ui()

    def _build_ui(self):
        # ── 顶部 ──
        toolbar = tk.Frame(self, bg="#0f3460", height=50)
        toolbar.pack(fill=tk.X, side=tk.TOP);
        toolbar.pack_propagate(False)
        tk.Label(toolbar, text="📡 Flux Protocol Analyzer",
                 bg="#0f3460", fg="#e94560",
                 font=("Microsoft YaHei", 14, "bold")).pack(side=tk.LEFT, padx=10)

        btn_style = {"bg": "#16213e", "fg": "#e0e0e0", "relief": tk.FLAT,
                     "font": ("Microsoft YaHei", 9), "activebackground": "#1a508b"}

        tk.Button(toolbar, text="📂 加载日志", command=self._load_log, **btn_style).pack(side=tk.LEFT, padx=3)
        tk.Button(toolbar, text="🔍 自动检测", command=self._auto_detect, **btn_style).pack(side=tk.LEFT, padx=3)

        self._watch_btn = tk.Button(toolbar, text="▶ 实时监控", command=self._toggle_watch,
                                    bg="#1a5c2a", fg="#e0e0e0", relief=tk.FLAT,
                                    font=("Microsoft YaHei", 9))
        self._watch_btn.pack(side=tk.LEFT, padx=3)

        tk.Button(toolbar, text="🔗 代理捕获", command=self._start_proxy, **btn_style).pack(side=tk.LEFT, padx=3)
        self._pause_btn = tk.Button(toolbar, text="⏸ 暂停", command=self._toggle_pause, **btn_style)
        self._pause_btn.pack(side=tk.LEFT, padx=3)
        tk.Button(toolbar, text="🗑 清空", command=self._clear, **btn_style).pack(side=tk.LEFT, padx=3)
        tk.Button(toolbar, text="💾 导出", command=self._export, **btn_style).pack(side=tk.LEFT, padx=3)

        self._scroll_var = tk.BooleanVar(value=True)
        tk.Checkbutton(toolbar, text="自动滚动", variable=self._scroll_var,
                       bg="#0f3460", fg="#e0e0e0", selectcolor="#16213e",
                       activebackground="#0f3460").pack(side=tk.LEFT, padx=8)

        self._count_lbl = tk.Label(toolbar, text="记录: 0", bg="#0f3460", fg="#e94560",
                                   font=("Consolas", 11, "bold"))
        self._count_lbl.pack(side=tk.RIGHT, padx=10)

        self._status_lbl = tk.Label(toolbar, text="未监控", bg="#0f3460", fg="#888",
                                    font=("Consolas", 9))
        self._status_lbl.pack(side=tk.RIGHT, padx=5)

        # ── 筛选 ──
        filt = tk.Frame(self, bg="#1a1a2e", height=35)
        filt.pack(fill=tk.X, padx=5, pady=2);
        filt.pack_propagate(False)

        tk.Label(filt, text="阶段:", bg="#1a1a2e", fg="#aaa").pack(side=tk.LEFT, padx=3)
        self._phase_var = tk.StringVar(value="全部")
        cb = ttk.Combobox(filt, textvariable=self._phase_var, width=8, state="readonly",
                          values=["全部", "握手", "同步", "事件", "广播", "控制", "心跳"])
        cb.pack(side=tk.LEFT, padx=2);
        cb.bind("<<ComboboxSelected>>", lambda e: self._refilter())

        tk.Label(filt, text="搜索:", bg="#1a1a2e", fg="#aaa").pack(side=tk.LEFT, padx=3)
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._refilter())
        tk.Entry(filt, textvariable=self._search_var, bg="#16213e", fg="#e0e0e0",
                 insertbackground="#e0e0e0", relief=tk.FLAT, width=25).pack(side=tk.LEFT, padx=3, ipady=3)

        tk.Label(filt, text="类型:", bg="#1a1a2e", fg="#aaa").pack(side=tk.LEFT, padx=3)
        self._type_var = tk.StringVar(value="全部")
        tc = ttk.Combobox(filt, textvariable=self._type_var, width=18, state="readonly",
                          values=["全部"] + [f"0x{k:02X} {v}" for k, v in sorted(PACKET_NAMES.items())])
        tc.pack(side=tk.LEFT, padx=2);
        tc.bind("<<ComboboxSelected>>", lambda e: self._refilter())

        # ── 主内容 ──
        main = tk.PanedWindow(self, orient=tk.HORIZONTAL, bg="#1a1a2e", sashwidth=4)
        main.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)

        # 左：列表
        left = tk.Frame(main, bg="#16213e");
        main.add(left, width=900)
        cols = ("idx", "time", "dir", "phase", "type", "size", "decoded")
        self._tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="browse")
        for c, w in [("idx", 40), ("time", 100), ("dir", 50), ("phase", 40), ("type", 170), ("size", 45),
                     ("decoded", 400)]:
            self._tree.heading(c, text=c);
            self._tree.column(c, width=w, minwidth=30)
        sb = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True);
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        # 右：详情
        right = tk.Frame(main, bg="#16213e");
        main.add(right, width=480)
        tk.Label(right, text="📋 包详情", bg="#16213e", fg="#e94560",
                 font=("Microsoft YaHei", 11, "bold")).pack(anchor=tk.W, padx=10, pady=5)
        self._detail = tk.Text(right, bg="#0a0a23", fg="#e0e0e0", font=("Consolas", 10),
                               relief=tk.FLAT, wrap=tk.WORD, state=tk.DISABLED)
        self._detail.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 底部统计
        stats = tk.Frame(self, bg="#0f3460", height=55)
        stats.pack(fill=tk.X, side=tk.BOTTOM);
        stats.pack_propagate(False)
        self._stats_canvas = tk.Canvas(stats, bg="#0f3460", highlightthickness=0)
        self._stats_canvas.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)

    def add_record(self, record: PacketRecord):
        if self._paused: return
        record.index = self._global_idx
        self._global_idx += 1
        self._records.append(record)
        self._stats[record.pkt_type] = self._stats.get(record.pkt_type, 0) + 1
        if self._match_filter(record):
            self._filtered.append(record)
            self._tree_insert(record)
        self._update_count()
        self._update_stats()

    def _tree_insert(self, record):
        tag = f"t{record.pkt_type:02x}"
        self._tree.insert("", tk.END, iid=str(record.index), values=(
            record.index, record.time_str, record.direction, record.phase,
            f"0x{record.pkt_type:02X} {record.type_name}",
            f"{record.payload_size}B", record.decoded), tags=(tag,))
        self._tree.tag_configure(tag, foreground=record.color)
        if self._scroll_var.get():
            self._tree.see(str(record.index))

    def _match_filter(self, r):
        p = self._phase_var.get()
        if p != "全部" and r.phase != p: return False
        t = self._type_var.get()
        if t != "全部":
            tc = int(t.split()[0], 16)
            if r.pkt_type != tc: return False
        s = self._search_var.get().lower()
        if s and s not in f"{r.decoded} {r.type_name}".lower(): return False
        return True

    def _refilter(self):
        self._filtered.clear()
        self._tree.delete(*self._tree.get_children())
        for r in self._records:
            if self._match_filter(r):
                self._filtered.append(r)
                self._tree_insert(r)
        self._update_count()

    def _on_select(self, _):
        sel = self._tree.selection()
        if not sel: return
        idx = int(sel[0])
        if idx >= len(self._records): return
        r = self._records[idx]
        self._detail.config(state=tk.NORMAL)
        self._detail.delete("1.0", tk.END)
        lines = [
            f"{'═' * 50}", f"  序号: #{r.index}", f"  时间: {r.time_str}",
            f"  方向: {r.direction}", f"  阶段: {r.phase}",
            f"  类型: 0x{r.pkt_type:02X} ({r.type_name})",
            f"  大小: {r.payload_size}B", f"{'─' * 50}",
            f"  解码: {r.decoded}", f"{'─' * 50}", "  HEX:"]
        raw = r.raw_payload
        for i in range(0, len(raw), 16):
            chunk = raw[i:i + 16]
            h = " ".join(f"{b:02X}" for b in chunk)
            a = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"  {i:04X}  {h:<48s}  {a}")
        lines.append(f"{'═' * 50}")
        self._detail.insert("1.0", "\n".join(lines))
        self._detail.config(state=tk.DISABLED)

    def _update_count(self):
        t, f = len(self._records), len(self._filtered)
        self._count_lbl.config(text=f"记录: {f}/{t}" if f != t else f"记录: {t}")

    def _update_stats(self):
        self._stats_canvas.delete("all")
        if not self._stats: return
        total = sum(self._stats.values());
        x = 10
        for pt in sorted(self._stats):
            cnt = self._stats[pt];
            name = PACKET_NAMES.get(pt, f"0x{pt:02X}")
            color = PACKET_COLORS.get(pt, "#888")
            w = max(20, cnt / total * 300)
            self._stats_canvas.create_rectangle(x, 5, x + w, 25, fill=color, outline="")
            self._stats_canvas.create_text(x + 3, 15, anchor=tk.W, text=f"{name}({cnt})",
                                           fill="white", font=("Consolas", 7))
            x += w + 4

    def _load_log(self):
        d = filedialog.askdirectory(title="选择 events 目录")
        if not d: return
        records = EventLogParser.parse_directory(d)
        if not records: messagebox.showinfo("提示", "未找到日志"); return
        self._clear()
        for r in records: self.add_record(r)
        messagebox.showinfo("完成", f"加载 {len(records)} 条")

    def _auto_detect(self):
        d = EventLogParser.find_log_dir()
        if not d:
            messagebox.showinfo("提示", "未找到 flux_data/events/ 目录\n"
                                        "请确保服务端已运行过，或手动加载")
            return
        records = EventLogParser.parse_directory(d)
        self._clear()
        for r in records: self.add_record(r)
        self._status_lbl.config(text=f"📁 {d}", fg="#82E0AA")
        messagebox.showinfo("自动检测", f"找到: {d}\n加载 {len(records)} 条记录")

    def _toggle_watch(self):
        if self._watching:
            self._stop_watch()
        else:
            self._start_watch()

    def _start_watch(self):
        d = EventLogParser.find_log_dir()
        if not d:
            d = filedialog.askdirectory(title="选择 flux_data/events/ 目录")
            if not d: return
        self._watcher = LogWatcher(d, lambda r: self.after(0, self.add_record, r))
        self._watcher.start()
        self._watching = True
        self._watch_btn.config(text="⏹ 停止监控", bg="#5c1a1a")
        self._status_lbl.config(text=f"🔴 实时监控: {d}", fg="#E74C3C")
        self._paused = False

    def _stop_watch(self):
        if self._watcher: self._watcher.stop()
        self._watching = False
        self._watch_btn.config(text="▶ 实时监控", bg="#1a5c2a")
        self._status_lbl.config(text="已停止", fg="#888")

    def _start_proxy(self):
        dlg = tk.Toplevel(self);
        dlg.title("代理捕获");
        dlg.geometry("350x200")
        dlg.configure(bg="#1a1a2e");
        dlg.transient(self)
        tk.Label(dlg, text="监听端口:", bg="#1a1a2e", fg="#e0e0e0").pack(pady=5)
        pe = tk.Entry(dlg, bg="#16213e", fg="#e0e0e0");
        pe.insert(0, "25581");
        pe.pack()
        tk.Label(dlg, text="目标:", bg="#1a1a2e", fg="#e0e0e0").pack(py=5)
        te = tk.Entry(dlg, bg="#16213e", fg="#e0e0e0");
        te.insert(0, "127.0.0.1:25580");
        te.pack()

        def go():
            try:
                port = int(pe.get());
                h, p = te.get().split(":");
                p = int(p)
                cap = PacketCapture(port, h, p)
                cap.set_callback(lambda r: self.after(0, self.add_record, r))
                cap.start()
                messagebox.showinfo("代理启动", f"监听 0.0.0.0:{port}\n目标 {h}:{p}\n\n"
                                                f"将客户端连接到 localhost:{port}")
                dlg.destroy()
            except Exception as e:
                messagebox.showerror("错误", str(e))

        tk.Button(dlg, text="启动", command=go, bg="#0f3460", fg="#e0e0e0").pack(pady=10)

    def _toggle_pause(self):
        self._paused = not self._paused
        self._pause_btn.config(text="▶ 继续" if self._paused else "⏸ 暂停")

    def _clear(self):
        self._records.clear();
        self._filtered.clear();
        self._stats.clear()
        self._global_idx = 0
        self._tree.delete(*self._tree.get_children())
        self._detail.config(state=tk.NORMAL);
        self._detail.delete("1.0", tk.END)
        self._detail.config(state=tk.DISABLED)
        self._update_count();
        self._stats_canvas.delete("all")

    def _export(self):
        fp = filedialog.asksaveasfilename(defaultextension=".txt",
                                          filetypes=[("Text", "*.txt"), ("CSV", "*.csv")])
        if not fp: return
        recs = self._filtered or self._records
        with open(fp, "w", encoding="utf-8") as f:
            if fp.endswith(".csv"):
                f.write("序号,时间,方向,阶段,类型,类型码,大小,解码\n")
                for r in recs:
                    f.write(f'{r.index},{r.time_str},{r.direction},{r.phase},'
                            f'{r.type_name},0x{r.pkt_type:02X},{r.payload_size},'
                            f'"{r.decoded}"\n')
            else:
                for r in recs:
                    f.write(f"[{r.time_str}] {r.direction} | "
                            f"0x{r.pkt_type:02X} {r.type_name:<24s} | "
                            f"{r.payload_size:>5d}B | {r.decoded}\n")
        messagebox.showinfo("导出完成", f"{len(recs)} 条 → {fp}")


# ═══════════════════════════════════════════════════════════════
#  入口
# ═══════════════════════════════════════════════════════════════

def main():
    app = FluxProtocolAnalyzer()

    if "--log" in sys.argv:
        idx = sys.argv.index("--log")
        if idx + 1 < len(sys.argv):
            d = sys.argv[idx + 1]
            for r in EventLogParser.parse_directory(d):
                app.add_record(r)
    elif "--proxy" in sys.argv:
        idx = sys.argv.index("--proxy")
        if idx + 1 < len(sys.argv):
            port = int(sys.argv[idx + 1])
            cap = PacketCapture(port, "127.0.0.1", 25580)
            cap.set_callback(lambda r: app.after(0, app.add_record, r))
            cap.start()
    else:
        d = EventLogParser.find_log_dir()
        if d:
            for r in EventLogParser.parse_directory(d):
                app.add_record(r)
            app._status_lbl.config(text=f"📁 {d}", fg="#82E0AA")

    app.mainloop()


if __name__ == "__main__":
    main()