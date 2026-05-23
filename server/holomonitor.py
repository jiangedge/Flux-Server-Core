#!/usr/bin/env python3
"""
Flux 监控面板 - GUI 版
功能：
  1. 实时服务器状态（连接数、运行时间、客户端列表）
  2. 历史事件日志回放（带筛选、搜索）
  3. 实时事件流（新事件实时刷新）
  4. 事件详情查看

依赖：仅 Python 标准库（tkinter），无需额外安装
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import struct
import os
import time
import hashlib
import threading
import socket
import json
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional


# ═══════════════════════════════════════════════════════════════
#  数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class EventEntry:
    index: int
    timestamp_ms: int
    client_id: int
    event_type: int
    data: bytes
    hash: bytes

    @property
    def time_str(self) -> str:
        ts = self.timestamp_ms / 1000.0
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    @property
    def type_name(self) -> str:
        names = {
            0x20: "PLAYER_MOVE",
            0x21: "BLOCK_BREAK",
            0x22: "BLOCK_PLACE",
            0x23: "ENTITY_INTERACT",
            0x24: "INVENTORY_CHANGE",
            0x25: "CHEST_OPEN",
            0x26: "CHEST_MODIFY",
            0x27: "CHUNK_TRANSFER",
        }
        return names.get(self.event_type, f"UNKNOWN(0x{self.event_type:02X})")

    @property
    def detail(self) -> str:
        """解析载荷为可读文本"""
        try:
            if self.event_type == 0x20 and len(self.data) >= 21:
                seq, x, y, z, yaw, pitch, on_ground = struct.unpack(
                    "<IfffffB", self.data[:21])
                return f"pos=({x:.1f}, {y:.1f}, {z:.1f}) yaw={yaw:.1f} pitch={pitch:.1f}"

            elif self.event_type == 0x21 and len(self.data) >= 18:
                seq, x, y, z, block_id, face = struct.unpack(
                    "<IiiiBB", self.data[:18])
                return f"block=({x}, {y}, {z}) id={block_id} face={face}"

            elif self.event_type == 0x22 and len(self.data) >= 30:
                seq, x, y, z, block_id, face, hx, hy, hz = struct.unpack(
                    "<IiiiBBfff", self.data[:30])
                return f"block=({x}, {y}, {z}) id={block_id} hit=({hx:.2f},{hy:.2f},{hz:.2f})"

            elif self.event_type == 0x23 and len(self.data) >= 21:
                seq, eid, action, px, py, pz = struct.unpack(
                    "<IIBfff", self.data[:21])
                act = "attack" if action == 0 else "interact"
                return f"entity={eid} action={act} pos=({px:.1f},{py:.1f},{pz:.1f})"

            elif self.event_type == 0x24 and len(self.data) >= 9:
                seq, slot, item_id, count, action = struct.unpack(
                    "<IBHBB", self.data[:9])
                act = {0: "pickup", 1: "drop", 2: "swap"}.get(action, str(action))
                return f"slot={slot} item={item_id} x{count} {act}"

            elif self.event_type == 0x26 and len(self.data) >= 20:
                seq, x, y, z, slot, item_id, count = struct.unpack(
                    "<IiiiBHB", self.data[:20])
                return f"chest=({x},{y},{z}) slot={slot} item={item_id} x{count}"

            elif self.event_type == 0x27 and len(self.data) >= 37:
                seq, eid, x, y, z, vx, vy, vz, etype, hp = struct.unpack(
                    "<IIffffffBf", self.data[:37])
                return f"entity={eid} pos=({x:.1f},{y:.1f},{z:.1f}) hp={hp:.1f}"

        except Exception:
            pass
        return f"raw({len(self.data)}B): {self.data[:32].hex()}{'...' if len(self.data) > 32 else ''}"

    @property
    def hash_hex(self) -> str:
        return self.hash.hex()[:16] + "..."


# ═══════════════════════════════════════════════════════════════
#  事件日志读取器
# ═══════════════════════════════════════════════════════════════

class EventLogReader:
    HEADER_FORMAT = "<IBBH"
    HEADER_SIZE = 8

    def __init__(self, log_dir: str = "./flux_data/events"):
        self.log_dir = log_dir

    def load_all_events(self) -> List[EventEntry]:
        events = []
        if not os.path.exists(self.log_dir):
            return events

        index = 0
        file_idx = 0
        while True:
            filepath = os.path.join(self.log_dir, f"events_{file_idx:04d}.bin")
            if not os.path.exists(filepath):
                break
            events.extend(self._load_file(filepath, index))
            index = len(events)
            file_idx += 1

        return events

    def _load_file(self, filepath: str, start_index: int) -> List[EventEntry]:
        events = []
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
        except Exception:
            return events

        offset = 0
        idx = start_index
        while offset + self.HEADER_SIZE <= len(data):
            ts, cid, etype, dlen = struct.unpack(
                self.HEADER_FORMAT, data[offset:offset + self.HEADER_SIZE])
            entry_size = self.HEADER_SIZE + dlen + 32
            if offset + entry_size > len(data):
                break

            ev_data = data[offset + self.HEADER_SIZE:offset + self.HEADER_SIZE + dlen]
            ev_hash = data[offset + self.HEADER_SIZE + dlen:offset + entry_size]

            events.append(EventEntry(
                index=idx, timestamp_ms=ts, client_id=cid,
                event_type=etype, data=ev_data, hash=ev_hash
            ))
            offset += entry_size
            idx += 1

        return events


# ═══════════════════════════════════════════════════════════════
#  监控数据采集（通过 UDP 查询服务端）
# ═══════════════════════════════════════════════════════════════

class ServerMonitor:
    """通过 TCP 连接到服务端获取状态（需要服务端支持监控接口）"""

    def __init__(self, host: str = "127.0.0.1", port: int = 25580):
        self.host = host
        self.port = port
        self._last_status = {}

    def get_status(self) -> dict:
        """尝试连接服务端获取状态"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.host, self.port))
            # 发送一个空包探测（服务端会因解密失败而忽略）
            # 实际状态通过读取日志文件获取
            sock.close()
            self._last_status["server_online"] = True
        except Exception:
            self._last_status["server_online"] = False

        # 从日志目录推断状态
        data_dir = Path("./flux_data")
        if data_dir.exists():
            events_dir = data_dir / "events"
            if events_dir.exists():
                event_files = list(events_dir.glob("events_*.bin"))
                total_size = sum(f.stat().st_size for f in event_files)
                self._last_status["event_files"] = len(event_files)
                self._last_status["total_log_size"] = total_size

            seed_file = data_dir / "seed.bin"
            if seed_file.exists():
                try:
                    with open(seed_file, 'rb') as f:
                        seed = struct.unpack("<q", f.read(8))[0]
                    self._last_status["world_seed"] = seed
                except Exception:
                    pass

        return self._last_status


# ═══════════════════════════════════════════════════════════════
#  GUI 主界面
# ═══════════════════════════════════════════════════════════════

class FluxMonitor:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Flux 监控面板")
        self.root.geometry("1200x700")
        self.root.minsize(900, 500)

        # 数据
        self.events: List[EventEntry] = []
        self.filtered_events: List[EventEntry] = []
        self.log_reader = EventLogReader()
        self.monitor = ServerMonitor()
        self.auto_refresh = True

        # 样式
        self._setup_styles()

        # 布局
        self._build_ui()

        # 初始加载
        self._load_events()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        # 自定义颜色
        self.BG = "#1e1e2e"
        self.BG_CARD = "#2a2a3e"
        self.FG = "#cdd6f4"
        self.ACCENT = "#89b4fa"
        self.GREEN = "#a6e3a1"
        self.RED = "#f38ba8"
        self.YELLOW = "#f9e2af"
        self.BORDER = "#45475a"

        self.root.configure(bg=self.BG)

        style.configure("Card.TFrame", background=self.BG_CARD)
        style.configure("Bg.TFrame", background=self.BG)
        style.configure("Title.TLabel", background=self.BG, foreground=self.ACCENT,
                         font=("Consolas", 14, "bold"))
        style.configure("CardTitle.TLabel", background=self.BG_CARD, foreground=self.ACCENT,
                         font=("Consolas", 11, "bold"))
        style.configure("Card.TLabel", background=self.BG_CARD, foreground=self.FG,
                         font=("Consolas", 10))
        style.configure("Status.TLabel", background=self.BG_CARD, foreground=self.GREEN,
                         font=("Consolas", 10, "bold"))
        style.configure("Warn.TLabel", background=self.BG_CARD, foreground=self.YELLOW,
                         font=("Consolas", 10, "bold"))
        style.configure("Error.TLabel", background=self.BG_CARD, foreground=self.RED,
                         font=("Consolas", 10, "bold"))
        style.configure("Accent.TButton", background=self.ACCENT, foreground=self.BG,
                         font=("Consolas", 10, "bold"))
        style.configure("Treeview", background=self.BG_CARD, foreground=self.FG,
                         fieldbackground=self.BG_CARD, font=("Consolas", 9),
                         rowheight=24)
        style.configure("Treeview.Heading", background=self.BORDER, foreground=self.ACCENT,
                         font=("Consolas", 9, "bold"))
        style.map("Treeview", background=[("selected", self.ACCENT)],
                  foreground=[("selected", self.BG)])

    def _build_ui(self):
        # ─── 顶部标题栏 ───
        top = ttk.Frame(self.root, style="Bg.TFrame")
        top.pack(fill=tk.X, padx=10, pady=(10, 5))

        ttk.Label(top, text="⬡ Flux 监控面板", style="Title.TFrame").pack(side=tk.LEFT)

        # 右侧按钮
        btn_frame = ttk.Frame(top, style="Bg.TFrame")
        btn_frame.pack(side=tk.RIGHT)

        self.btn_refresh = tk.Button(btn_frame, text="⟳ 刷新", command=self._load_events,
                                     bg=self.ACCENT, fg=self.BG, font=("Consolas", 10, "bold"),
                                     relief=tk.FLAT, padx=12, cursor="hand2")
        self.btn_refresh.pack(side=tk.LEFT, padx=4)

        self.btn_export = tk.Button(btn_frame, text="↓ 导出CSV", command=self._export_csv,
                                    bg=self.BORDER, fg=self.FG, font=("Consolas", 10),
                                    relief=tk.FLAT, padx=12, cursor="hand2")
        self.btn_export.pack(side=tk.LEFT, padx=4)

        # ─── 状态卡片 ───
        status_frame = ttk.Frame(self.root, style="Bg.TFrame")
        status_frame.pack(fill=tk.X, padx=10, pady=5)

        self._status_cards = {}
        cards = [
            ("服务器状态", "server_status", "检测中..."),
            ("世界种子", "world_seed", "--"),
            ("事件总数", "event_count", "0"),
            ("日志文件", "log_files", "0"),
            ("日志大小", "log_size", "0 B"),
            ("哈希链", "hash_chain", "检测中..."),
        ]
        for i, (title, key, default) in enumerate(cards):
            card = ttk.Frame(status_frame, style="Card.TFrame")
            card.grid(row=0, column=i, padx=4, pady=4, sticky="nsew")
            status_frame.columnconfigure(i, weight=1)

            ttk.Label(card, text=title, style="CardTitle.TLabel").pack(padx=10, pady=(8, 2))
            lbl = ttk.Label(card, text=default, style="Card.TLabel")
            lbl.pack(padx=10, pady=(2, 8))
            self._status_cards[key] = lbl

        # ─── 筛选栏 ───
        filter_frame = ttk.Frame(self.root, style="Bg.TFrame")
        filter_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(filter_frame, text="事件类型:", style="Card.TLabel",
                  background=self.BG).pack(side=tk.LEFT, padx=(0, 5))

        self.filter_type = ttk.Combobox(filter_frame, width=20, state="readonly",
                                        font=("Consolas", 9))
        self.filter_type["values"] = ["全部", "PLAYER_MOVE", "BLOCK_BREAK", "BLOCK_PLACE",
                                       "ENTITY_INTERACT", "INVENTORY_CHANGE", "CHEST_MODIFY",
                                       "CHUNK_TRANSFER"]
        self.filter_type.set("全部")
        self.filter_type.pack(side=tk.LEFT, padx=4)
        self.filter_type.bind("<<ComboboxSelected>>", lambda e: self._apply_filter())

        ttk.Label(filter_frame, text="客户端:", style="Card.TLabel",
                  background=self.BG).pack(side=tk.LEFT, padx=(20, 5))

        self.filter_client = ttk.Combobox(filter_frame, width=10, state="readonly",
                                          font=("Consolas", 9))
        self.filter_client["values"] = ["全部"]
        self.filter_client.set("全部")
        self.filter_client.pack(side=tk.LEFT, padx=4)
        self.filter_client.bind("<<ComboboxSelected>>", lambda e: self._apply_filter())

        ttk.Label(filter_frame, text="搜索:", style="Card.TLabel",
                  background=self.BG).pack(side=tk.LEFT, padx=(20, 5))

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._apply_filter())
        search_entry = tk.Entry(filter_frame, textvariable=self.search_var,
                                bg=self.BG_CARD, fg=self.FG, insertbackground=self.FG,
                                font=("Consolas", 10), relief=tk.FLAT, width=30)
        search_entry.pack(side=tk.LEFT, padx=4, ipady=3)

        self.lbl_count = ttk.Label(filter_frame, text="显示: 0 / 0", style="Card.TLabel",
                                   background=self.BG)
        self.lbl_count.pack(side=tk.RIGHT, padx=10)

        # ─── 事件列表 + 详情（左右分栏）───
        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 10))

        # 左侧：事件列表
        left = ttk.Frame(paned, style="Bg.TFrame")
        paned.add(left, weight=3)

        cols = ("序号", "时间", "客户端", "事件类型", "详情")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="browse")

        self.tree.heading("序号", text="#")
        self.tree.heading("时间", text="时间")
        self.tree.heading("客户端", text="客户端")
        self.tree.heading("事件类型", text="事件类型")
        self.tree.heading("详情", text="详情")

        self.tree.column("序号", width=50, minwidth=40)
        self.tree.column("时间", width=160, minwidth=120)
        self.tree.column("客户端", width=60, minwidth=50)
        self.tree.column("事件类型", width=140, minwidth=100)
        self.tree.column("详情", width=400, minwidth=200)

        scrollbar = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # 右侧：详情面板
        right = ttk.Frame(paned, style="Bg.TFrame")
        paned.add(right, weight=2)

        ttk.Label(right, text="事件详情", style="Title.TFrame").pack(anchor=tk.W, pady=(0, 5))

        self.detail_text = tk.Text(right, bg=self.BG_CARD, fg=self.FG,
                                   font=("Consolas", 10), relief=tk.FLAT,
                                   insertbackground=self.FG, wrap=tk.WORD,
                                   state=tk.DISABLED)
        self.detail_text.pack(fill=tk.BOTH, expand=True)

        # 事件类型颜色标签
        self.tree.tag_configure("move", foreground="#89b4fa")
        self.tree.tag_configure("break", foreground="#f38ba8")
        self.tree.tag_configure("place", foreground="#a6e3a1")
        self.tree.tag_configure("interact", foreground="#f9e2af")
        self.tree.tag_configure("inventory", foreground="#cba6f7")
        self.tree.tag_configure("other", foreground="#9399b2")

    # ─────────────────────────────────────────────────────────
    #  数据加载
    # ─────────────────────────────────────────────────────────

    def _load_events(self):
        """加载所有事件日志"""
        self.events = self.log_reader.load_all_events()
        self._update_status()
        self._apply_filter()

    def _update_status(self):
        """更新状态卡片"""
        # 服务器状态
        status = self.monitor.get_status()
        if status.get("server_online"):
            self._status_cards["server_status"].configure(text="● 在线", style="Status.TLabel")
        else:
            self._status_cards["server_status"].configure(text="○ 离线", style="Error.TLabel")

        # 世界种子
        seed = status.get("world_seed")
        if seed is not None:
            self._status_cards["world_seed"].configure(text=str(seed))
        else:
            self._status_cards["world_seed"].configure(text="--")

        # 事件总数
        self._status_cards["event_count"].configure(text=str(len(self.events)))

        # 日志文件
        self._status_cards["log_files"].configure(text=str(status.get("event_files", 0)))

        # 日志大小
        size = status.get("total_log_size", 0)
        if size > 1024 * 1024:
            size_str = f"{size / 1024 / 1024:.1f} MB"
        elif size > 1024:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size} B"
        self._status_cards["log_size"].configure(text=size_str)

        # 哈希链验证
        if self.events:
            valid = self._verify_hash_chain()
            if valid:
                self._status_cards["hash_chain"].configure(
                    text="✓ 完整", style="Status.TLabel")
            else:
                self._status_cards["hash_chain"].configure(
                    text="✗ 损坏", style="Error.TLabel")
        else:
            self._status_cards["hash_chain"].configure(text="无数据", style="Warn.TLabel")

        # 更新客户端筛选器
        client_ids = sorted(set(e.client_id for e in self.events))
        self.filter_client["values"] = ["全部"] + [str(cid) for cid in client_ids]

    def _verify_hash_chain(self) -> bool:
        """验证哈希链完整性"""
        prev_hash = b'\x00' * 32
        header_fmt = "<IBBH"
        for event in self.events:
            header = struct.pack(header_fmt,
                                 event.timestamp_ms, event.client_id,
                                 event.event_type, len(event.data))
            h = hashlib.sha256()
            h.update(prev_hash)
            h.update(header)
            h.update(event.data)
            expected = h.digest()
            if event.hash != expected:
                return False
            prev_hash = event.hash
        return True

    # ─────────────────────────────────────────────────────────
    #  筛选与显示
    # ─────────────────────────────────────────────────────────

    def _apply_filter(self):
        """应用筛选条件"""
        type_filter = self.filter_type.get()
        client_filter = self.filter_client.get()
        search = self.search_var.get().strip().lower()

        self.filtered_events = []
        for e in self.events:
            # 类型筛选
            if type_filter != "全部" and e.type_name != type_filter:
                continue
            # 客户端筛选
            if client_filter != "全部" and str(e.client_id) != client_filter:
                continue
            # 搜索
            if search and search not in e.detail.lower() and search not in e.type_name.lower():
                continue
            self.filtered_events.append(e)

        self._refresh_tree()

    def _refresh_tree(self):
        """刷新事件列表"""
        self.tree.delete(*self.tree.get_children())

        # 只显示最后 5000 条（避免卡顿）
        display = self.filtered_events[-5000:]

        for e in display:
            # 选择颜色标签
            tag = "other"
            if e.event_type == 0x20:
                tag = "move"
            elif e.event_type in (0x21,):
                tag = "break"
            elif e.event_type in (0x22,):
                tag = "place"
            elif e.event_type in (0x23,):
                tag = "interact"
            elif e.event_type in (0x24, 0x26):
                tag = "inventory"

            self.tree.insert("", tk.END, iid=str(e.index), values=(
                e.index, e.time_str, e.client_id, e.type_name, e.detail
            ), tags=(tag,))

        # 自动滚动到底部
        children = self.tree.get_children()
        if children:
            self.tree.see(children[-1])
            self.tree.selection_set(children[-1])

        self.lbl_count.configure(
            text=f"显示: {len(display)} / {len(self.filtered_events)}")

    def _on_select(self, event):
        """选中事件时显示详情"""
        sel = self.tree.selection()
        if not sel:
            return

        idx = int(sel[0])
        if idx >= len(self.events):
            return

        e = self.events[idx]

        detail = f"""═══ 事件 #{e.index} ═══

时间戳:    {e.time_str}
原始时间戳: {e.timestamp_ms} ms
客户端 ID:  {e.client_id}
事件类型:   {e.type_name} (0x{e.event_type:02X})
数据长度:   {len(e.data)} 字节

─── 解析内容 ───
{e.detail}

─── 原始数据 (Hex) ───
{self._hex_dump(e.data)}

─── 哈希链 ───
SHA-256: {e.hash.hex()}
"""

        self.detail_text.configure(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert("1.0", detail)
        self.detail_text.configure(state=tk.DISABLED)

    def _hex_dump(self, data: bytes) -> str:
        """格式化十六进制输出"""
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"  {i:04X}  {hex_part:<48s}  {ascii_part}")
        return "\n".join(lines)

    # ─────────────────────────────────────────────────────────
    #  导出
    # ─────────────────────────────────────────────────────────

    def _export_csv(self):
        """导出筛选后的事件为 CSV"""
        if not self.filtered_events:
            messagebox.showinfo("导出", "没有可导出的事件")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV 文件", "*.csv"), ("所有文件", "*.*")],
            initialfile=f"flux_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        if not filepath:
            return

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("序号,时间戳,客户端ID,事件类型,详情,哈希\n")
                for e in self.filtered_events:
                    detail = e.detail.replace('"', '""')
                    f.write(f'{e.index},"{e.time_str}",{e.client_id},'
                            f'{e.type_name},"{detail}",{e.hash_hex}\n')
            messagebox.showinfo("导出成功", f"已导出 {len(self.filtered_events)} 条事件到:\n{filepath}")
        except Exception as ex:
            messagebox.showerror("导出失败", str(ex))

    # ─────────────────────────────────────────────────────────
    #  运行
    # ─────────────────────────────────────────────────────────

    def run(self):
        self.root.mainloop()


# ═══════════════════════════════════════════════════════════════
#  入口
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = FluxMonitor()
    app.run()
