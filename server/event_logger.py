"""
Flux Server - 事件日志引擎
事件溯源 + SHA-256 哈希链防篡改
"""

import os
import struct
import time
import hashlib
import logging
from dataclasses import dataclass
from typing import Optional, List
from pathlib import Path

from config import (
    LOG_DIR, EVENT_LOG_DIR, EVENT_LOG_FILE,
    WORLD_SEED_FILE, MAX_LOG_FILE_SIZE
)

logger = logging.getLogger("flux.logger")


@dataclass
class EventEntry:
    """事件日志条目，与 ESP32 固件的 sd_event_entry_t 对齐"""
    timestamp_ms: int = 0
    client_id: int = 0
    event_type: int = 0
    data: bytes = b''
    hash: bytes = b'\x00' * 32

    # 序列化格式: timestamp(4) + client_id(1) + event_type(1) + data_len(2) + data(N) + hash(32)
    HEADER_FORMAT = "<IBBH"
    HEADER_SIZE = 8  # 4+1+1+2

    def pack(self, prev_hash: bytes = b'\x00' * 32) -> bytes:
        """序列化并计算哈希"""
        self.timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF

        header = struct.pack(self.HEADER_FORMAT,
                             self.timestamp_ms, self.client_id,
                             self.event_type, len(self.data))

        # 计算哈希链: SHA-256(prev_hash || header || data)
        h = hashlib.sha256()
        h.update(prev_hash)
        h.update(header)
        h.update(self.data)
        self.hash = h.digest()

        return header + self.data + self.hash

    @classmethod
    def unpack(cls, data: bytes) -> Optional['EventEntry']:
        if len(data) < cls.HEADER_SIZE + 32:
            return None
        ts, cid, etype, dlen = struct.unpack(cls.HEADER_FORMAT, data[:cls.HEADER_SIZE])
        ev_data = data[cls.HEADER_SIZE:cls.HEADER_SIZE + dlen]
        ev_hash = data[cls.HEADER_SIZE + dlen:cls.HEADER_SIZE + dlen + 32]
        return cls(timestamp_ms=ts, client_id=cid, event_type=etype,
                   data=ev_data, hash=ev_hash)

    @property
    def packed_size(self) -> int:
        return self.HEADER_SIZE + len(self.data) + 32


class EventLogger:
    """事件日志管理器"""

    def __init__(self):
        self._events: List[EventEntry] = []
        self._last_hash: bytes = b'\x00' * 32
        self._current_file_index: int = 0
        self._current_file_size: int = 0
        self._world_seed: int = 0
        self._flush_pending: bool = False

    def init(self) -> bool:
        """初始化日志目录，加载已有日志"""
        try:
            Path(EVENT_LOG_DIR).mkdir(parents=True, exist_ok=True)
            logger.info(f"Event log directory: {EVENT_LOG_DIR}")

            # 加载世界种子
            self._load_seed()

            # 加载已有事件日志
            self._load_events()

            logger.info(f"Loaded {len(self._events)} events, "
                        f"world seed={self._world_seed}")
            return True
        except Exception as e:
            logger.error(f"Failed to init event logger: {e}")
            return False

    def _load_seed(self):
        """加载世界种子"""
        if os.path.exists(WORLD_SEED_FILE):
            with open(WORLD_SEED_FILE, 'rb') as f:
                data = f.read(8)
                if len(data) == 8:
                    self._world_seed = struct.unpack("<q", data)[0]
        else:
            # 生成随机种子
            self._world_seed = int.from_bytes(os.urandom(8), 'little', signed=True)
            self._save_seed()

    def _save_seed(self):
        with open(WORLD_SEED_FILE, 'wb') as f:
            f.write(struct.pack("<q", self._world_seed))

    def _load_events(self):
        """从磁盘加载所有事件日志"""
        self._events.clear()
        self._last_hash = b'\x00' * 32

        # 扫描所有 events_XXXX.bin 文件
        index = 0
        while True:
            filepath = os.path.join(EVENT_LOG_DIR, f"events_{index:04d}.bin")
            if not os.path.exists(filepath):
                break
            self._load_event_file(filepath)
            index += 1

        self._current_file_index = index
        self._current_file_size = 0
        if self._events:
            last = self._events[-1]
            self._current_file_size = last.packed_size

    def _load_event_file(self, filepath: str):
        """从单个文件加载事件"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            offset = 0
            while offset < len(data):
                # 读取 header 获取 data_len
                if offset + EventEntry.HEADER_SIZE > len(data):
                    break
                _, _, _, dlen = struct.unpack(
                    EventEntry.HEADER_FORMAT,
                    data[offset:offset + EventEntry.HEADER_SIZE])
                entry_size = EventEntry.HEADER_SIZE + dlen + 32
                if offset + entry_size > len(data):
                    break

                entry = EventEntry.unpack(data[offset:offset + entry_size])
                if entry:
                    # 验证哈希链
                    expected_hash = self._compute_hash(self._last_hash, entry)
                    if entry.hash != expected_hash:
                        logger.warning(
                            f"Hash chain broken at event {len(self._events)}!")
                    self._events.append(entry)
                    self._last_hash = entry.hash
                offset += entry_size
        except Exception as e:
            logger.error(f"Failed to load {filepath}: {e}")

    @staticmethod
    def _compute_hash(prev_hash: bytes, entry: EventEntry) -> bytes:
        h = hashlib.sha256()
        h.update(prev_hash)
        header = struct.pack(EventEntry.HEADER_FORMAT,
                             entry.timestamp_ms, entry.client_id,
                             entry.event_type, len(entry.data))
        h.update(header)
        h.update(entry.data)
        return h.digest()

    def log_event(self, client_id: int, event_type: int, data: bytes) -> int:
        """
        记录一个事件。
        返回事件序号。
        """
        entry = EventEntry(
            client_id=client_id,
            event_type=event_type,
            data=data
        )
        packed = entry.pack(self._last_hash)
        self._events.append(entry)
        self._last_hash = entry.hash

        # 写入文件
        self._append_to_file(packed)

        logger.debug(f"Logged event #{len(self)-1}: "
                     f"type=0x{event_type:02X}, client={client_id}, "
                     f"data_len={len(data)}")
        return len(self._events) - 1

    def _append_to_file(self, packed: bytes):
        """追加写入当前日志文件"""
        filepath = os.path.join(
            EVENT_LOG_DIR,
            f"events_{self._current_file_index:04d}.bin")

        if self._current_file_size + len(packed) > MAX_LOG_FILE_SIZE:
            self._current_file_index += 1
            self._current_file_size = 0
            filepath = os.path.join(
                EVENT_LOG_DIR,
                f"events_{self._current_file_index:04d}.bin")

        with open(filepath, 'ab') as f:
            f.write(packed)
        self._current_file_size += len(packed)

    def get_world_seed(self) -> int:
        return self._world_seed

    def set_world_seed(self, seed: int):
        self._world_seed = seed
        self._save_seed()

    def get_events_since(self, index: int = 0) -> List[EventEntry]:
        """获取从 index 开始的所有事件"""
        return self._events[index:]

    def get_event_count(self) -> int:
        return len(self._events)

    def __len__(self) -> int:
        return len(self._events)
