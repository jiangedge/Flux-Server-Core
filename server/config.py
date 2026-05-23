"""
Flux Server - 全局配置
Decentralized Minecraft Server - Hardware Validator
"""

# ─── 网络配置 ───
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 25580          # Flux 服务端口
MAX_CLIENTS = 16             # 最大同时连接数
CLIENT_TIMEOUT_SEC = 30      # 客户端超时（秒）

# ─── 协议常量 ───
PROTOCOL_MAGIC = 0x4658      # "FX" (Flux)
PROTOCOL_HEADER_SIZE = 7     # Magic(2) + Type(1) + Length(4) — 大端序
PROTOCOL_IV_SIZE = 12        # AES-GCM 初始化向量
PROTOCOL_GCM_TAG_SIZE = 16   # GCM 认证标签
PROTOCOL_SEQID_SIZE = 4      # 序列号（大端序）
MAX_PAYLOAD_SIZE = 512       # 最大载荷（不含 seq_id）
MAX_PACKET_SIZE = 567        # Header(7) + IV(12) + SeqID(4) + Payload(512) + Tag(16) + 余量

# ─── 加密配置 ───
ECDH_KEY_SIZE = 32           # Curve25519 私钥
ECDH_PUBKEY_SIZE = 32        # Curve25519 公钥
AES_KEY_SIZE = 16            # AES-128 密钥

# ─── 防作弊阈值 ───
MAX_SPEED_BLOCKS_PER_SEC = 10.0   # 最大速度 (m/s)
MAX_INTERACTION_DISTANCE = 6.0    # 最大交互距离 (格)
MAX_ATTACK_DISTANCE = 4.5         # 最大攻击距离 (格)
VIOLATION_FREEZE_COUNT = 3        # 连续违规 → 冻结
VIOLATION_KICK_COUNT = 5          # 累计违规 → 踢出
POSITION_UPDATE_INTERVAL_MS = 50  # 位置更新间隔

# ─── TTL 缓存 ───
TTL_VOLATILE_MS = 3000       # 坐标等瞬态数据
TTL_PERSISTENT_MS = 10000    # 方块变更等持久数据

# ─── 事件日志配置 ───
LOG_DIR = "./flux_data"
EVENT_LOG_DIR = "./flux_data/events"
EVENT_LOG_FILE = "./flux_data/events/events.bin"
WORLD_SEED_FILE = "./flux_data/seed.bin"
MAX_LOG_FILE_SIZE = 4 * 1024 * 1024  # 4MB/文件
LOG_FLUSH_INTERVAL_SEC = 5

# ─── 世界同步 ───
SYNC_BATCH_SIZE = 10         # 每批发送事件数
SYNC_BATCH_DELAY_MS = 1      # 批次间延迟

# ─── 心跳 ───
PING_INTERVAL_SEC = 5        # 心跳间隔
PING_TIMEOUT_SEC = 15        # 心跳超时
