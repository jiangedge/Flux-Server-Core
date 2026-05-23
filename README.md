# Flux — 去中心化 Minecraft 联机方案

> **Synergyedge Team**
> 版本：v0.1.0
项⽬详细介绍

## Flux

去中⼼化 联机⽅案

## Flux — Minecraft

Synergyedge Team
版本：v0.1.0
⽬录
1. 项⽬简介
2. 设计哲学
3. 系统架构
4. 核⼼模块
5. ⼆进制协议规范
6. 加密与安全机制
7. 防作弊规则
8. 世界同步机制
9. 数据流详解
10. 项⽬⽂件清单
11. 部署指南
12. 监控与运维
13. FAQ
项⽬简介
1.
什么是
1.1 Flux

## Flux 是⼀个创新性的 Minecraft 去中⼼化联机⽅案。

传统 Minecraft 联机需要⼀台⾼性能服务器运⾏完整的游戏服务端（Java Edition Server），消

## 耗⼤量 CPU 和内存资源。Flux 的思路完全不同：

玩家⾃⼰的电脑承担 100% 的游戏逻辑计算，服务端只做"裁判"。
服务端不运⾏游戏引擎，不模拟世界，只负责：
验证每个玩家的操作是否合法（防作弊）
在玩家之间转发合法的操作（⼴播）
记录事件⽇志（⽤于新玩家加⼊时的世界还原）

---

与传统⽅案的对⽐
1.2

## 指标 官⽅ Java 服务端 Flux

内存占⽤ 2-4 GB < 50 MB
CPU 使⽤ 单核满载（游戏逻辑） ⼏乎为零（仅校验和转发）
硬件成本 ⾼性能服务器 / 云主机 任意电脑 / 树莓派
最⼤玩家数 受限于服务器算⼒ 理论⽆上限
游戏体验 取决于服务器延迟 取决于玩家本地性能
世界归属 服务端拥有世界 玩家共同拥有世界
核⼼优势
1.3
极低资源消耗：服务端只做数据包校验和转发，不需要运⾏游戏引擎
去中⼼化：没有"管理员"可以作弊，规则由代码强制执⾏
低成本：任意⼀台电脑即可运⾏，不需要⾼配服务器
可审计：所有事件记录在⽇志中，哈希链防篡改，可追溯任何操作

## 隐私保护：端到端加密，服务端看不到玩家的明⽂数据


## 设计哲学

2.
服务端是裁判，不是世界
2.1
传统 Minecraft 服务端的职责：
物理引擎 + AI 寻路 + 世界生成 + 区块管理 + 网络通信 + 反作弊

## Flux 服务端的职责：


## 加密/解密 + 数据包合法性校验 + 广播转发 + 事件日志

服务端不知道"钻⽯矿⻓什么样"，不知道"僵⼫怎么⾛路"，它只知道：
这个玩家移动速度是否超过 10 m/s？
这个玩家攻击距离是否超过 4.5 格？
这个⽅块操作是否符合因果关系？
四条铁律
2.2

## Flux 的防作弊不依赖复杂的游戏逻辑，只检查四条不可违反的物理边界：


---

1. 速度不能超限 — 正常疾跑 ~5.6 m/s，硬上限 10 m/s
2. 距离不能超标 — 攻击距离 > 4.5 格、交互距离 > 6 格 → 直接拒绝
3. 物品必须守恒 — 从箱⼦⾥拿东西，箱⼦⾥要真的有
4. 事件必须有因 — 说挖了钻⽯矿，坐标上要有钻⽯矿
影⼦⻅证⼈
2.3
当⼀个区块只有单个玩家时，他可以肆⽆忌惮地修改客⼾端。解决办法：
只要附近有第⼆个玩家 B，A 发送的每⼀个涉及实体的数据包，不仅服务端⾃⼰校验，还
会转发给 B。B 的客⼾端在后台并⾏运⾏相同规则，如果 B 的计算结果和 A 的不⼀致，服
务端就触发仲裁。

## 系统架构

3.

## 整体架构

3.1
┌─────────────────────────────────────────────────────────────┐
│ 玩家电脑 A │
│ ┌──────────────┐ ┌──────────────┐ ┌───────────────┐ │
│ │ Minecraft │───>│ Fabric Mod │───>│ TCP Client │ │

## │ │ 游戏客户端 │<───│ (事件拦截) │<───│ (加密/解密) │ │

│ └──────────────┘ └──────────────┘ └───────┬───────┘ │
│ │ TCP │
└───────────────────────────────────────────────────┼──────────┘
│
┌─────────▼─────────┐

## │ Flux Server │

│ (Python / PC) │
│ │
│ • ECDH 密钥协商 │

## │ • AES-128-GCM 加密 │

│ • 数据包合法性校验 │
│ • 区块所有权追踪 │
│ • 事件日志记录 │
│ • 盲转发广播 │
└─────────┬─────────┘
│ TCP
┌───────────────────────────────────────────────────┼──────────┐
│ 玩家电脑 B │ │
│ ┌──────────────┐ ┌──────────────┐ ┌───────▼───────┐ │
│ │ Minecraft │<───│ Fabric Mod │<───│ TCP Client │ │

## │ │ 游戏客户端 │───>│ (事件拦截) │───>│ (加密/解密) │ │

│ └──────────────┘ └──────────────┘ └───────────────┘ │
└─────────────────────────────────────────────────────────────┘

---

数据流
3.2
玩家操作（移动/破坏/放置/攻击）
│
▼
Fabric Mod 拦截事件
│
▼

## 编码为二进制协议包（小端序，紧凑格式）

│
▼

## AES-128-GCM 加密（ECDH 协商的会话密钥）

│
▼

## TCP 发送到 Flux 服务端

│
▼
服务端解密 + GCM 标签验证 + SeqID 防重放
│
▼
包校验器检查四条铁律
│

## ├─ 合法 → 记录事件日志 → 加密广播给其他玩家

│
└─ 非法 → 丢弃 + 回滚/冻结/踢出
启动时序
3.3
服务端启动
│
├─ [1] 生成 ECDH 密钥对
├─ [2] 加载事件日志 + 世界种子
├─ [3] 启动 TCP 监听
└─ [4] 等待客户端连接
客户端连接
│
├─ [1] TCP 连接建立
├─ [2] CLIENT_HELLO → 客户端发送 ECDH 公钥
├─ [3] SERVER_HELLO → 服务端发送 ECDH 公钥
├─ [4] 双方独立派生 AES-128 会话密钥
├─ [5] AUTH_REQUEST → 客户端发送 UUID + 用户名
├─ [6] AUTH_SUCCESS → 认证通过
├─ [7] WORLD_SEED → 服务端下发世界种子
├─ [8] EVENT_LOG_ENTRY × N → 回放历史事件

## ├─ [9] SYNC_COMPLETE → 同步完成

└─ [10] 进入 ACTIVE 状态，开始游戏

---


## 核⼼模块

4.

## 模块总览

4.1

## Flux-server/ ← 服务端（Python）

├── config.py ← 全局配置

## ├── protocol.py ← 二进制协议层

├── crypto_engine.py ← ECDH + AES-128-GCM
├── packet_validator.py ← 防作弊校验器
├── event_logger.py ← 事件日志 + 哈希链
├── relay_engine.py ← 中继引擎 + 区块所有权
├── server.py ← TCP 服务主逻辑
└── main.py ← 入口

## Flux-fabric-mod/ ← 客户端（Java / Fabric Mod）


## ├── FluxClient.java ← 主入口


## ├── FluxConfig.java ← 配置


## ├── crypto/CryptoEngine.java ← 加密引擎


## ├── protocol/Protocol.java ← 协议常量

├── protocol/PacketBuilder.java ← 包构建器
├── network/NetworkClient.java ← TCP 客户端
├── mod/EventInterceptor.java ← 事件拦截器
├── mod/FabricEventRegistrar.java ← Fabric 事件注册
├── world/BroadcastHandler.java ← 广播包处理
└── mixin/*.java ← Mixin 注入

## Fluxmonitor.py ← 监控面板（Python / GUI）


## 加密引擎

4.2 (crypto_engine)
职责：密钥协商 + 数据加解密
算法：
密钥协商：ECDH (X25519 / Curve25519)

## 对称加密：AES-128-GCM（认证加密）

密钥派⽣：SHA-256(shared_secret) → 取前 16 字节

## 流程：

双方各自生成临时密钥对
→ 交换公钥
→ 各自计算共享密钥（结果相同）
→ SHA-256 哈希取前 16 字节 → AES-128 会话密钥

## → 所有后续通信使用此密钥加密

→ 断开连接 → 密钥销毁（仅存于内存，不落盘）

---

安全特性：
前向安全：每次连接使⽤全新临时密钥，即使⻓期密钥泄露也⽆法解密历史通信

## 认证加密：AES-GCM 同时提供保密性和完整性，任何篡改都会被检测

防重放：每个包携带递增的 SeqID，拒绝重复或乱序的包

## ⼆进制协议层

4.3 (protocol)
职责：定义所有数据包的格式、编解码

## 设计原则：

极致紧凑：移动包仅 59 字节（官⽅ ~200+ 字节）

## ⼩端序：与 C 结构体 __attribute__((packed)) 直接对应


## 强类型：每种包类型有固定的载荷结构

包类型⼀览：
类别 类型码 名称 ⽅向 载荷⼤⼩
握⼿ 0x01 CLIENT_HELLO 客⼾端→服务端 32B (公钥)
握⼿ 0x02 SERVER_HELLO 服务端→客⼾端 32B (公钥)
握⼿ 0x03 AUTH_REQUEST 客⼾端→服务端 32B (UUID+⽤⼾名)
握⼿ 0x04 AUTH_SUCCESS 服务端→客⼾端 0B

## 同步 0x10 WORLD_SEED 服务端→客⼾端 8B (种⼦)


## 同步 0x11 EVENT_LOG_ENTRY 服务端→客⼾端 可变


## 同步 0x12 SYNC_COMPLETE 服务端→客⼾端 0B

游戏 0x20 PLAYER_MOVE 客⼾端→服务端 25B
游戏 0x21 BLOCK_BREAK 客⼾端→服务端 18B
游戏 0x22 BLOCK_PLACE 客⼾端→服务端 30B
游戏 0x23 ENTITY_INTERACT 客⼾端→服务端 21B
游戏 0x24 INVENTORY_CHANGE 客⼾端→服务端 9B
游戏 0x26 CHEST_MODIFY 客⼾端→服务端 20B
游戏 0x27 CHUNK_TRANSFER 客⼾端→服务端 37B
⼴播 0x30 BROADCAST_MOVE 服务端→所有客⼾端 25B
⼴播 0x31 BROADCAST_BLOCK 服务端→所有客⼾端 可变
⼴播 0x32 BROADCAST_ENTITY 服务端→所有客⼾端 可变
⼴播 0x33 BROADCAST_INVENTORY 服务端→所有客⼾端 可变
控制 0x40 ROLLBACK 服务端→客⼾端 0B
控制 0x41 FREEZE 服务端→客⼾端 0B

---

类别 类型码 名称 ⽅向 载荷⼤⼩
控制 0x42 KICK 服务端→客⼾端 可变 (原因)
⼼跳 0x50 PING 服务端→客⼾端 4B
⼼跳 0x51 PONG 客⼾端→服务端 4B
包校验器
4.4 (packet_validator)
职责：执⾏四条防作弊规则

## 实现：

维护每个玩家的位置状态（⽤于速度计算）
维护⽅块世界状态（⽤于因果关系校验）
维护容器槽位状态（⽤于物品守恒校验）
连续违规计数 → ⾃动升级惩罚
惩罚等级：
等级 条件 动作 游戏内表现
Lv.1 单次偶发超限 丢包 + 回滚 玩家被"拉回"
Lv.2 连续 3 次篡改 冻结客⼾端 世界静⽌，⽆法交互
Lv.3 累计 5 次或畸形包 踢出 弹出"连接被关闭"
事件⽇志引擎
4.5 (event_logger)

## 职责：记录所有游戏事件，⽀持世界同步和审计

存储格式：
事件条目 = 时间戳(4B) + 客户端ID(1B) + 事件类型(1B) + 数据长度(2B) + 数据(NB) +
SHA-256哈希(32B)
哈希链防篡改：
事件 #0 的 hash = SHA-256(全零 || 事件 #0 数据)
事件 #1 的 hash = SHA-256(事件 #0 的 hash || 事件 #1 数据)
事件 #2 的 hash = SHA-256(事件 #1 的 hash || 事件 #2 数据)
...
任何⼀条事件被篡改，后续所有哈希都会变化，可被监控⾯板检测。
⽂件管理：

---


## Flux_data/

├── seed.bin ← 世界种子 (int64)
└── events/
├── events_0000.bin ← 事件日志分片 #0 (最大 4MB)
├── events_0001.bin ← 事件日志分片 #1
└── ...
中继引擎
4.6 (relay_engine)
职责：客⼾端管理 + 区块所有权 + 盲转发⼴播
客⼾端状态机：
DISCONNECTED → HANDSHAKE → AUTHENTICATED → SYNCING → ACTIVE
↓ ↓
AUTH_FAIL FROZEN → KICKED
区块所有权：
区块⼤⼩：16×16 格
谁距离区块中⼼最近，谁就是"托管⼈"
30 秒⽆更新 → ⾃动释放所有权
新玩家靠近 → 重新分配
盲转发⼴播：
for 每个活跃客户端:
if 不是发送者 and 不是冻结状态:

## 用该客户端的会话密钥加密后发送

每个客⼾端使⽤独⽴的会话密钥，服务端⽆法伪造其他客⼾端的数据。
服务端
4.7 TCP (server)

## 职责：接受 TCP 连接，驱动整个服务端流程


## 技术栈：

Python asyncio 异步 I/O
每个客⼾端⼀个协程处理
独⽴的维护协程（超时检测、区块 GC）
独⽴的⼼跳协程（定期 PING）

## ⼆进制协议规范

5.

---

线格式
5.1 (Wire Format)
+----------+--------+-------------+------------------+----------------+-----
-----+----------+
| Magic(2B)| Type(1B)| Length(4B) | IV (12B) | SeqID (4B) |
Data(NB) | Tag(16B) |
+----------+--------+-------------+------------------+----------------+-----
-----+----------+
|<------------ Header (7B) ------>|<---------------- 加密载荷 (Length 字节) -
---------------->|
Magic: 0x484E ("HN")，⽤于在字节流中定位包头
Type: 数据包类型（⻅上表）
Length: IV + SeqID + Data + Tag 的总字节数

## IV: 随机初始化向量，保证相同数据每次加密结果不同

SeqID: 递增序列号，防重放
Data: 实际游戏数据
GCM Tag: 16 字节认证标签，任何篡改都会导致校验失败
字节序: ⼩端序 (Little-Endian)
包⼤⼩对⽐
5.2

## 包类型 Flux 官⽅协议 节省

玩家移动 59 B ~200 B 70%
⽅块破坏 52 B ~150 B 65%
⽅块放置 64 B ~250 B 74%

## 加密与安全机制

6.
三根⽀柱
6.1
⽀柱 算法 解决的问题
动态密钥 ECDH (X25519) "我们是谁" — 每次连接全新临时密钥

## 流加密 AES-128-GCM "数据没被看且没被改" — 认证加密

防重放 SeqID 单调递增 "这句话你刚才已经说过了"
密钥⽣命周期
6.2

---

连接建立 → 生成临时 ECDH 密钥对
→ 交换公钥（明文传输）
→ 各自计算共享密钥
→ SHA-256(shared_secret) → 取前 16 字节 → AES-128 会话密钥

## → 所有后续通信加密

→ 断开连接 → 密钥销毁（仅存于内存，不落盘）
安全保障
6.3
前向安全：每次连接使⽤全新临时密钥
零知识：服务端⽆法解密玩家的明⽂数据（只知道数据是否合法）
防中间⼈：GCM 标签验证，任何篡改都会被检测
防重放：SeqID 严格递增，拒绝重复包
防作弊规则
7.
规则⼀：速度不能超限
7.1
正常疾跑: ~5.6 m/s
鞘翅飞行: ~8.0 m/s
蓝冰船: ~7.0 m/s
药水加速疾跑: ~8.0 m/s
硬上限: 10.0 m/s（超过就是异常）
规则⼆：距离不能超标
7.2
攻击距离: 最大 4.5 格（锋利 III 剑 + 力量 II 的极限）
交互距离: 最大 6 格（开箱子、按按钮等）
超过 → 数据包直接丢弃
规则三：物品必须守恒
7.3
合成: 材料消耗 = 产品产出
捡拾: 地面掉落物存在 → 物品栏增加
箱子操作: 箱子里真的有这些东西
事件日志是最终账本
规则四：事件必须有因
7.4
挖方块: 该坐标确实有方块
放方块: 该坐标确实是空气

---

开箱子: 该坐标确实有箱子
没有历史记录 = 假账

## 世界同步机制

8.
事件溯源原理
8.1
新玩家加入
→ 本地用种子生成原始地形
→ 回放所有历史事件日志
→ 从区块托管人获取动态实体快照
→ 世界还原完成

## 三阶段同步

8.2
阶段 1：种⼦下发
服务端 → 客户端: WORLD_SEED (8 字节种子)
客户端在本地用种子生成原始地形
阶段 2：事件回放
服务端 → 客户端: EVENT_LOG_ENTRY × N
客户端逐条回放方块变更
每 10 条暂停 1ms（防止发送过快）

## 阶段 3：同步完成

服务端 → 客户端: SYNC_COMPLETE
客户端正式进入世界
区块跨界交互
8.3
静态跨界（红⽯、⽔流）：
A 的客户端计算出红石延伸到边界 → 停止越界计算
→ 打包成差值包 → 服务端校验 → 广播
→ B 收到后在本地引擎激活对应位置的红石
动态跨界（实体移动）：

---

A 检测到僵尸越过边界 → 冻结僵尸 AI → 提取完整状态
→ 本地"销毁" → 发送移交包 → 服务端校验记录
→ B 收到后在区块边缘"生成"僵尸 → 接管 AI 计算
数据流详解
9.
玩家移动
9.1
玩家移动
→ Fabric Mod 每 50ms 检测位置变化
→ 编码: seq_id(4B) + x(4B) + y(4B) + z(4B) + yaw(4B) + pitch(4B) +
on_ground(1B) = 25B

## → AES-128-GCM 加密

→ TCP 发送
→ 服务端解密
→ 速度校验 (distance/time_delta < 10.0 m/s)
→ 合法 → 更新区块所有权 → 广播给其他玩家
→ 非法 → 回滚位置
⽅块破坏
9.2
玩家破坏方块
→ Fabric Mod 拦截 AttackBlock 事件
→ 编码: seq_id(4B) + x(4B) + y(4B) + z(4B) + block_id(1B) + face(1B) =
18B

## → AES-128-GCM 加密

→ TCP 发送
→ 服务端解密
→ 距离校验 (< 6.0 格)
→ 因果校验 (该坐标确实有方块)
→ 合法 → 记录事件日志 → 广播给其他玩家
→ 非法 → 丢弃
新玩家加⼊
9.3
新玩家 TCP 连接
→ ECDH 密钥协商
→ 身份认证
→ 接收世界种子 (WORLD_SEED)
→ 在本地生成原始地形
→ 接收历史事件 (EVENT_LOG_ENTRY × N)
→ 逐条回放方块变更

---


## → 接收同步完成信号 (SYNC_COMPLETE)

→ 正式进入世界
项⽬⽂件清单
10.
服务端
10.1 (Python)

## Flux-server/

├── main.py 入口，启动 asyncio 事件循环
├── config.py 全局配置（端口、阈值、路径）

## ├── server.py TCP 服务主逻辑（握手、认证、同步、分发）

├── crypto_engine.py ECDH (X25519) + AES-128-GCM

## ├── protocol.py 二进制协议（包头、载荷结构体、解析器）

├── packet_validator.py 四条防作弊规则 + 违规追踪
├── event_logger.py 事件日志 + SHA-256 哈希链
├── relay_engine.py 客户端管理 + 区块所有权 + 盲转发广播
└── requirements.txt Python 依赖: cryptography
客⼾端
10.2 (Fabric Mod)

## Flux-fabric-mod/

├── build.gradle Gradle 构建配置
├── gradle.properties MC 1.20.1 + Fabric API
└── src/main/

## ├── java/synergyedge/Flux/


## │ ├── FluxClient.java 主入口 (ClientModInitializer)


## │ ├── FluxConfig.java 配置文件读写

│ ├── crypto/
│ │ └── CryptoEngine.java X25519 ECDH + AES-128-GCM
│ ├── protocol/

## │ │ ├── Protocol.java 协议常量

│ │ └── PacketBuilder.java 二进制载荷构建器
│ ├── network/
│ │ └── NetworkClient.java TCP 客户端 + 包收发
│ ├── mod/
│ │ ├── EventInterceptor.java 游戏事件编码
│ │ └── FabricEventRegistrar.java Fabric API 事件注册
│ ├── mixin/
│ │ ├── BlockBreakMixin.java 方块破坏拦截
│ │ ├── BlockPlaceMixin.java 方块放置拦截
│ │ ├── InteractionMixin.java 交互拦截
│ │ └── EntityAttackMixin.java 实体攻击拦截
│ └── world/
│ └── BroadcastHandler.java 广播包处理
└── resources/

---

├── fabric.mod.json

## └── Flux.mixins.json

监控⾯板
10.3 (Python GUI)

## Fluxmonitor.py 监控面板，tkinter GUI

├── 服务器状态卡片（在线/离线、种子、事件数）
├── 哈希链完整性验证
├── 事件列表（筛选、搜索）
├── 事件详情（解析 + Hex dump）
└── CSV 导出
部署指南
11.
环境要求
11.1
服务端：
Python 3.10+
pip install cryptography
客⼾端：
Minecraft Java Edition 1.20.1
Fabric Loader 0.15.11+
Fabric API
JDK 21（编译 Mod ⽤）
快速启动
11.2
服务端：

## cd Flux-server

pip install cryptography
python main.py
客⼾端：

## cd Flux-fabric-mod

./gradlew build
# 产物: build/libs/holonode-client-0.1.0.jar
# 放入 .minecraft/mods/
监控⾯板：

---


## python Fluxmonitor.py

配置
11.3
服务端 ( config.py )：
SERVER_HOST = "0.0.0.0" # 监听地址
SERVER_PORT = 25580 # 监听端口
MAX_CLIENTS = 16 # 最大客户端数
MAX_SPEED_BLOCKS_PER_SEC = 10.0 # 速度上限 (m/s)
MAX_INTERACTION_DISTANCE = 6.0 # 交互距离上限 (格)

## 客⼾端 ( config/Flux.properties )：

server.host=127.0.0.1
server.port=25580
auto.connect=true
监控与运维
12.

## 监控⾯板功能

12.1
服务器状态：实时检测服务端是否在线
事件统计：事件总数、⽇志⽂件数、⽇志⼤⼩
哈希链验证：⾃动校验事件⽇志是否被篡改
事件浏览：表格展⽰所有事件，按类型颜⾊标注
筛选搜索：按事件类型、客⼾端 ID、关键词筛选
详情查看：点击事件查看解析内容和原始 Hex 数据
CSV 导出：⼀键导出筛选后的事件
⽇志⽂件
12.2
服务端运⾏时产⽣以下数据：

## Flux_data/

├── seed.bin 世界种子 (int64, 8 字节)
└── events/
├── events_0000.bin 事件日志分片 #0 (最大 4MB)
├── events_0001.bin 事件日志分片 #1
└── ...
事件类型说明
12.3

---

事件类型 ⼗六进制 记录内容
PLAYER_MOVE 0x20 玩家位置（不记录到⽇志，仅实时⼴播）
BLOCK_BREAK 0x21 坐标 + ⽅块类型 + 操作者
BLOCK_PLACE 0x22 坐标 + ⽅块类型 + 命中向量
ENTITY_INTERACT 0x23 实体 ID + 动作 + 玩家位置
INVENTORY_CHANGE 0x24 槽位 + 物品 ID + 数量 + 动作
CHEST_MODIFY 0x26 容器坐标 + 槽位 + 物品 + 数量
CHUNK_TRANSFER 0x27 实体完整状态（位置、速度、类型、⾎量）
13. FAQ
和 有什么区别？

## Q: Flux Paper/Spigot

Paper/Spigot 是官⽅服务端的优化分⽀，仍然需要运⾏完整游戏引擎。Flux 完全不运⾏游戏
引擎，只做数据包校验和转发。
玩家可以作弊吗？
Q:

## Flux 检查四条不可违反的物理边界。客⼾端可以尝试发送假数据，但：

速度超限 → 丢包
距离超标 → 丢包
物品凭空出现 → 丢包 + 冻结
⽅块不存在 → 丢包
新玩家加⼊时怎么还原世界？
Q:

## 三阶段同步：种⼦⽣成原始地形 → 回放事件⽇志 → 获取动态实体快照。

服务端能看到玩家的数据吗？
Q:

## 不能。所有数据使⽤ AES-128-GCM 端到端加密，服务端只能看到密⽂。服务端只知道"这个

包是否合法"，不知道具体内容。
⽀持多少玩家？
Q:
理论上⽆上限。服务端只做校验和转发，不运⾏游戏逻辑。实际限制取决于⽹络带宽和 TCP
连接数。
可以⽤⼿机 平板玩吗？
Q: /
⽬前只⽀持 Minecraft Java Edition + Fabric Mod。Bedrock 版本需要不同的客⼾端实现。

---

断线重连后世界会丢失吗？
Q:

## 不会。所有事件都记录在服务端的⽇志中，重连后会重新同步。


## 附录：技术栈


## 组件 技术

服务端语⾔ Python 3.10+
异步框架 asyncio

## 加密库 cryptography (Python)

客⼾端语⾔ Java 17
Mod 框架 Fabric Loader + Fabric API

## 加密库 JCE (Java Cryptography Extension)

监控⾯板 Python tkinter

## 传输协议 TCP


## 加密协议 AES-128-GCM

密钥协商 ECDH (X25519)
哈希算法 SHA-256
