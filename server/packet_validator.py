"""
Flux Server - 包校验器
实现四条防作弊规则 + 违规追踪
"""

import math
import time
import logging
from dataclasses import dataclass, field
from typing import Optional

from config import (
    MAX_SPEED_BLOCKS_PER_SEC,
    MAX_INTERACTION_DISTANCE,
    MAX_ATTACK_DISTANCE,
    VIOLATION_FREEZE_COUNT,
    VIOLATION_KICK_COUNT,
    POSITION_UPDATE_INTERVAL_MS
)

logger = logging.getLogger("flux.validator")


class ViolationAction:
    NONE = 0
    ROLLBACK = 1    # 回滚（丢包）
    FREEZE = 2      # 冻结客户端
    KICK = 3        # 踢出客户端


@dataclass
class PlayerState:
    """每个玩家的追踪状态"""
    x: float = 0.0
    y: float = 0.0
    z: float = 0.0
    last_update_time: float = 0.0   # time.monotonic()
    consecutive_violations: int = 0
    total_violations: int = 0
    frozen: bool = False


@dataclass
class ValidationResult:
    ok: bool = True
    action: int = ViolationAction.NONE
    reason: str = ""


class PacketValidator:
    """包校验器 - 不运行游戏物理，只检查不可违反的边界"""

    def __init__(self):
        self._players: dict[int, PlayerState] = {}  # client_id → state
        self._block_world: dict[tuple[int, int, int], int] = {}  # (x,y,z) → block_id
        self._container_slots: dict[tuple[int, int, int], dict[int, tuple[int, int]]] = {}
        # container (x,y,z) → { slot → (item_id, count) }

    def get_player_state(self, client_id: int) -> PlayerState:
        if client_id not in self._players:
            self._players[client_id] = PlayerState()
        return self._players[client_id]

    def reset_player(self, client_id: int):
        """玩家断开时清理"""
        self._players.pop(client_id, None)

    # ─────────────────────────────────────────────────────────
    #  规则一：速度不能超限
    # ─────────────────────────────────────────────────────────

    def check_speed(self, client_id: int,
                    x: float, y: float, z: float) -> ValidationResult:
        ps = self.get_player_state(client_id)
        now = time.monotonic()

        if ps.last_update_time == 0:
            # 首次位置更新，直接记录
            ps.x, ps.y, ps.z = x, y, z
            ps.last_update_time = now
            return ValidationResult()

        dt = now - ps.last_update_time
        if dt < 0.001:  # 防止除零
            return ValidationResult()

        dx = x - ps.x
        dy = y - ps.y
        dz = z - ps.z
        distance = math.sqrt(dx * dx + dy * dy + dz * dz)
        speed = distance / dt

        if speed > MAX_SPEED_BLOCKS_PER_SEC:
            ps.consecutive_violations += 1
            ps.total_violations += 1
            action = self._determine_action(ps)
            logger.warning(
                f"[Validator] Client {client_id} speed violation: "
                f"{speed:.1f} m/s > {MAX_SPEED_BLOCKS_PER_SEC} m/s "
                f"(consecutive={ps.consecutive_violations}, total={ps.total_violations})")
            return ValidationResult(
                ok=False, action=action,
                reason=f"Speed {speed:.1f} m/s exceeds limit"
            )

        # 合法移动，更新状态
        ps.consecutive_violations = 0  # 重置连续计数
        ps.x, ps.y, ps.z = x, y, z
        ps.last_update_time = now
        return ValidationResult()

    # ─────────────────────────────────────────────────────────
    #  规则二：距离不能超标
    # ─────────────────────────────────────────────────────────

    def check_interaction_distance(self, client_id: int,
                                   target_x: float, target_y: float, target_z: float,
                                   is_attack: bool = False) -> ValidationResult:
        ps = self.get_player_state(client_id)
        if ps.last_update_time == 0:
            return ValidationResult()  # 无历史位置，跳过

        dx = target_x - ps.x
        dy = target_y - ps.y
        dz = target_z - ps.z
        dist = math.sqrt(dx * dx + dy * dy + dz * dz)

        max_dist = MAX_ATTACK_DISTANCE if is_attack else MAX_INTERACTION_DISTANCE
        if dist > max_dist:
            ps.consecutive_violations += 1
            ps.total_violations += 1
            action = self._determine_action(ps)
            logger.warning(
                f"[Validator] Client {client_id} distance violation: "
                f"{dist:.1f} > {max_dist} "
                f"(attack={is_attack})")
            return ValidationResult(
                ok=False, action=action,
                reason=f"Distance {dist:.1f} exceeds {max_dist}"
            )

        return ValidationResult()

    # ─────────────────────────────────────────────────────────
    #  规则三：物品必须守恒
    # ─────────────────────────────────────────────────────────

    def check_inventory_operation(self, client_id: int,
                                  container_pos: Optional[tuple[int, int, int]],
                                  slot: int,
                                  item_id: int, count: int,
                                  action: int) -> ValidationResult:
        """
        校验物品操作的合法性。
        action: 0=拾取, 1=丢弃, 2=交换
        """
        ps = self.get_player_state(client_id)

        if container_pos is not None:
            # 从容器操作
            container_key = container_pos
            if container_key not in self._container_slots:
                self._container_slots[container_key] = {}

            slots = self._container_slots[container_key]

            if action == 0:  # 从容器取出
                if slot not in slots:
                    ps.consecutive_violations += 1
                    ps.total_violations += 1
                    return ValidationResult(
                        ok=False,
                        action=self._determine_action(ps),
                        reason=f"Container slot {slot} is empty"
                    )
                stored_id, stored_count = slots[slot]
                if stored_id != item_id or stored_count < count:
                    ps.consecutive_violations += 1
                    ps.total_violations += 1
                    return ValidationResult(
                        ok=False,
                        action=self._determine_action(ps),
                        reason=f"Container has {stored_count}x{stored_id}, "
                               f"requested {count}x{item_id}"
                    )
                # 扣减
                new_count = stored_count - count
                if new_count <= 0:
                    del slots[slot]
                else:
                    slots[slot] = (stored_id, new_count)

            elif action == 1:  # 放入容器
                if slot in slots:
                    stored_id, stored_count = slots[slot]
                    if stored_id == item_id:
                        slots[slot] = (item_id, stored_count + count)
                    else:
                        # 交换
                        slots[slot] = (item_id, count)
                else:
                    slots[slot] = (item_id, count)

        return ValidationResult()

    # ─────────────────────────────────────────────────────────
    #  规则四：事件必须有因
    # ─────────────────────────────────────────────────────────

    def check_block_event(self, client_id: int,
                          x: int, y: int, z: int,
                          block_id: int, is_break: bool) -> ValidationResult:
        """
        破坏方块：该坐标确实有方块
        放置方块：该坐标确实是空气（或可替换方块）
        """
        ps = self.get_player_state(client_id)
        pos = (x, y, z)

        if is_break:
            # 破坏方块：坐标上必须有方块
            if pos not in self._block_world:
                # 没有记录，可能是原始地形，允许通过（客户端自行生成）
                # 记录此方块被破坏
                self._block_world[pos] = 0  # 变为空气
                return ValidationResult()

            current_block = self._block_world[pos]
            if current_block == 0:
                ps.consecutive_violations += 1
                ps.total_violations += 1
                return ValidationResult(
                    ok=False,
                    action=self._determine_action(ps),
                    reason=f"Block at ({x},{y},{z}) is already air"
                )
            # 合法破坏
            self._block_world[pos] = 0
        else:
            # 放置方块：坐标上必须是空气（或可替换方块如草、水等）
            if pos in self._block_world and self._block_world[pos] != 0:
                ps.consecutive_violations += 1
                ps.total_violations += 1
                return ValidationResult(
                    ok=False,
                    action=self._determine_action(ps),
                    reason=f"Block at ({x},{y},{z}) already occupied "
                           f"(id={self._block_world[pos]})"
                )
            # 合法放置
            self._block_world[pos] = block_id

        return ValidationResult()

    # ─────────────────────────────────────────────────────────
    #  违规处理
    # ─────────────────────────────────────────────────────────

    def _determine_action(self, ps: PlayerState) -> int:
        if ps.consecutive_violations >= VIOLATION_KICK_COUNT:
            return ViolationAction.KICK
        elif ps.consecutive_violations >= VIOLATION_FREEZE_COUNT:
            return ViolationAction.FREEZE
        else:
            return ViolationAction.ROLLBACK

    def unfreeze_player(self, client_id: int):
        ps = self.get_player_state(client_id)
        ps.frozen = False
        ps.consecutive_violations = 0

    def update_container(self, container_pos: tuple[int, int, int],
                         slot: int, item_id: int, count: int):
        """外部更新容器状态（如事件回放时）"""
        if container_pos not in self._container_slots:
            self._container_slots[container_pos] = {}
        self._container_slots[container_pos][slot] = (item_id, count)
