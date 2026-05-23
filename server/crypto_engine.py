"""
Flux Server - 加密引擎
支持 X25519 和 P-256 (ECDH) + AES-128-GCM

线格式:
  Header(7B, 大端) + IV(12B) + EncryptedPayload(Length B)

  EncryptedPayload 内部: Ciphertext(SeqID(4B, 大端) + 游戏数据) + GCM Tag(16B)
  Length = len(EncryptedPayload) = 4 + len(游戏数据) + 16（不含 IV）
"""

import os
import hashlib
import struct
import logging
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from config import (
    ECDH_KEY_SIZE, ECDH_PUBKEY_SIZE, AES_KEY_SIZE,
    PROTOCOL_IV_SIZE, PROTOCOL_GCM_TAG_SIZE, PROTOCOL_SEQID_SIZE,
    PROTOCOL_MAGIC, PROTOCOL_HEADER_SIZE
)
from protocol import PacketHeader, PacketType

logger = logging.getLogger("flux.crypto")


@dataclass
class CryptoSession:
    """每个客户端的加密会话"""
    # X25519
    x25519_private_key: Optional[X25519PrivateKey] = None
    x25519_public_key_bytes: bytes = b''
    # P-256
    p256_private_key: Optional[ec.EllipticCurvePrivateKey] = None
    p256_peer_public_bytes: bytes = b''
    # 通用
    peer_public_bytes: bytes = b''
    session_key: bytes = b''
    tx_seq: int = -1   # 首次 encrypt_packet 时 +1 → 第一个包 seq_id=0
    rx_seq: int = -1   # 允许接收 seq_id=0 的第一个包
    key_ready: bool = False

    def reset(self):
        self.x25519_private_key = None
        self.x25519_public_key_bytes = b''
        self.p256_private_key = None
        self.p256_peer_public_bytes = b''
        self.peer_public_bytes = b''
        self.session_key = b''
        self.tx_seq = -1
        self.rx_seq = -1
        self.key_ready = False


class CryptoEngine:
    """服务端加密引擎"""

    def __init__(self):
        self._server_x25519_private: Optional[X25519PrivateKey] = None
        self._server_x25519_public_bytes: bytes = b''
        self._server_p256_private: Optional[ec.EllipticCurvePrivateKey] = None
        self._server_p256_public_bytes: bytes = b''

    def generate_keypair(self) -> bytes:
        """
        生成服务端 ECDH 密钥对（同时支持 X25519 和 P-256）。
        返回 X25519 公钥字节（32 字节）。
        """
        # X25519
        self._server_x25519_private = X25519PrivateKey.generate()
        x25519_pub = self._server_x25519_private.public_key()
        self._server_x25519_public_bytes = x25519_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # P-256
        self._server_p256_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        p256_pub = self._server_p256_private.public_key()
        self._server_p256_public_bytes = p256_pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        self._server_p256_der_bytes = p256_pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # 客户端自定义格式: 01 + OID(10B) + 03 42 00 04 + PubKey(64B) + 填充
        self._server_p256_flux_bytes = self._build_flux_key(p256_pub)

        logger.info(f"Generated X25519 pubkey: {self._server_x25519_public_bytes.hex()[:16]}...")
        logger.info(f"Generated P-256 pubkey:  {self._server_p256_public_bytes.hex()[:16]}...")
        return self._server_x25519_public_bytes

    @property
    def _server_public_key_bytes(self) -> bytes:
        """兼容旧代码的属性"""
        return self._server_x25519_public_bytes

    @staticmethod
    def _build_flux_key(pub_key: ec.EllipticCurvePublicKey) -> bytes:
        """
        构建 Flux 自定义 P-256 公钥格式（91 字节）。
        格式: 01(1B) + OID(10B) + 03 42 00(3B) + 04(1B) + X(32B) + Y(32B) + 零填充(12B)
        """
        raw = pub_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        # raw = 04 + X(32) + Y(32) = 65 bytes
        prefix = bytes([
            0x01,                                      # version
            0x06, 0x08,                                # OID tag + length
            0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,  # P-256 OID
            0x03, 0x42, 0x00,                          # BIT STRING(66B), unused=0
            0x04,                                      # uncompressed point marker
        ])
        # X(32) + Y(32) from raw[1:]
        coords = raw[1:]
        padding = b'\x00' * 12
        result = prefix + coords + padding
        assert len(result) == 91, f"Flux key format should be 91 bytes, got {len(result)}"
        return result

    @staticmethod
    def _extract_flux_point(data: bytes) -> Optional[bytes]:
        """
        从 Flux 自定义格式中提取 P-256 未压缩点（65 字节）。
        格式: 01 + OID(10B) + 03 42 00 04 + X(32B) + Y(32B) + 填充
        返回: 04 + X(32) + Y(32) = 65 字节，或 None
        """
        if len(data) < 91:
            return None
        # 检查 P-256 OID: bytes[2:12]
        expected_oid = bytes([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])
        if data[1:11] != expected_oid:
            return None
        # 提取 X(32) + Y(32)，从 byte 15 开始（跳过 0x04 前缀）
        coords = data[15:15 + 64]
        return b'\x04' + coords

    def derive_session_key(self, session: CryptoSession,
                           peer_public_bytes: bytes) -> bool:
        """
        用客户端公钥 + 服务端私钥派生 AES-128 会话密钥。
        自动检测密钥类型：X25519 (32B) 或 P-256 SubjectPublicKeyInfo/UncompressedPoint。
        """
        try:
            logger.info(f"derive_session_key: received {len(peer_public_bytes)} bytes, "
                        f"full_hex={peer_public_bytes.hex()}")

            key_type, raw_key_bytes = self._detect_and_extract_key(peer_public_bytes)

            if key_type == "x25519":
                return self._derive_x25519(session, raw_key_bytes)
            elif key_type == "p256":
                return self._derive_p256(session, raw_key_bytes)
            else:
                logger.error(f"Unsupported key type: {key_type}")
                return False

        except Exception as e:
            logger.error(f"Key derivation failed: {type(e).__name__}: {e}")
            return False

    def _detect_and_extract_key(self, data: bytes) -> tuple[str, bytes]:
        """
        检测密钥类型并提取原始公钥字节。
        返回 (key_type, raw_bytes)
        """
        data_len = len(data)

        # ── X25519: 原始 32 字节 ──
        if data_len == 32:
            logger.info("Detected X25519 raw public key (32 bytes)")
            return "x25519", data

        # ── Flux 自定义 P-256 格式: 91 字节 ──
        # 格式: 01 + OID(10B) + 03 42 00 04 + X(32B) + Y(32B) + 填充(13B)
        if data_len == 91:
            point = self._extract_flux_point(data)
            if point is not None:
                logger.info("Detected Flux P-256 custom format (91 bytes)")
                return "p256", point

        # ── P-256 UncompressedPoint: 0x04 + X(32) + Y(32) = 65 字节 ──
        if data_len == 65 and data[0] == 0x04:
            logger.info("Detected P-256 uncompressed point (65 bytes)")
            return "p256", data

        # ── 尝试标准 DER SubjectPublicKeyInfo ──
        if data_len >= 65:
            try:
                public_key = serialization.load_der_public_key(data, backend=default_backend())
                if isinstance(public_key, ec.EllipticCurvePublicKey):
                    raw = public_key.public_bytes(
                        encoding=serialization.Encoding.X962,
                        format=serialization.PublicFormat.UncompressedPoint
                    )
                    logger.info(f"Parsed standard DER SubjectPublicKeyInfo ({data_len} bytes)")
                    return "p256", raw
            except Exception:
                pass

        # ── 在数据中找 0x04 前缀的未压缩点 ──
        if data_len >= 65:
            for i in range(min(20, data_len - 64)):
                if data[i] == 0x04 and i + 65 <= data_len:
                    candidate = data[i:i + 65]
                    logger.info(f"Found 0x04 at offset {i}, trying as P-256 uncompressed point")
                    return "p256", candidate

        logger.error(f"无法识别的密钥格式: {data_len} bytes, "
                     f"first 16: {data[:16].hex()}")
        return "unknown", data

    def _derive_x25519(self, session: CryptoSession, raw_key: bytes) -> bool:
        """X25519 ECDH 密钥派生"""
        peer_public_key = X25519PublicKey.from_public_bytes(raw_key)
        shared_secret = self._server_x25519_private.exchange(peer_public_key)
        key_material = hashlib.sha256(shared_secret).digest()[:AES_KEY_SIZE]

        session.peer_public_bytes = raw_key
        session.session_key = key_material
        session.key_ready = True

        logger.info(f"X25519 session key derived: {key_material.hex()[:16]}...")
        return True

    def _derive_p256(self, session: CryptoSession, raw_key: bytes) -> bool:
        """P-256 ECDH 密钥派生"""
        peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), raw_key
        )
        shared_secret = self._server_p256_private.exchange(
            ec.ECDH(), peer_public_key
        )
        key_material = hashlib.sha256(shared_secret).digest()[:AES_KEY_SIZE]

        session.p256_peer_public_bytes = raw_key
        session.peer_public_bytes = raw_key
        session.session_key = key_material
        session.key_ready = True

        logger.info(f"P-256 session key derived: {key_material.hex()[:16]}...")
        return True

    @staticmethod
    def encrypt_packet(session: CryptoSession, pkt_type: int,
                       payload: bytes) -> Optional[bytes]:
        """
        加密一个数据包。
        返回完整线格式: Header(7B, 大端) + IV(12B) + Ciphertext+Tag
        Length 字段 = len(Ciphertext+Tag)，不含 IV。
        """
        if not session.key_ready:
            logger.error("Cannot encrypt: session key not ready")
            return None

        session.tx_seq += 1
        seq_id = session.tx_seq

        # 构建明文: SeqID(4B, 大端) + Payload
        cleartext = struct.pack(">I", seq_id) + payload

        # 生成随机 IV
        iv = os.urandom(PROTOCOL_IV_SIZE)

        # AES-128-GCM 加密
        aesgcm = AESGCM(session.session_key)
        ciphertext_with_tag = aesgcm.encrypt(iv, cleartext, None)

        # 构建包头 — 大端序，Length = 密文+Tag 长度（不含 IV）
        header = PacketHeader(
            magic=PROTOCOL_MAGIC,
            pkt_type=pkt_type,
            length=len(ciphertext_with_tag)
        )

        return header.pack() + iv + ciphertext_with_tag

    @staticmethod
    def decrypt_packet(session: CryptoSession, header: PacketHeader,
                       iv: bytes, ciphertext_with_tag: bytes) -> Optional[bytes]:
        """
        解密一个数据包。
        输入: iv (12B), ciphertext_with_tag (密文+GCM Tag)
        返回: 解密后的游戏载荷（已去掉 SeqID 前缀）
        """
        if not session.key_ready:
            logger.error("Cannot decrypt: session key not ready")
            return None

        try:
            aesgcm = AESGCM(session.session_key)
            cleartext = aesgcm.decrypt(iv, ciphertext_with_tag, None)

            # 提取 SeqID（大端序）
            if len(cleartext) < PROTOCOL_SEQID_SIZE:
                logger.error("Decrypted payload too short for SeqID")
                return None

            seq_id = struct.unpack(">I", cleartext[:PROTOCOL_SEQID_SIZE])[0]

            # 防重放检查: SeqID 必须严格递增
            if seq_id <= session.rx_seq:
                logger.warning(
                    f"Replay detected! seq={seq_id} <= expected={session.rx_seq}")
                return None

            session.rx_seq = seq_id
            payload = cleartext[PROTOCOL_SEQID_SIZE:]

            return payload

        except Exception as e:
            logger.error(f"Decryption failed (GCM tag mismatch or corrupt): {e}")
            return None

    @staticmethod
    def reset_session(session: CryptoSession):
        """安全擦除会话密钥"""
        session.reset()
        logger.info("Crypto session reset (keys cleared)")
