package com.flux.client.crypto;

import com.flux.client.FluxClient;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * AES-128-GCM 加解密引擎
 *
 * GCM（Galois/Counter Mode）认证加密：
 * - 加密和完整性校验在同一个操作中完成
 * - 任何一比特的篡改都会导致解密失败
 */
public class PacketCipher {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    private final SecureRandom secureRandom = new SecureRandom();
    private SecretKey secretKey;
    private boolean initialized = false;

    public void init(byte[] sharedSecret) {
        if (sharedSecret.length != 16) {
            throw new IllegalArgumentException("AES-128 requires 16-byte key");
        }
        this.secretKey = new SecretKeySpec(sharedSecret, "AES");
        this.initialized = true;
        FluxClient.LOGGER.info("[Flux] PacketCipher initialized (AES-128-GCM).");
    }

    public byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        secureRandom.nextBytes(iv);
        return iv;
    }

    public byte[] encrypt(byte[] plaintext, byte[] iv) throws Exception {
        checkInitialized();
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        return cipher.doFinal(plaintext);
    }

    public byte[] decrypt(byte[] ciphertext, byte[] iv) {
        checkInitialized();
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            return cipher.doFinal(ciphertext);
        } catch (javax.crypto.AEADBadTagException e) {
            FluxClient.LOGGER.warn("[Flux] GCM Auth Tag mismatch! Packet tampered.");
            return null;
        } catch (Exception e) {
            FluxClient.LOGGER.error("[Flux] Decryption failed: {}", e.getMessage());
            return null;
        }
    }

    public void destroy() {
        secretKey = null;
        initialized = false;
        FluxClient.LOGGER.info("[Flux] PacketCipher destroyed.");
    }

    private void checkInitialized() {
        if (!initialized) {
            throw new IllegalStateException("PacketCipher not initialized.");
        }
    }
}
