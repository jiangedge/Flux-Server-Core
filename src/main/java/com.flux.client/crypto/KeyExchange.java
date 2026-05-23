package com.flux.client.crypto;

import com.flux.client.FluxClient;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

/**
 * ECDH 密钥协商 (X25519 / NIST P-256)
 *
 * 流程：
 * 1. 客户端生成临时 ECDH 密钥对
 * 2. 发送公钥给服务端（CLIENT_HELLO）
 * 3. 接收服务端公钥（SERVER_HELLO）
 * 4. 双方独立计算相同的 AES 会话密钥
 */
public class KeyExchange {

    private static final String EC_ALGORITHM = "EC";
    private static final String KA_ALGORITHM = "ECDH";
    private static final String EC_CURVE = "secp256r1";

    private KeyPair clientKeyPair;
    private byte[] clientPublicKeyEncoded;
    private byte[] sharedSecret;

    public void generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(EC_ALGORITHM);
        kpg.initialize(new ECGenParameterSpec(EC_CURVE), new SecureRandom());
        clientKeyPair = kpg.generateKeyPair();
        clientPublicKeyEncoded = clientKeyPair.getPublic().getEncoded();
        FluxClient.LOGGER.info("[Flux] ECDH keypair generated ({} bytes)", clientPublicKeyEncoded.length);
    }

    public byte[] getClientPublicKey() {
        if (clientPublicKeyEncoded == null) {
            throw new IllegalStateException("Key pair not generated.");
        }
        return clientPublicKeyEncoded;
    }

    public byte[] computeSharedSecret(byte[] serverPublicKeyEncoded) throws Exception {
        KeyFactory kf = KeyFactory.getInstance(EC_ALGORITHM);
        java.security.spec.X509EncodedKeySpec keySpec = new java.security.spec.X509EncodedKeySpec(serverPublicKeyEncoded);
        PublicKey serverPublicKey = kf.generatePublic(keySpec);

        KeyAgreement ka = KeyAgreement.getInstance(KA_ALGORITHM);
        ka.init(clientKeyPair.getPrivate());
        ka.doPhase(serverPublicKey, true);
        byte[] rawSecret = ka.generateSecret();

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(rawSecret);
        sharedSecret = new byte[16];
        System.arraycopy(hash, 0, sharedSecret, 0, 16);

        FluxClient.LOGGER.info("[Flux] Shared secret computed. AES-128 key derived.");
        return sharedSecret;
    }

    public byte[] getSharedSecret() {
        if (sharedSecret == null) {
            throw new IllegalStateException("Shared secret not computed.");
        }
        return sharedSecret;
    }

    public void destroy() {
        if (sharedSecret != null) {
            Arrays.fill(sharedSecret, (byte) 0);
            sharedSecret = null;
        }
        clientKeyPair = null;
        clientPublicKeyEncoded = null;
        FluxClient.LOGGER.info("[Flux] Key material destroyed.");
    }
}
