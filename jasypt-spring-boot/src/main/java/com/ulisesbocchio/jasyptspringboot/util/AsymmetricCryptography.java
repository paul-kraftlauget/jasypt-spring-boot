package com.ulisesbocchio.jasyptspringboot.util;

import lombok.SneakyThrows;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.FileCopyUtils;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AsymmetricCryptography {

    private static final String PEM_HEADER = "-----BEGIN [A-Z ]*-----";
    private static final String PEM_FOOTER = "-----END [A-Z ]*-----";

    private final ResourceLoader resourceLoader;
    private final String providerName;
    private final String keyAlgorithm;
    private final String cipherAlgorithm;

    public AsymmetricCryptography(ResourceLoader resourceLoader) {
        this(resourceLoader, null, "RSA", "RSA");
    }

    public AsymmetricCryptography(ResourceLoader resourceLoader, String providerName, String keyAlgorithm, String cipherAlgorithm) {
        this.resourceLoader = resourceLoader;
        this.providerName = providerName;
        this.keyAlgorithm = keyAlgorithm;
        this.cipherAlgorithm = cipherAlgorithm;
    }

    @SneakyThrows
    private byte[] getResourceBytes(Resource resource) {
        return FileCopyUtils.copyToByteArray(resource.getInputStream());
    }

    @SneakyThrows
    private byte[] decodePem(byte[] bytes) {
        String pem = new String(bytes, StandardCharsets.UTF_8)
                .replaceFirst(PEM_HEADER, "")
                .replaceFirst(PEM_FOOTER, "")
                .trim();
        return Base64.getMimeDecoder().decode(pem);
    }

    @SneakyThrows
    public PrivateKey getPrivateKey(String resourceLocation, KeyFormat format) {
        return getPrivateKey(resourceLoader.getResource(resourceLocation), format);
    }

    @SneakyThrows
    public PrivateKey getPrivateKey(Resource resource, KeyFormat format) {
        byte[] keyBytes = getResourceBytes(resource);
        if (format == KeyFormat.PEM) {
            keyBytes = decodePem(keyBytes);
        }
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = providerName == null
                ? KeyFactory.getInstance(keyAlgorithm)
                : KeyFactory.getInstance(keyAlgorithm, providerName);
        return kf.generatePrivate(spec);
    }

    @SneakyThrows
    public PublicKey getPublicKey(String resourceLocation, KeyFormat format) {
        return getPublicKey(resourceLoader.getResource(resourceLocation), format);
    }

    @SneakyThrows
    public PublicKey getPublicKey(Resource resource, KeyFormat format) {
        byte[] keyBytes = getResourceBytes(resource);
        if (format == KeyFormat.PEM) {
            keyBytes = decodePem(keyBytes);
        }
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = providerName == null
                ? KeyFactory.getInstance(keyAlgorithm)
                : KeyFactory.getInstance(keyAlgorithm, providerName);
        return kf.generatePublic(spec);
    }

    @SneakyThrows
    public byte[] encrypt(byte[] msg, PublicKey key) {
        final Cipher cipher = providerName == null
                ? Cipher.getInstance(cipherAlgorithm)
                : Cipher.getInstance(cipherAlgorithm, providerName);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(msg);
    }

    @SneakyThrows
    public byte[] decrypt(byte[] msg, PrivateKey key) {
        final Cipher cipher = providerName == null
                ? Cipher.getInstance(cipherAlgorithm)
                : Cipher.getInstance(cipherAlgorithm, providerName);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(msg);
    }

    public enum KeyFormat {
        DER,
        PEM;
    }
}