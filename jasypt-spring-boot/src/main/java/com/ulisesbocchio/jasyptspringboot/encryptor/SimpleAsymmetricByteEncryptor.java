package com.ulisesbocchio.jasyptspringboot.encryptor;

import com.ulisesbocchio.jasyptspringboot.util.AsymmetricCryptography;
import com.ulisesbocchio.jasyptspringboot.util.Singleton;
import lombok.SneakyThrows;
import org.jasypt.encryption.ByteEncryptor;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;

/**
 * Vanilla implementation of an asymmetric encryptor that relies on {@link AsymmetricCryptography}
 * Keys are lazily loaded from {@link SimpleAsymmetricConfig}
 *
 * @author Ulises Bocchio
 */
public class SimpleAsymmetricByteEncryptor implements ByteEncryptor {

    private final AsymmetricCryptography crypto;
    private final Singleton<PublicKey> publicKey;
    private final Singleton<PrivateKey> privateKey;

    @SneakyThrows
    public SimpleAsymmetricByteEncryptor(SimpleAsymmetricConfig config) {
        if (config.getProviderName() != null && Security.getProvider(config.getProviderName()) == null) {
            Security.addProvider((Provider) Class.forName(config.getProviderClassName()).getDeclaredConstructor().newInstance());
        } else if (config.getProviderClassName() != null) {
            Security.addProvider((Provider) Class.forName(config.getProviderClassName()).getDeclaredConstructor().newInstance());
        }
        crypto = new AsymmetricCryptography(config.getResourceLoader(), config.getProviderName(), config.getAsymmetricKeyAlgorithm(), config.getAlgorithm());
        privateKey = Singleton.fromLazy(crypto::getPrivateKey, config::loadPrivateKeyResource, config::getPrivateKeyFormat);
        publicKey = Singleton.fromLazy(crypto::getPublicKey, config::loadPublicKeyResource, config::getPublicKeyFormat);
    }

    @Override
    public byte[] encrypt(byte[] message) {
        return this.crypto.encrypt(message, publicKey.get());
    }

    @Override
    public byte[] decrypt(byte[] encryptedMessage) {
        return this.crypto.decrypt(encryptedMessage, privateKey.get());
    }
}
