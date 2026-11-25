package com.wasl.secure.core.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Manages the Master Key inside Android Keystore.
 * Implements Envelope Encryption to protect Database Encryption Keys (DEK)
 * and long-term cryptographic identities (Ed25519).
 */
open class KeystoreManager(
    private val keyStoreType: String = ANDROID_KEYSTORE
) {

    companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val MASTER_KEY_ALIAS = "WASL_MASTER_ENVELOPE_KEY"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_LENGTH = 128
        const val GCM_IV_LENGTH = 12
        const val DEK_LENGTH_BYTES = 32 // 256 bits
    }

    private val secureRandom = SecureRandom()
    private val keyStore: KeyStore? = try {
        KeyStore.getInstance(keyStoreType).apply { load(null) }
    } catch (e: Exception) {
        null
    }

    // In-memory fallback key for JVM unit tests where AndroidKeyStore provider is absent
    private var testFallbackKey: SecretKey? = null

    init {
        ensureMasterKeyExists()
    }

    /**
     * Checks if the master key is accessible and ready for encryption/decryption.
     */
    fun isMasterKeyAvailable(): Boolean {
        return try {
            if (keyStore != null) {
                keyStore.containsAlias(MASTER_KEY_ALIAS)
            } else {
                testFallbackKey != null
            }
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Checks whether the Master Key resides in hardware (TEE or StrongBox).
     * Returns false on emulator, software-only Keystore, or JVM test environments.
     */
    fun isHardwareBacked(): Boolean {
        if (keyStore == null) return false
        return try {
            val key = getMasterKey()
            val factory = KeyFactory.getInstance(key.algorithm, keyStoreType)
            val keyInfo = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                        keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
            } else {
                @Suppress("DEPRECATION")
                keyInfo.isInsideSecureHardware
            }
        } catch (e: Throwable) {
            false
        }
    }

    private fun ensureMasterKeyExists() {
        if (keyStore != null) {
            if (!keyStore.containsAlias(MASTER_KEY_ALIAS)) {
                val keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES,
                    keyStoreType
                )
                val parameterSpec = KeyGenParameterSpec.Builder(
                    MASTER_KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()

                keyGenerator.init(parameterSpec)
                keyGenerator.generateKey()
            }
        } else {
            // JVM Unit Test Fallback
            if (testFallbackKey == null) {
                val raw = ByteArray(32)
                secureRandom.nextBytes(raw)
                testFallbackKey = SecretKeySpec(raw, "AES")
            }
        }
    }

    private fun getMasterKey(): SecretKey {
        return if (keyStore != null) {
            keyStore.getKey(MASTER_KEY_ALIAS, null) as SecretKey
        } else {
            testFallbackKey ?: throw IllegalStateException("Master key not available in test fallback mode")
        }
    }

    /**
     * Generates a brand-new cryptographically secure 256-bit Database Encryption Key (DEK).
     */
    fun generateDatabaseEncryptionKey(): ByteArray {
        val dek = ByteArray(DEK_LENGTH_BYTES)
        secureRandom.nextBytes(dek)
        return dek
    }

    /**
     * Encrypts (wraps) sensitive key data using the Master Key.
     * Output structure: 12-byte IV + Ciphertext + 16-byte Tag.
     */
    fun wrapKey(data: ByteArray): ByteArray {
        return encrypt(data)
    }

    /**
     * Decrypts (unwraps) envelope-encrypted key data using the Master Key.
     */
    fun unwrapKey(wrappedEnvelope: ByteArray): ByteArray {
        return decrypt(wrappedEnvelope)
    }

    /**
     * Encrypts arbitrary sensitive data using AES-256-GCM under the Master Key.
     */
    fun encrypt(data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getMasterKey())
        val iv = cipher.iv
        val encryptedData = cipher.doFinal(data)
        return iv + encryptedData
    }

    /**
     * Decrypts envelope-encrypted data using AES-256-GCM under the Master Key.
     */
    fun decrypt(encryptedEnvelope: ByteArray): ByteArray {
        require(encryptedEnvelope.size > GCM_IV_LENGTH + 16) { "Invalid envelope size: too short" }
        val iv = encryptedEnvelope.copyOfRange(0, GCM_IV_LENGTH)
        val ciphertext = encryptedEnvelope.copyOfRange(GCM_IV_LENGTH, encryptedEnvelope.size)

        val cipher = Cipher.getInstance(TRANSFORMATION)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.DECRYPT_MODE, getMasterKey(), spec)
        return cipher.doFinal(ciphertext)
    }
}
