package com.wasl.secure.core.crypto

import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-256-GCM Authenticated Encryption with Associated Data (AEAD).
 * Enforces strict 96-bit (12-byte) Nonces and 128-bit (16-byte) Authentication Tags.
 */
object AesGcmCipher {

    private const val ALGORITHM = "AES"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    const val NONCE_LENGTH_BYTES = 12
    const val TAG_LENGTH_BITS = 128
    const val KEY_LENGTH_BYTES = 32 // 256 bits

    data class EncryptionResult(
        val nonce: ByteArray,
        val ciphertextWithTag: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as EncryptionResult
            if (!nonce.contentEquals(other.nonce)) return false
            if (!ciphertextWithTag.contentEquals(other.ciphertextWithTag)) return false
            return true
        }

        override fun hashCode(): Int {
            var result = nonce.contentHashCode()
            result = 31 * result + ciphertextWithTag.contentHashCode()
            return result
        }
    }

    /**
     * Encrypts plaintext using AES-256-GCM.
     * @param key 32-byte symmetric key
     * @param nonce Strictly unique 12-byte Nonce
     * @param plaintext Original message bytes
     * @param associatedData Additional Authenticated Data (header metadata)
     */
    fun encrypt(
        key: ByteArray,
        nonce: ByteArray,
        plaintext: ByteArray,
        associatedData: ByteArray? = null
    ): EncryptionResult {
        require(key.size == KEY_LENGTH_BYTES) { "AES-256 key must be exactly 32 bytes" }
        require(nonce.size == NONCE_LENGTH_BYTES) { "GCM Nonce must be exactly 12 bytes" }

        val cipher = Cipher.getInstance(TRANSFORMATION)
        val keySpec = SecretKeySpec(key, ALGORITHM)
        val gcmSpec = GCMParameterSpec(TAG_LENGTH_BITS, nonce)

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
        if (associatedData != null && associatedData.isNotEmpty()) {
            cipher.updateAAD(associatedData)
        }

        val ciphertextWithTag = cipher.doFinal(plaintext)
        return EncryptionResult(nonce, ciphertextWithTag)
    }

    /**
     * Decrypts and verifies AES-256-GCM ciphertext.
     * Throws GeneralSecurityException (AEADBadTagException) if data or AAD was tampered with.
     */
    @Throws(GeneralSecurityException::class)
    fun decrypt(
        key: ByteArray,
        nonce: ByteArray,
        ciphertextWithTag: ByteArray,
        associatedData: ByteArray? = null
    ): ByteArray {
        require(key.size == KEY_LENGTH_BYTES) { "AES-256 key must be exactly 32 bytes" }
        require(nonce.size == NONCE_LENGTH_BYTES) { "GCM Nonce must be exactly 12 bytes" }

        val cipher = Cipher.getInstance(TRANSFORMATION)
        val keySpec = SecretKeySpec(key, ALGORITHM)
        val gcmSpec = GCMParameterSpec(TAG_LENGTH_BITS, nonce)

        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
        if (associatedData != null && associatedData.isNotEmpty()) {
            cipher.updateAAD(associatedData)
        }

        return cipher.doFinal(ciphertextWithTag)
    }
}
