package com.wasl.secure.core.crypto

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64

/**
 * Manages the long-term cryptographic identity of the device (Ed25519 Key Pair).
 * Automatically generates identity on first launch and protects the private key
 * via Android Keystore envelope encryption.
 */
class IdentityManager(
    context: Context,
    private val keystoreManager: KeystoreManager
) {
    companion object {
        private const val PREFS_NAME = "wasl_identity_secure_prefs"
        private const val KEY_PUBLIC_IDENTITY = "public_identity_key_base64"
        private const val KEY_ENCRYPTED_PRIVATE_IDENTITY = "enc_private_identity_key_base64"
    }

    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    init {
        ensureIdentityExists()
    }

    private fun ensureIdentityExists() {
        if (!prefs.contains(KEY_PUBLIC_IDENTITY) || !prefs.contains(KEY_ENCRYPTED_PRIVATE_IDENTITY)) {
            generateNewIdentity()
        }
    }

    /**
     * Generates a brand new cryptographic identity.
     * Used on first launch, or when reinstalling / resetting the device.
     */
    fun generateNewIdentity() {
        val keyPair = Curve25519Engine.generateEd25519KeyPair()

        // 1. Envelope-encrypt private key with hardware master key
        val encryptedPrivateKey = keystoreManager.encrypt(keyPair.privateKey)

        // 2. Persist public key (Base64) and encrypted private key (Base64)
        val pubBase64 = Base64.encodeToString(keyPair.publicKey, Base64.NO_WRAP)
        val encPrivBase64 = Base64.encodeToString(encryptedPrivateKey, Base64.NO_WRAP)

        prefs.edit()
            .putString(KEY_PUBLIC_IDENTITY, pubBase64)
            .putString(KEY_ENCRYPTED_PRIVATE_IDENTITY, encPrivBase64)
            .apply()
    }

    /**
     * Returns the 32-byte public identity key of this device.
     */
    fun getPublicIdentityKey(): ByteArray {
        val pubBase64 = prefs.getString(KEY_PUBLIC_IDENTITY, null)
            ?: throw IllegalStateException("Public identity key not found")
        return Base64.decode(pubBase64, Base64.NO_WRAP)
    }

    fun getPublicIdentityKeyBase64(): String {
        return prefs.getString(KEY_PUBLIC_IDENTITY, "") ?: ""
    }

    /**
     * Decrypts the private identity key in-memory using KeystoreManager to perform a digital signature.
     */
    private fun getPrivateIdentityKey(): ByteArray {
        val encPrivBase64 = prefs.getString(KEY_ENCRYPTED_PRIVATE_IDENTITY, null)
            ?: throw IllegalStateException("Encrypted private identity key not found")
        val encryptedBytes = Base64.decode(encPrivBase64, Base64.NO_WRAP)
        return keystoreManager.decrypt(encryptedBytes)
    }

    /**
     * Signs data (e.g. handshake parameters) using the device's private identity key.
     */
    fun sign(data: ByteArray): ByteArray {
        val privateKey = getPrivateIdentityKey()
        return try {
            Curve25519Engine.signEd25519(privateKey, data)
        } finally {
            // Overwrite in-memory private key copy for defense in depth
            privateKey.fill(0)
        }
    }

    /**
     * Verifies a digital signature from a peer using their public identity key.
     */
    fun verifyPeerSignature(peerPublicKey: ByteArray, data: ByteArray, signature: ByteArray): Boolean {
        return Curve25519Engine.verifyEd25519(peerPublicKey, data, signature)
    }
}
