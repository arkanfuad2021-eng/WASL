package com.wasl.secure.core.crypto

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64

/**
 * Manages the long-term cryptographic identity of the device (Ed25519 Key Pair).
 * Automatically generates identity on first launch, wraps the private key via Android Keystore,
 * and strictly prevents silent identity replacement if the key is lost or corrupted.
 */
open class IdentityManager(
    context: Context,
    private val keystoreManager: KeystoreManager
) {
    companion object {
        const val PREFS_NAME = "wasl_identity_secure_prefs"
        const val KEY_PUBLIC_IDENTITY = "public_identity_key_base64"
        const val KEY_ENCRYPTED_PRIVATE_IDENTITY = "enc_private_identity_key_base64"
        const val KEY_IDENTITY_INITIALIZED = "identity_has_been_initialized"
    }

    enum class IdentityState {
        ACTIVE,
        FIRST_LAUNCH_PENDING,
        LOCKDOWN_KEY_LOST
    }

    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    var currentState: IdentityState = IdentityState.FIRST_LAUNCH_PENDING
        private set

    init {
        checkAndInitializeIdentity()
    }

    private fun checkAndInitializeIdentity() {
        val hasBeenInitialized = prefs.getBoolean(KEY_IDENTITY_INITIALIZED, false)
        val hasPublicKey = prefs.contains(KEY_PUBLIC_IDENTITY)
        val hasPrivateKey = prefs.contains(KEY_ENCRYPTED_PRIVATE_IDENTITY)

        if (!hasBeenInitialized && !hasPublicKey && !hasPrivateKey) {
            // First run on a clean installation -> Generate brand new identity
            generateNewIdentity()
            currentState = IdentityState.ACTIVE
        } else if (hasBeenInitialized && hasPublicKey && hasPrivateKey) {
            // Existing installation -> Perform cryptographic key pair consistency self-test
            try {
                val privateKey = getPrivateIdentityKey()
                val publicKey = getPublicIdentityKey()
                
                // Sign challenge and verify with public key to mathematically prove key-pair correspondence
                val challenge = "WASL_IDENTITY_SELF_TEST_V1".toByteArray(Charsets.UTF_8)
                val testSignature = try {
                    Curve25519Engine.signEd25519(privateKey, challenge)
                } finally {
                    privateKey.fill(0) // Wipe decrypted private key immediately
                }

                val isMatch = Curve25519Engine.verifyEd25519(publicKey, challenge, testSignature)
                if (isMatch) {
                    currentState = IdentityState.ACTIVE
                } else {
                    // Mismatched or corrupted key pair! Enter lockdown mode.
                    currentState = IdentityState.LOCKDOWN_KEY_LOST
                }
            } catch (e: Exception) {
                // Key in Keystore lost, revoked, or corrupted! Enter lockdown mode.
                currentState = IdentityState.LOCKDOWN_KEY_LOST
            }
        } else {
            // State corruption: App was initialized previously, but keys are missing!
            currentState = IdentityState.LOCKDOWN_KEY_LOST
        }
    }

    /**
     * Generates a new cryptographic identity on first installation.
     */
    fun generateNewIdentity() {
        val keyPair = Curve25519Engine.generateEd25519KeyPair()

        // 1. Envelope-encrypt private key with Keystore master key
        val encryptedPrivateKey = keystoreManager.wrapKey(keyPair.privateKey)

        // 2. Persist public key (Base64) and wrapped private key (Base64)
        val pubBase64 = Base64.encodeToString(keyPair.publicKey, Base64.NO_WRAP)
        val encPrivBase64 = Base64.encodeToString(encryptedPrivateKey, Base64.NO_WRAP)

        prefs.edit()
            .putString(KEY_PUBLIC_IDENTITY, pubBase64)
            .putString(KEY_ENCRYPTED_PRIVATE_IDENTITY, encPrivBase64)
            .putBoolean(KEY_IDENTITY_INITIALIZED, true)
            .apply()

        // Wipe in-memory private key copy
        keyPair.privateKey.fill(0)
        currentState = IdentityState.ACTIVE
    }

    /**
     * Emergency reset: ONLY callable when user explicitly confirms complete wipe from lockdown UI.
     */
    fun forceEmergencyResetIdentity() {
        prefs.edit().clear().apply()
        generateNewIdentity()
    }

    fun isHealthy(): Boolean = currentState == IdentityState.ACTIVE

    /**
     * Returns the 32-byte public identity key of this device.
     */
    fun getPublicIdentityKey(): ByteArray {
        if (currentState == IdentityState.LOCKDOWN_KEY_LOST) {
            throw SecurityException("التطبيق في وضع الإغلاق الأمني: مفتاح الهوية تالف أو مفقود ولا يمكن استخدامه")
        }
        val pubBase64 = prefs.getString(KEY_PUBLIC_IDENTITY, null)
            ?: throw IllegalStateException("Public identity key not found")
        return Base64.decode(pubBase64, Base64.NO_WRAP)
    }

    fun getPublicIdentityKeyBase64(): String {
        return prefs.getString(KEY_PUBLIC_IDENTITY, "") ?: ""
    }

    /**
     * Decrypts the private identity key in-memory using KeystoreManager.
     */
    private fun getPrivateIdentityKey(): ByteArray {
        val encPrivBase64 = prefs.getString(KEY_ENCRYPTED_PRIVATE_IDENTITY, null)
            ?: throw IllegalStateException("Encrypted private identity key not found")
        val encryptedBytes = Base64.decode(encPrivBase64, Base64.NO_WRAP)
        return keystoreManager.unwrapKey(encryptedBytes)
    }

    /**
     * Signs data using the device's private identity key.
     * The private key is wiped in memory immediately after signature generation.
     */
    fun sign(data: ByteArray): ByteArray {
        if (currentState == IdentityState.LOCKDOWN_KEY_LOST) {
            throw SecurityException("التطبيق في وضع الإغلاق الأمني: لا يمكن توقيع البيانات بمفتاح تالف")
        }
        val privateKey = getPrivateIdentityKey()
        return try {
            Curve25519Engine.signEd25519(privateKey, data)
        } finally {
            privateKey.fill(0) // Immediate defense-in-depth zeroization
        }
    }

    /**
     * Verifies a digital signature from a peer using their public identity key.
     */
    fun verifyPeerSignature(peerPublicKey: ByteArray, data: ByteArray, signature: ByteArray): Boolean {
        return Curve25519Engine.verifyEd25519(peerPublicKey, data, signature)
    }
}
