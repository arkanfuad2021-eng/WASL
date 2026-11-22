package com.wasl.secure.core.crypto

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.SecureRandom

/**
 * High-performance, side-channel resistant implementation of:
 * - X25519 (RFC 7748) for Diffie-Hellman Key Agreement.
 * - Ed25519 (RFC 8032) for Digital Signatures.
 *
 * Backed by Bouncy Castle's lightweight cryptographic engine,
 * guaranteeing full compatibility and uniform security across all Android versions (API 26 - 35+).
 */
object Curve25519Engine {

    const val KEY_SIZE = 32
    const val SIGNATURE_SIZE = 64

    data class KeyPairBytes(
        val privateKey: ByteArray,
        val publicKey: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as KeyPairBytes
            if (!privateKey.contentEquals(other.privateKey)) return false
            if (!publicKey.contentEquals(other.publicKey)) return false
            return true
        }

        override fun hashCode(): Int {
            var result = privateKey.contentHashCode()
            result = 31 * result + publicKey.contentHashCode()
            return result
        }
    }

    // ==========================================
    // X25519: Key Agreement
    // ==========================================

    fun generateX25519KeyPair(): KeyPairBytes {
        val generator = X25519KeyPairGenerator()
        generator.init(X25519KeyGenerationParameters(SecureRandom()))
        val pair = generator.generateKeyPair()

        val priv = (pair.private as X25519PrivateKeyParameters).encoded
        val pub = (pair.public as X25519PublicKeyParameters).encoded
        return KeyPairBytes(priv, pub)
    }

    fun computeSharedSecret(ourPrivateKey: ByteArray, peerPublicKey: ByteArray): ByteArray {
        require(ourPrivateKey.size == KEY_SIZE) { "X25519 private key must be 32 bytes" }
        require(peerPublicKey.size == KEY_SIZE) { "X25519 public key must be 32 bytes" }

        val privParams = X25519PrivateKeyParameters(ourPrivateKey, 0)
        val pubParams = X25519PublicKeyParameters(peerPublicKey, 0)

        val agreement = X25519Agreement()
        agreement.init(privParams)

        val sharedSecret = ByteArray(KEY_SIZE)
        agreement.calculateAgreement(pubParams, sharedSecret, 0)
        return sharedSecret
    }

    // ==========================================
    // Ed25519: Digital Signatures
    // ==========================================

    fun generateEd25519KeyPair(): KeyPairBytes {
        val generator = Ed25519KeyPairGenerator()
        generator.init(Ed25519KeyGenerationParameters(SecureRandom()))
        val pair = generator.generateKeyPair()

        val priv = (pair.private as Ed25519PrivateKeyParameters).encoded
        val pub = (pair.public as Ed25519PublicKeyParameters).encoded
        return KeyPairBytes(priv, pub)
    }

    fun signEd25519(privateKey: ByteArray, message: ByteArray): ByteArray {
        require(privateKey.size == KEY_SIZE) { "Ed25519 private key must be 32 bytes" }

        val privParams = Ed25519PrivateKeyParameters(privateKey, 0)
        val signer = Ed25519Signer()
        signer.init(true, privParams)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    fun verifyEd25519(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != KEY_SIZE || signature.size != SIGNATURE_SIZE) return false

        return try {
            val pubParams = Ed25519PublicKeyParameters(publicKey, 0)
            val signer = Ed25519Signer()
            signer.init(false, pubParams)
            signer.update(message, 0, message.size)
            signer.verifySignature(signature)
        } catch (e: Exception) {
            false
        }
    }
}
