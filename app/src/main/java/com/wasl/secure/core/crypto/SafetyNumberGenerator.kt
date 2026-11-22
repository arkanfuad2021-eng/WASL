package com.wasl.secure.core.crypto

import java.nio.ByteBuffer
import java.security.MessageDigest

/**
 * Deterministically generates an identical 12-digit Safety Number for both communication parties.
 * Enables users to verify identity out-of-band and detect any Man-In-The-Middle (MITM) tampering.
 */
object SafetyNumberGenerator {

    fun generateSafetyNumber(ourIdentityPublicKey: ByteArray, peerIdentityPublicKey: ByteArray): String {
        require(ourIdentityPublicKey.size == Curve25519Engine.KEY_SIZE)
        require(peerIdentityPublicKey.size == Curve25519Engine.KEY_SIZE)

        // 1. Sort public keys lexicographically to guarantee identical input order on both devices
        val (firstKey, secondKey) = if (compareByteArrays(ourIdentityPublicKey, peerIdentityPublicKey) < 0) {
            Pair(ourIdentityPublicKey, peerIdentityPublicKey)
        } else {
            Pair(peerIdentityPublicKey, ourIdentityPublicKey)
        }

        // 2. Hash both keys using SHA-256
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("WASL_SAFETY_NUMBER_V1".toByteArray(Charsets.UTF_8))
        digest.update(firstKey)
        digest.update(secondKey)
        val hash = digest.digest()

        // 3. Extract 3 numerical chunks (each 4 digits: 0000 - 9999) from hash bytes
        val buffer = ByteBuffer.wrap(hash)
        val chunk1 = (Math.abs(buffer.getInt(0)) % 10000).toString().padStart(4, '0')
        val chunk2 = (Math.abs(buffer.getInt(4)) % 10000).toString().padStart(4, '0')
        val chunk3 = (Math.abs(buffer.getInt(8)) % 10000).toString().padStart(4, '0')

        return "$chunk1 - $chunk2 - $chunk3"
    }

    private fun compareByteArrays(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val byteA = a[i].toInt() and 0xFF
            val byteB = b[i].toInt() and 0xFF
            if (byteA != byteB) return byteA - byteB
        }
        return a.size - b.size
    }
}
