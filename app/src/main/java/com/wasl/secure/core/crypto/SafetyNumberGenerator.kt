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
        val chunk1 = ((buffer.getInt(0) and 0x7FFFFFFF) % 10000).toString().padStart(4, '0')
        val chunk2 = ((buffer.getInt(4) and 0x7FFFFFFF) % 10000).toString().padStart(4, '0')
        val chunk3 = ((buffer.getInt(8) and 0x7FFFFFFF) % 10000).toString().padStart(4, '0')

        return "$chunk1 - $chunk2 - $chunk3"
    }

    fun generateQrPayload(ourKey: ByteArray, peerKey: ByteArray): String {
        val b64 = java.util.Base64.getUrlEncoder().withoutPadding()
        val ourB64 = b64.encodeToString(ourKey)
        val peerB64 = b64.encodeToString(peerKey)
        return "WASL:V1:SAFETY:$ourB64:$peerB64"
    }

    fun parseAndVerifyQrPayload(qrContent: String, expectedOurKey: ByteArray, expectedPeerKey: ByteArray): Boolean {
        return try {
            val parts = qrContent.trim().split(":")
            if (parts.size != 5 || parts[0] != "WASL" || parts[1] != "V1" || parts[2] != "SAFETY") return false
            val b64 = java.util.Base64.getUrlDecoder()
            val scannedKey1 = b64.decode(parts[3])
            val scannedKey2 = b64.decode(parts[4])
            // On the peer's phone, key1 is peer's identity key, key2 is our identity key
            (scannedKey1.contentEquals(expectedPeerKey) && scannedKey2.contentEquals(expectedOurKey)) ||
                    (scannedKey1.contentEquals(expectedOurKey) && scannedKey2.contentEquals(expectedPeerKey))
        } catch (e: Exception) {
            false
        }
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
