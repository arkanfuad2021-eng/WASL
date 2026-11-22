package com.wasl.secure.core.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.ceil

/**
 * RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
 * using HMAC-SHA256.
 */
object Hkdf {

    private const val HMAC_ALGORITHM = "HmacSHA256"
    private const val HASH_LEN = 32 // SHA-256 output size in bytes

    /**
     * HKDF-Extract(salt, IKM) -> PRK
     */
    fun extract(salt: ByteArray?, ikm: ByteArray): ByteArray {
        val actualSalt = if (salt == null || salt.isEmpty()) {
            ByteArray(HASH_LEN) // All-zeros salt of HashLen
        } else {
            salt
        }

        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(SecretKeySpec(actualSalt, HMAC_ALGORITHM))
        return mac.doFinal(ikm)
    }

    /**
     * HKDF-Expand(PRK, info, L) -> OKM
     */
    fun expand(prk: ByteArray, info: ByteArray?, length: Int): ByteArray {
        require(length <= 255 * HASH_LEN) { "Cannot expand to more than 255 * HashLen bytes" }

        val actualInfo = info ?: ByteArray(0)
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(SecretKeySpec(prk, HMAC_ALGORITHM))

        val n = ceil(length.toDouble() / HASH_LEN).toInt()
        val okm = ByteArray(length)
        var t = ByteArray(0)
        var offset = 0

        for (i in 1..n) {
            mac.reset()
            mac.update(t)
            mac.update(actualInfo)
            mac.update(i.toByte())
            t = mac.doFinal()

            val bytesToCopy = minOf(HASH_LEN, length - offset)
            System.arraycopy(t, 0, okm, offset, bytesToCopy)
            offset += bytesToCopy
        }

        return okm
    }

    /**
     * Full HKDF: Extract then Expand.
     */
    fun deriveKey(
        salt: ByteArray?,
        ikm: ByteArray,
        info: ByteArray?,
        length: Int
    ): ByteArray {
        val prk = extract(salt, ikm)
        return expand(prk, info, length)
    }
}
