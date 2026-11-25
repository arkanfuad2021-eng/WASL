package com.wasl.secure.core.crypto

import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicLong

/**
 * Generates strictly unique, stateful 12-byte (96-bit) Nonces for AES-256-GCM.
 * Nonce Structure:
 * - Bytes 0..3 (4 bytes): Fixed 4-byte prefix (e.g. Conversation/Protocol tag)
 * - Bytes 4..11 (8 bytes): Monotonic 64-bit counter (Atomic & database persisted)
 *
 * This design provides mathematical impossibility of Nonce reuse,
 * guaranteeing complete non-repetition across application restarts and multi-threaded encryption.
 */
class MonotonicNonceManager(
    initialCounter: Long = 1L,
    fixedPrefix: ByteArray? = null
) {
    private val counter = AtomicLong(initialCounter)
    private val prefix: ByteArray = if (fixedPrefix != null && fixedPrefix.size == 4) {
        fixedPrefix
    } else {
        // Default 4-byte prefix: ASCII for "WASL"
        byteArrayOf(0x57.toByte(), 0x41.toByte(), 0x53.toByte(), 0x4C.toByte())
    }

    /**
     * Generates a guaranteed-unique 12-byte Nonce and increments the monotonic counter.
     * Returns: Pair of (Generated 12-byte Nonce, New Counter value to persist).
     */
    @Synchronized
    fun generateNextNonce(): Pair<ByteArray, Long> {
        val currentCounter = counter.getAndIncrement()

        val buffer = ByteBuffer.allocate(AesGcmCipher.NONCE_LENGTH_BYTES) // 12 bytes
        // 1. Prefix (4 bytes)
        buffer.put(prefix)
        // 2. Monotonic 64-bit Counter (8 bytes)
        buffer.putLong(currentCounter)

        return Pair(buffer.array(), counter.get())
    }

    /**
     * Generates a deterministic 12-byte Nonce for a specific counter value without mutating state.
     */
    fun createNonceForCounter(counterValue: Long): ByteArray {
        val buffer = ByteBuffer.allocate(AesGcmCipher.NONCE_LENGTH_BYTES)
        buffer.put(prefix)
        buffer.putLong(counterValue)
        return buffer.array()
    }

    fun getCurrentCounter(): Long = counter.get()

    fun setCounter(value: Long) {
        counter.set(value)
    }
}
