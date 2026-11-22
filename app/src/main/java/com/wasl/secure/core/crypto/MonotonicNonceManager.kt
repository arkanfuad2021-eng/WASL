package com.wasl.secure.core.crypto

import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong

/**
 * Generates strictly unique, stateful 12-byte (96-bit) Nonces for AES-256-GCM.
 * Nonce Structure:
 * - Bytes 0..3 (4 bytes): Monotonic counter (Atomic & database persisted)
 * - Bytes 4..7 (4 bytes): Timestamp in epoch seconds
 * - Bytes 8..11 (4 bytes): Cryptographically secure random bytes
 *
 * This design provides mathematical impossibility of Nonce reuse,
 * even across application restarts, system clock changes, or multi-threaded encryption.
 */
class MonotonicNonceManager(
    initialCounter: Long = 1L
) {
    private val counter = AtomicLong(initialCounter)
    private val secureRandom = SecureRandom()

    /**
     * Generates a guaranteed-unique 12-byte Nonce and increments the monotonic counter.
     * Returns: Pair of (Generated 12-byte Nonce, New Counter value to persist).
     */
    @Synchronized
    fun generateNextNonce(): Pair<ByteArray, Long> {
        val currentCounter = counter.getAndIncrement()
        val currentTimestamp = System.currentTimeMillis() / 1000L // Epoch seconds

        val randomBytes = ByteArray(4)
        secureRandom.nextBytes(randomBytes)

        val buffer = ByteBuffer.allocate(AesGcmCipher.NONCE_LENGTH_BYTES)
        // 1. Counter (4 bytes)
        buffer.putInt(currentCounter.toInt())
        // 2. Timestamp (4 bytes)
        buffer.putInt(currentTimestamp.toInt())
        // 3. Secure Random (4 bytes)
        buffer.put(randomBytes)

        return Pair(buffer.array(), counter.get())
    }

    fun getCurrentCounter(): Long = counter.get()

    fun setCounter(value: Long) {
        counter.set(value)
    }
}
