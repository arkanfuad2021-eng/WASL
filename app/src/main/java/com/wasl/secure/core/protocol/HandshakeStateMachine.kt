package com.wasl.secure.core.protocol

import com.wasl.secure.domain.model.HandshakeStatus
import java.util.UUID

/**
 * State machine enforcing the lifecycle and strict rules of WASL handshake requests.
 * Conforms to Sections 5 and 18 of the Master Specification.
 */
object HandshakeStateMachine {

    const val REJECTION_COOLDOWN_MS = 3 * 60 * 1000L      // Exactly 3 minutes
    const val PENDING_REQUEST_TIMEOUT_MS = 24 * 60 * 60 * 1000L // 24 hours

    /**
     * Generates a unique, non-guessable request ID (e.g. "W9F4A2").
     */
    fun generateNewRequestId(): String {
        return "W" + UUID.randomUUID().toString().replace("-", "").take(6).uppercase()
    }

    /**
     * Checks if a new request can be created to a previously rejected contact.
     * Returns 0 if allowed, or the remaining seconds of the 3-minute cooldown.
     */
    fun checkRejectionCooldown(rejectedAt: Long?, currentTime: Long = System.currentTimeMillis()): Long {
        if (rejectedAt == null) return 0
        val elapsed = currentTime - rejectedAt
        val remaining = (REJECTION_COOLDOWN_MS - elapsed) / 1000L
        return if (remaining > 0) remaining else 0
    }

    /**
     * Checks if a pending request has exceeded the 24-hour validity period.
     */
    fun isRequestExpired(createdAt: Long, currentTime: Long = System.currentTimeMillis()): Boolean {
        return (currentTime - createdAt) > PENDING_REQUEST_TIMEOUT_MS
    }

    /**
     * Validates whether a state transition is permitted by the protocol.
     */
    fun canTransition(from: HandshakeStatus, to: HandshakeStatus): Boolean {
        return when (from) {
            HandshakeStatus.NEW -> to in listOf(HandshakeStatus.WAITING, HandshakeStatus.FAILED)
            HandshakeStatus.WAITING -> to in listOf(
                HandshakeStatus.RESPONSE_RECEIVED,
                HandshakeStatus.READY,
                HandshakeStatus.REJECTED,
                HandshakeStatus.EXPIRED,
                HandshakeStatus.FAILED
            )
            HandshakeStatus.RESPONSE_RECEIVED -> to in listOf(
                HandshakeStatus.ESTABLISHING,
                HandshakeStatus.READY,
                HandshakeStatus.FAILED
            )
            HandshakeStatus.ESTABLISHING -> to in listOf(
                HandshakeStatus.READY,
                HandshakeStatus.FAILED
            )
            HandshakeStatus.REJECTED -> to in listOf(HandshakeStatus.NEW, HandshakeStatus.WAITING)
            HandshakeStatus.EXPIRED -> to in listOf(HandshakeStatus.NEW, HandshakeStatus.WAITING)
            HandshakeStatus.READY -> false // Ready conversations cannot revert
            HandshakeStatus.FAILED -> to in listOf(HandshakeStatus.WAITING, HandshakeStatus.NEW)
        }
    }
}
