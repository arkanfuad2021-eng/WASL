package com.wasl.secure.core.protocol

import com.wasl.secure.domain.model.HandshakeStatus
import java.util.UUID

/**
 * State machine enforcing the lifecycle and strict rules of WASL handshake requests.
 * Conforms to Sections 5 and 18 of the Master Specification.
 */
object HandshakeStateMachine {

    const val REJECTION_COOLDOWN_MS = 3 * 60 * 1000L      // Exactly 3 minutes

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
     * Validates whether a state transition is permitted by the protocol.
     */
    fun canTransition(from: HandshakeStatus, to: HandshakeStatus): Boolean {
        return when (from) {
            HandshakeStatus.NEW -> to in listOf(
                HandshakeStatus.WAITING,
                HandshakeStatus.FAILED,
                HandshakeStatus.KEY_CHANGED_ALERT
            )
            HandshakeStatus.WAITING -> to in listOf(
                HandshakeStatus.RESPONSE_RECEIVED,
                HandshakeStatus.ESTABLISHING,
                HandshakeStatus.PENDING_CONFIRM_SEND,
                HandshakeStatus.READY,
                HandshakeStatus.REJECTED,
                HandshakeStatus.KEY_CHANGED_ALERT,
                HandshakeStatus.FAILED
            )
            HandshakeStatus.RESPONSE_RECEIVED -> to in listOf(
                HandshakeStatus.ESTABLISHING,
                HandshakeStatus.PENDING_CONFIRM_SEND,
                HandshakeStatus.READY,
                HandshakeStatus.KEY_CHANGED_ALERT,
                HandshakeStatus.FAILED
            )
            HandshakeStatus.ESTABLISHING -> to in listOf(
                HandshakeStatus.PENDING_CONFIRM_SEND,
                HandshakeStatus.READY,
                HandshakeStatus.KEY_CHANGED_ALERT,
                HandshakeStatus.FAILED
            )
            HandshakeStatus.PENDING_CONFIRM_SEND -> to in listOf(
                HandshakeStatus.READY,
                HandshakeStatus.KEY_CHANGED_ALERT,
                HandshakeStatus.FAILED
            )
            HandshakeStatus.REJECTED -> to in listOf(
                HandshakeStatus.NEW,
                HandshakeStatus.WAITING,
                HandshakeStatus.KEY_CHANGED_ALERT
            )
            HandshakeStatus.EXPIRED -> to in listOf(
                HandshakeStatus.NEW,
                HandshakeStatus.WAITING,
                HandshakeStatus.KEY_CHANGED_ALERT
            )
            HandshakeStatus.READY -> to == HandshakeStatus.KEY_CHANGED_ALERT // Ready conversations cannot revert; only security alert allowed
            HandshakeStatus.KEY_CHANGED_ALERT -> false // Security alert state cannot be bypassed automatically
            HandshakeStatus.FAILED -> to in listOf(
                HandshakeStatus.WAITING,
                HandshakeStatus.NEW,
                HandshakeStatus.KEY_CHANGED_ALERT
            )
        }
    }
}
