package com.wasl.secure.domain.model

enum class HandshakeStatus {
    NEW,
    WAITING,            // Sent INIT, waiting for recipient's response
    RESPONSE_RECEIVED,  // Recipient approved, processing response
    ESTABLISHING,       // Deriving keys & sending confirmation
    READY,              // Handshake complete, fully encrypted session
    REJECTED,           // Recipient rejected request (3-min cooldown)
    EXPIRED,            // 24-hr timeout elapsed
    FAILED              // Network/telephony failure
}

data class Conversation(
    val id: String,
    val contactName: String,
    val phoneNumber: String,
    val lastMessage: String?,
    val lastMessageTimestamp: Long,
    val unreadCount: Int = 0,
    val handshakeStatus: HandshakeStatus = HandshakeStatus.READY,
    val defaultSubscriptionId: Int? = null,
    val rejectedAt: Long? = null,
    val currentRequestId: String? = null
) {
    /**
     * Checks if this conversation is currently in the 3-minute post-rejection cooldown.
     * Returns the remaining seconds, or 0 if cooldown has elapsed.
     */
    fun remainingCooldownSeconds(currentTime: Long = System.currentTimeMillis()): Long {
        if (handshakeStatus != HandshakeStatus.REJECTED || rejectedAt == null) return 0
        val cooldownDurationMs = 3 * 60 * 1000L // 3 minutes
        val elapsed = currentTime - rejectedAt
        val remaining = (cooldownDurationMs - elapsed) / 1000L
        return if (remaining > 0) remaining else 0
    }
}
