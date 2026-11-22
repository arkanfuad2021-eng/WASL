package com.wasl.secure.domain.model

enum class MessageStatus {
    DRAFT,
    QUEUED,
    SENDING,
    SENT,            // 1 checkmark: Out of device
    DELIVERED,       // 2 checkmarks: Delivery report from carrier
    FAILED,          // Failed to send, requires manual retry
    RECEIVED,        // Inbound SMS received
    DECRYPTED        // Inbound SMS verified and decrypted
}

enum class MessageDirection {
    OUTGOING,
    INCOMING
}

data class Message(
    val id: String,
    val conversationId: String,
    val direction: MessageDirection,
    val content: String,
    val timestamp: Long,
    val status: MessageStatus,
    val simSubscriptionId: Int? = null,
    val totalParts: Int = 1,
    val deliveredParts: Int = 0
)
