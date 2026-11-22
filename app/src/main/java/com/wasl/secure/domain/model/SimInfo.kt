package com.wasl.secure.domain.model

data class SimInfo(
    val subscriptionId: Int,
    val slotIndex: Int,
    val displayName: String,
    val carrierName: String,
    val isDefaultSms: Boolean = false
)

data class HandshakeRequest(
    val requestId: String,
    val conversationId: String,
    val phoneNumber: String,
    val isIncoming: Boolean,
    val status: HandshakeStatus,
    val createdAt: Long,
    val expiredAt: Long,
    val rejectedAt: Long? = null
)
