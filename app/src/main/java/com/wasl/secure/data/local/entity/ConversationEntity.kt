package com.wasl.secure.data.local.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "conversations")
data class ConversationEntity(
    @PrimaryKey
    val id: String,
    val contactName: String,
    val phoneNumber: String,
    val lastMessage: String?,
    val lastMessageTimestamp: Long,
    val unreadCount: Int = 0,
    val handshakeStatus: String,
    val defaultSubscriptionId: Int?,
    val rejectedAt: Long?,
    val currentRequestId: String?,
    val peerIdentityKeyBase64: String?,   // Ed25519 Public Key
    val sessionKeyBase64: String?,        // Directional Key K_AB (encrypted with Keystore master key)
    val inboundSessionKeyBase64: String?, // Directional Key K_BA (encrypted with Keystore master key)
    val nextOutboundCounter: Long = 1L    // Monotonic Counter for Nonce generation
)
