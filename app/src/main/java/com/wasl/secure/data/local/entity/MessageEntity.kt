package com.wasl.secure.data.local.entity

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index

@Entity(
    tableName = "messages",
    primaryKeys = ["conversationId", "id"],
    foreignKeys = [
        ForeignKey(
            entity = ConversationEntity::class,
            parentColumns = ["id"],
            childColumns = ["conversationId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [
        Index(value = ["conversationId"]),
        Index(value = ["timestamp"])
    ]
)
data class MessageEntity(
    val conversationId: String,
    val id: String,
    val direction: String,        // "OUTGOING" or "INCOMING"
    val content: String,          // Decrypted plain text stored only locally
    val timestamp: Long,
    val status: String,           // "DRAFT", "QUEUED", "SENDING", "SENT", "DELIVERED", "FAILED", etc.
    val simSubscriptionId: Int?,  // Exact SIM used for sending all chunks
    val totalParts: Int = 1,
    val deliveredParts: Int = 0,
    val nonceBase64: String?,     // Unique 12-byte Nonce used for AES-GCM
    val chunkSequence: Int = 0,
    val attemptCount: Int = 1,
    val currentAttemptId: String = "0001",
    val ciphertextBase64: String? = null // Encrypted payload stored permanently to allow retrying without re-encrypting
)
