package com.wasl.secure.data.local.entity

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "messages",
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
    @PrimaryKey
    val id: String,
    val conversationId: String,
    val direction: String,        // "OUTGOING" or "INCOMING"
    val content: String,          // Decrypted plain text stored only locally
    val timestamp: Long,
    val status: String,           // "DRAFT", "QUEUED", "SENDING", "SENT", "DELIVERED", "FAILED", etc.
    val simSubscriptionId: Int?,  // Exact SIM used for sending all chunks
    val totalParts: Int = 1,
    val deliveredParts: Int = 0,
    val nonceBase64: String?,     // Unique 12-byte Nonce used for AES-GCM
    val chunkSequence: Int = 0
)
