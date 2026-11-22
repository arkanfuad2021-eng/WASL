package com.wasl.secure.data.local.entity

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Temporary buffer storing incoming fragmented SMS parts until all chunks arrive.
 * Conforms to Section 7 of the Master Specification.
 */
@Entity(
    tableName = "pending_message_chunks",
    indices = [
        Index(value = ["messageId", "chunkIndex"], unique = true),
        Index(value = ["conversationId"])
    ]
)
data class MessageChunkEntity(
    @PrimaryKey
    val id: String,                    // Composite key: "${messageId}_${chunkIndex}"
    val messageId: String,             // Parent message ID
    val conversationId: String,
    val chunkIndex: Int,               // 1-based index (e.g. 1, 2, 3)
    val totalChunks: Int,              // Total expected chunks
    val chunkPayloadBase64: String,    // Base64 chunk of the ciphertext
    val nonceBase64: String,           // Shared 12-byte Nonce
    val sequenceNumber: Long,
    val receivedAt: Long = System.currentTimeMillis()
)
