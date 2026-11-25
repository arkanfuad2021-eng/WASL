package com.wasl.secure.data.local.entity

import androidx.room.Entity
import androidx.room.Index

/**
 * Temporary buffer storing incoming fragmented SMS parts until all chunks for an attempt arrive.
 * Conforms to Section 7 of the Master Specification with strict attempt and conversation isolation.
 */
@Entity(
    tableName = "pending_message_chunks",
    primaryKeys = ["conversationId", "messageId", "attemptId", "chunkIndex"],
    indices = [
        Index(value = ["conversationId", "messageId", "attemptId"]),
        Index(value = ["receivedAt"])
    ]
)
data class MessageChunkEntity(
    val conversationId: String,
    val messageId: String,
    val attemptId: String,             // 4-hex string e.g. "0001", "0002"
    val chunkIndex: Int,               // 1-based index (e.g. 1, 2, 3)
    val totalChunks: Int,              // Total expected chunks
    val chunkPayloadBase64: String,    // Base64 chunk of the ciphertext
    val nonceBase64: String,           // Shared 12-byte Nonce
    val sequenceNumber: Long,
    val receivedAt: Long = System.currentTimeMillis()
)
