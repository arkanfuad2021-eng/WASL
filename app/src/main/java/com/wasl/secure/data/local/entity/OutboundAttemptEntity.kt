package com.wasl.secure.data.local.entity

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index

/**
 * Tracks individual outbound message transmission attempts and chunk delivery progress persistently.
 */
@Entity(
    tableName = "outbound_attempts",
    primaryKeys = ["conversationId", "messageId", "attemptId"],
    foreignKeys = [
        ForeignKey(
            entity = MessageEntity::class,
            parentColumns = ["conversationId", "id"],
            childColumns = ["conversationId", "messageId"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [
        Index(value = ["conversationId", "messageId"])
    ]
)
data class OutboundAttemptEntity(
    val conversationId: String,
    val messageId: String,
    val attemptId: String,                // 4-hex string e.g. "0001", "0002" up to "FFFF"
    val totalChunks: Int,
    val sentChunks: Int = 0,
    val deliveredChunks: Int = 0,
    val sentIndices: String = "",         // Comma-separated set of sent chunk indices e.g. "1,2"
    val deliveredIndices: String = "",    // Comma-separated set of delivered chunk indices e.g. "1,2"
    val status: String,                   // "SENDING", "SENT", "DELIVERED", "FAILED"
    val createdAt: Long = System.currentTimeMillis()
)
