package com.wasl.secure.data.local.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Update
import com.wasl.secure.data.local.entity.OutboundAttemptEntity

@Dao
interface OutboundAttemptDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(attempt: OutboundAttemptEntity)

    @Update
    suspend fun update(attempt: OutboundAttemptEntity)

    @Query("SELECT * FROM outbound_attempts WHERE conversationId = :conversationId AND messageId = :messageId AND attemptId = :attemptId LIMIT 1")
    suspend fun getAttempt(conversationId: String, messageId: String, attemptId: String): OutboundAttemptEntity?

    @Query("SELECT * FROM outbound_attempts WHERE conversationId = :conversationId AND messageId = :messageId ORDER BY createdAt ASC")
    suspend fun getAttemptsForMessage(conversationId: String, messageId: String): List<OutboundAttemptEntity>

    @Query("SELECT COUNT(*) FROM outbound_attempts WHERE conversationId = :conversationId AND messageId = :messageId")
    suspend fun getAttemptCountForMessage(conversationId: String, messageId: String): Int

    @Query("UPDATE outbound_attempts SET status = :status WHERE conversationId = :conversationId AND messageId = :messageId AND attemptId = :attemptId")
    suspend fun updateStatus(conversationId: String, messageId: String, attemptId: String, status: String)

    @Query("DELETE FROM outbound_attempts WHERE conversationId = :conversationId AND messageId = :messageId")
    suspend fun deleteAttemptsForMessage(conversationId: String, messageId: String)

    /**
     * Atomically records that a specific chunk index was sent.
     * Prevents duplicate counting of the same chunk index and prohibits late sent
     * reports from converting a FAILED attempt into SENT.
     * Returns: Pair of (isNewlyRecorded: Boolean, allChunksSent: Boolean)
     */
    @Transaction
    suspend fun recordChunkSentAtomic(
        conversationId: String,
        messageId: String,
        attemptId: String,
        chunkIndex: Int
    ): Pair<Boolean, Boolean> {
        val attempt = getAttempt(conversationId, messageId, attemptId) ?: return Pair(false, false)
        if (attempt.totalChunks <= 0 || chunkIndex !in 1..attempt.totalChunks) {
            return Pair(false, false)
        }
        if (attempt.status == "FAILED") {
            return Pair(false, false)
        }

        val indices = if (attempt.sentIndices.isBlank()) {
            mutableSetOf()
        } else {
            attempt.sentIndices.split(",").mapNotNull { it.toIntOrNull() }.toMutableSet()
        }

        if (indices.contains(chunkIndex)) {
            // Already counted; never count twice or re-emit completion
            return Pair(false, false)
        }

        indices.add(chunkIndex)
        val newSentCount = indices.size
        val allSent = newSentCount >= attempt.totalChunks
        val newStatus = when {
            attempt.status == "DELIVERED" -> "DELIVERED"
            allSent -> "SENT"
            else -> attempt.status
        }

        update(
            attempt.copy(
                sentIndices = indices.sorted().joinToString(","),
                sentChunks = newSentCount,
                status = newStatus
            )
        )
        return Pair(true, allSent)
    }

    /**
     * Atomically records that a specific chunk index was delivered.
     * Prevents duplicate counting of the same chunk index and prohibits late delivery
     * reports from converting a FAILED attempt into DELIVERED.
     * Returns: Pair of (isNewlyRecorded: Boolean, allChunksDelivered: Boolean)
     */
    @Transaction
    suspend fun recordChunkDeliveredAtomic(
        conversationId: String,
        messageId: String,
        attemptId: String,
        chunkIndex: Int
    ): Pair<Boolean, Boolean> {
        val attempt = getAttempt(conversationId, messageId, attemptId) ?: return Pair(false, false)
        if (attempt.totalChunks <= 0 || chunkIndex !in 1..attempt.totalChunks) {
            return Pair(false, false)
        }
        if (attempt.status == "FAILED") {
            return Pair(false, false)
        }

        val indices = if (attempt.deliveredIndices.isBlank()) {
            mutableSetOf()
        } else {
            attempt.deliveredIndices.split(",").mapNotNull { it.toIntOrNull() }.toMutableSet()
        }

        if (indices.contains(chunkIndex)) {
            // Already counted; never count twice or re-emit completion
            return Pair(false, false)
        }

        indices.add(chunkIndex)
        val newDeliveredCount = indices.size
        val allDelivered = newDeliveredCount >= attempt.totalChunks
        val newStatus = if (allDelivered) "DELIVERED" else attempt.status

        update(
            attempt.copy(
                deliveredIndices = indices.sorted().joinToString(","),
                deliveredChunks = newDeliveredCount,
                status = newStatus
            )
        )
        return Pair(true, allDelivered)
    }
}
