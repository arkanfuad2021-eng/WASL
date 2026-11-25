package com.wasl.secure.data.local.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import com.wasl.secure.data.local.entity.MessageChunkEntity

sealed class ProcessChunkResult {
    data class Complete(val sortedChunks: List<MessageChunkEntity>) : ProcessChunkResult()
    object Incomplete : ProcessChunkResult()
    object Conflicted : ProcessChunkResult()
}

@Dao
interface MessageChunkDao {

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertChunk(chunk: MessageChunkEntity): Long

    @Query("SELECT * FROM pending_message_chunks WHERE conversationId = :conversationId AND messageId = :messageId AND attemptId = :attemptId ORDER BY chunkIndex ASC")
    suspend fun getChunksForAttempt(conversationId: String, messageId: String, attemptId: String): List<MessageChunkEntity>

    @Query("SELECT COUNT(*) FROM pending_message_chunks WHERE conversationId = :conversationId AND messageId = :messageId AND attemptId = :attemptId")
    suspend fun getChunkCountForAttempt(conversationId: String, messageId: String, attemptId: String): Int

    @Query("DELETE FROM pending_message_chunks WHERE conversationId = :conversationId AND messageId = :messageId AND attemptId = :attemptId")
    suspend fun deleteChunksForAttempt(conversationId: String, messageId: String, attemptId: String)

    @Query("DELETE FROM pending_message_chunks WHERE conversationId = :conversationId AND messageId = :messageId")
    suspend fun deleteChunksForMessage(conversationId: String, messageId: String)

    @Query("DELETE FROM pending_message_chunks WHERE messageId = :messageId")
    suspend fun deleteChunksForMessage(messageId: String)

    @Query("DELETE FROM pending_message_chunks WHERE conversationId = :conversationId OR conversationId = :packetConversationId")
    suspend fun deleteChunksForConversation(conversationId: String, packetConversationId: String)

    @Query("DELETE FROM pending_message_chunks WHERE receivedAt < :expiryTimestamp")
    suspend fun deleteExpiredChunks(expiryTimestamp: Long)

    /**
     * Atomically validates metadata consistency, detects payload/metadata conflicts
     * (including same attemptId + chunkIndex with differing payload), records conflicts,
     * inserts the chunk, and verifies completeness and ordering in a single transaction.
     */
    @Transaction
    suspend fun processAndCheckChunkAtomic(
        chunk: MessageChunkEntity
    ): ProcessChunkResult {
        if (chunk.chunkIndex < 1 || chunk.totalChunks < 1 || chunk.chunkIndex > chunk.totalChunks) {
            return ProcessChunkResult.Conflicted
        }

        val existingChunks = getChunksForAttempt(chunk.conversationId, chunk.messageId, chunk.attemptId)

        // 1. Check if attempt was already marked conflicted
        if (existingChunks.any { it.chunkIndex == 0 || it.chunkPayloadBase64 == "CONFLICT" }) {
            return ProcessChunkResult.Conflicted
        }

        // 2. Metadata consistency & duplicate-index payload conflict check across chunks of this attempt
        val validExisting = existingChunks.filter { it.chunkIndex > 0 }
        if (validExisting.isNotEmpty()) {
            val first = validExisting.first()
            val sameIndexExisting = validExisting.find { it.chunkIndex == chunk.chunkIndex }
            val hasPayloadConflict = sameIndexExisting != null &&
                sameIndexExisting.chunkPayloadBase64 != chunk.chunkPayloadBase64

            if (chunk.totalChunks != first.totalChunks ||
                chunk.nonceBase64 != first.nonceBase64 ||
                chunk.sequenceNumber != first.sequenceNumber ||
                hasPayloadConflict
            ) {
                // Conflict detected! Mark attempt as conflicted and reject reassembly
                insertChunk(
                    chunk.copy(
                        chunkIndex = 0,
                        chunkPayloadBase64 = "CONFLICT"
                    )
                )
                return ProcessChunkResult.Conflicted
            }
        }

        // 3. Insert chunk (identical duplicates on composite PK are ignored)
        insertChunk(chunk)

        // 4. Check completeness and ordering
        val updatedChunks = getChunksForAttempt(chunk.conversationId, chunk.messageId, chunk.attemptId)
        val validChunks = updatedChunks.filter { it.chunkIndex > 0 }

        if (validChunks.size == chunk.totalChunks) {
            val sorted = validChunks.sortedBy { it.chunkIndex }
            // Verify contiguous 1..N
            val isContiguous = sorted.mapIndexed { idx, entity -> entity.chunkIndex == idx + 1 }.all { it }
            if (isContiguous) {
                return ProcessChunkResult.Complete(sorted)
            }
        }

        return ProcessChunkResult.Incomplete
    }
}
