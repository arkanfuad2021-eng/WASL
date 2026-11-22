package com.wasl.secure.data.local.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.wasl.secure.data.local.entity.MessageChunkEntity

@Dao
interface MessageChunkDao {

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertChunk(chunk: MessageChunkEntity): Long

    @Query("SELECT * FROM pending_message_chunks WHERE messageId = :messageId ORDER BY chunkIndex ASC")
    suspend fun getChunksForMessage(messageId: String): List<MessageChunkEntity>

    @Query("SELECT COUNT(*) FROM pending_message_chunks WHERE messageId = :messageId")
    suspend fun getChunkCountForMessage(messageId: String): Int

    @Query("DELETE FROM pending_message_chunks WHERE messageId = :messageId")
    suspend fun deleteChunksForMessage(messageId: String)

    @Query("DELETE FROM pending_message_chunks WHERE receivedAt < :expiryTimestamp")
    suspend fun deleteExpiredChunks(expiryTimestamp: Long)
}
