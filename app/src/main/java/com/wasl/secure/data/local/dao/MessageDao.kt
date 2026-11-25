package com.wasl.secure.data.local.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Update
import com.wasl.secure.data.local.entity.MessageEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface MessageDao {

    @Query("SELECT * FROM messages WHERE conversationId = :conversationId ORDER BY timestamp ASC")
    fun getMessagesForConversation(conversationId: String): Flow<List<MessageEntity>>

    @Query("SELECT * FROM messages WHERE conversationId = :conversationId AND id = :id LIMIT 1")
    suspend fun getMessageByConversationAndId(conversationId: String, id: String): MessageEntity?

    @Query("SELECT * FROM messages WHERE id = :id LIMIT 1")
    suspend fun getMessageById(id: String): MessageEntity?

    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insertStrict(message: MessageEntity): Long

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(message: MessageEntity)

    @Update
    suspend fun update(message: MessageEntity)

    @Query("UPDATE messages SET status = :status WHERE conversationId = :conversationId AND id = :id")
    suspend fun updateStatus(conversationId: String, id: String, status: String)

    @Query("UPDATE messages SET status = :status WHERE conversationId = :conversationId AND id = :id AND status NOT IN ('FAILED', 'DELIVERED')")
    suspend fun updateStatusIfNotFailedOrDelivered(conversationId: String, id: String, status: String)

    @Query("UPDATE messages SET status = :status WHERE id = :id")
    suspend fun updateStatus(id: String, status: String)

    @Query("UPDATE messages SET attemptCount = :attemptCount, currentAttemptId = :attemptId WHERE conversationId = :conversationId AND id = :id")
    suspend fun updateAttempt(conversationId: String, id: String, attemptCount: Int, attemptId: String)

    @Query("UPDATE messages SET attemptCount = :attemptCount, currentAttemptId = :attemptId, deliveredParts = 0, status = 'SENDING' WHERE conversationId = :conversationId AND id = :id")
    suspend fun startNewAttemptState(conversationId: String, id: String, attemptCount: Int, attemptId: String)

    @Query("UPDATE messages SET deliveredParts = deliveredParts + 1, status = CASE WHEN deliveredParts + 1 >= totalParts THEN 'DELIVERED' ELSE status END WHERE conversationId = :conversationId AND id = :id AND status != 'FAILED'")
    suspend fun recordDeliveryReport(conversationId: String, id: String)

    @Query("UPDATE messages SET deliveredParts = deliveredParts + 1, status = CASE WHEN deliveredParts + 1 >= totalParts THEN 'DELIVERED' ELSE status END WHERE id = :id")
    suspend fun recordDeliveryReport(id: String)

    @Query("UPDATE conversations SET lastMessage = :snippet, lastMessageTimestamp = :timestamp, unreadCount = unreadCount + 1 WHERE id = :conversationId")
    suspend fun updateConversationSnippetAndUnread(conversationId: String, snippet: String, timestamp: Long)

    @Query("DELETE FROM messages WHERE conversationId = :conversationId AND id = :id")
    suspend fun deleteById(conversationId: String, id: String)

    @Query("DELETE FROM messages WHERE id = :id")
    suspend fun deleteById(id: String)

    @Query("DELETE FROM messages WHERE id IN (:ids)")
    suspend fun deleteByIds(ids: List<String>)

    @Query("DELETE FROM messages WHERE conversationId = :conversationId")
    suspend fun deleteAllForConversation(conversationId: String)

    @Query("SELECT * FROM messages WHERE conversationId = :conversationId ORDER BY timestamp DESC LIMIT 1")
    suspend fun getLatestMessageForConversation(conversationId: String): MessageEntity?

    @Query("UPDATE conversations SET lastMessage = :lastMsg, lastMessageTimestamp = :timestamp WHERE id = :conversationId")
    suspend fun updateConversationLastMessage(conversationId: String, lastMsg: String?, timestamp: Long)

    @Query("UPDATE conversations SET lastMessage = NULL WHERE id = :conversationId")
    suspend fun clearConversationLastMessage(conversationId: String)

    /**
     * Atomically deletes a single message by composite (conversationId, id) and updates the
     * parent conversation's lastMessage snippet to the newest remaining message (or null if none).
     */
    @Transaction
    suspend fun deleteMessageAndRefreshConversation(conversationId: String, id: String) {
        deleteById(conversationId, id)
        val latest = getLatestMessageForConversation(conversationId)
        if (latest != null) {
            updateConversationLastMessage(conversationId, latest.content, latest.timestamp)
        } else {
            clearConversationLastMessage(conversationId)
        }
    }

    /**
     * Atomically reserves the next attemptId, increments attemptCount,
     * updates the parent message status to SENDING, strictly enforcing the 65,535 cap.
     */
    @Transaction
    suspend fun reserveNextAttemptAtomic(
        conversationId: String,
        messageId: String
    ): Pair<Int, String> {
        val message = getMessageByConversationAndId(conversationId, messageId)
            ?: throw IllegalStateException("الرسالة غير موجودة في هذه المحادثة")
        if (message.attemptCount >= 65535) {
            throw IllegalStateException("تم بلوغ الحد الأقصى لمحاولات الإرسال (65,535). يُحظر إعادة المحاولة أو إعادة استخدام المعرّفات.")
        }
        val newAttemptCount = message.attemptCount + 1
        val newAttemptId = String.format("%04X", newAttemptCount)

        startNewAttemptState(conversationId, messageId, newAttemptCount, newAttemptId)
        return Pair(newAttemptCount, newAttemptId)
    }

    /**
     * Atomically checks for message duplication scoped to (conversationId, messageId),
     * inserts the new reassembled message, and updates the conversation snippet.
     * Returns true if message was newly inserted; false if message was already present.
     */
    @Transaction
    suspend fun insertReassembledMessageIfNew(
        conversationId: String,
        message: MessageEntity,
        conversationSnippet: String,
        timestamp: Long
    ): Boolean {
        val existing = getMessageByConversationAndId(conversationId, message.id)
        if (existing != null) {
            return false
        }
        insert(message)
        updateConversationSnippetAndUnread(conversationId, conversationSnippet, timestamp)
        return true
    }
}
