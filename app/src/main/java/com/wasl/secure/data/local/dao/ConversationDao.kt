package com.wasl.secure.data.local.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Update
import com.wasl.secure.data.local.entity.ConversationEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface ConversationDao {

    @Query("SELECT * FROM conversations ORDER BY lastMessageTimestamp DESC")
    fun getAllConversations(): Flow<List<ConversationEntity>>

    @Query("SELECT * FROM conversations WHERE id = :id LIMIT 1")
    suspend fun getConversationById(id: String): ConversationEntity?

    @Query("SELECT * FROM conversations WHERE phoneNumber = :phoneNumber LIMIT 1")
    suspend fun getConversationByPhone(phoneNumber: String): ConversationEntity?

    @Query("SELECT * FROM conversations WHERE phoneNumber LIKE '%' || :comparableDigits LIMIT 1")
    suspend fun getConversationByComparableDigits(comparableDigits: String): ConversationEntity?

    @Query("SELECT * FROM conversations WHERE id = :convId OR id LIKE :convId || '%' OR replace(id, '-', '') LIKE :convId || '%' LIMIT 1")
    suspend fun getConversationByPacketConvId(convId: String): ConversationEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertOrUpdate(conversation: ConversationEntity)

    @Update
    suspend fun update(conversation: ConversationEntity)

    @Query("UPDATE conversations SET nextOutboundCounter = nextOutboundCounter + 1 WHERE id = :id")
    suspend fun incrementOutboundCounter(id: String)

    @Query("SELECT nextOutboundCounter FROM conversations WHERE id = :id")
    suspend fun getNextOutboundCounter(id: String): Long?

    /**
     * Atomically reserves the next unique monotonic counter value within a database transaction.
     * Prevents race conditions and nonce reuse across concurrent message transmissions.
     */
    @Transaction
    suspend fun reserveNextOutboundCounter(id: String): Long {
        val current = getNextOutboundCounter(id)
            ?: throw IllegalStateException("المحادثة غير موجودة لحجز العداد")
        if (current >= Long.MAX_VALUE) {
            throw IllegalStateException("تم بلوغ السقف الأقصى لعداد الرسائل (Long.MAX_VALUE). يلزم إعادة تأسيس مفاتيح التشفير.")
        }
        incrementOutboundCounter(id)
        return current
    }

    @Query("UPDATE conversations SET defaultSubscriptionId = :subId WHERE id = :id")
    suspend fun updateDefaultSim(id: String, subId: Int)

    @Query("UPDATE conversations SET unreadCount = 0 WHERE id = :id")
    suspend fun markConversationAsRead(id: String)

    @Query("UPDATE conversations SET lastMessage = :lastMsg, lastMessageTimestamp = :timestamp WHERE id = :id")
    suspend fun updateLastMessage(id: String, lastMsg: String?, timestamp: Long)

    @Query("""
        UPDATE conversations
        SET pendingConfirmMessageId = :confirmMessageId,
            pendingConfirmTotalParts = :totalParts,
            pendingConfirmSentIndices = ''
        WHERE id = :id
          AND handshakeStatus = 'PENDING_CONFIRM_SEND'
          AND identityState != 'KEY_CHANGED_ALERT'
    """)
    suspend fun initPendingConfirmAttempt(id: String, confirmMessageId: String, totalParts: Int): Int

    @Query("""
        UPDATE conversations
        SET pendingConfirmSentIndices = :sentIndices
        WHERE id = :id
          AND pendingConfirmMessageId = :confirmMessageId
          AND handshakeStatus = 'PENDING_CONFIRM_SEND'
          AND identityState != 'KEY_CHANGED_ALERT'
    """)
    suspend fun updatePendingConfirmProgress(id: String, confirmMessageId: String, sentIndices: String): Int

    @Query("""
        UPDATE conversations
        SET pendingConfirmMessageId = NULL,
            pendingConfirmTotalParts = 0,
            pendingConfirmSentIndices = ''
        WHERE id = :id
    """)
    suspend fun clearPendingConfirmTracking(id: String)

    /**
     * Conditionally updates handshake status to READY on Initiator only if the current state in DB
     * is PENDING_CONFIRM_SEND and NOT KEY_CHANGED_ALERT. Prevents overwriting identity tamper warnings.
     */
    @Query("""
        UPDATE conversations
        SET handshakeStatus = 'READY',
            pendingConfirmMessageId = NULL,
            pendingConfirmTotalParts = 0,
            pendingConfirmSentIndices = '',
            lastMessage = :lastMsg,
            lastMessageTimestamp = :timestamp
        WHERE id = :id
          AND handshakeStatus = 'PENDING_CONFIRM_SEND'
          AND identityState != 'KEY_CHANGED_ALERT'
    """)
    suspend fun markReadyIfPendingConfirm(id: String, lastMsg: String, timestamp: Long): Int

    /**
     * Persists CONFIRM part sent progress in DB across app restarts and atomically transitions
     * the initiator conversation to READY once all parts succeed (unless KEY_CHANGED_ALERT).
     */
    @Transaction
    suspend fun recordConfirmSentPartAtomic(
        conversationId: String,
        confirmMessageId: String,
        partIndex: Int,
        totalParts: Int,
        isSuccess: Boolean,
        timestamp: Long
    ): String? {
        val conv = getConversationById(conversationId) ?: return null

        // CRITICAL SECURITY: Strictly prohibit transition to READY if identity key changed
        if (conv.identityState == "KEY_CHANGED_ALERT" || conv.handshakeStatus == "KEY_CHANGED_ALERT") {
            clearPendingConfirmTracking(conversationId)
            return null
        }

        if (conv.handshakeStatus != "PENDING_CONFIRM_SEND") {
            return null
        }

        // Ignore stale reports from earlier CONFIRM attempts
        if (conv.pendingConfirmMessageId == null || conv.pendingConfirmMessageId != confirmMessageId) {
            return null
        }

        val expectedTotalParts = if (conv.pendingConfirmTotalParts > 0) conv.pendingConfirmTotalParts else totalParts

        if (!isSuccess) {
            update(
                conv.copy(
                    handshakeStatus = "PENDING_CONFIRM_SEND",
                    pendingConfirmMessageId = null,
                    pendingConfirmTotalParts = 0,
                    pendingConfirmSentIndices = "",
                    lastMessage = "⚠️ فشل إرسال تأكيد المصافحة (انقر لإعادة الإرسال)",
                    lastMessageTimestamp = timestamp
                )
            )
            return null
        }

        if (expectedTotalParts <= 0 || partIndex !in 1..expectedTotalParts) {
            return null
        }

        val sentIndices = if (conv.pendingConfirmSentIndices.isBlank()) {
            mutableSetOf()
        } else {
            conv.pendingConfirmSentIndices.split(",").mapNotNull { it.toIntOrNull() }.toMutableSet()
        }

        val isNewPart = sentIndices.add(partIndex)

        if (sentIndices.size >= expectedTotalParts) {
            val updatedRows = markReadyIfPendingConfirm(
                id = conversationId,
                lastMsg = "✅ تم تأسيس التشفير بنجاح",
                timestamp = timestamp
            )
            return if (updatedRows > 0) conv.currentRequestId else null
        } else if (isNewPart) {
            updatePendingConfirmProgress(
                id = conversationId,
                confirmMessageId = confirmMessageId,
                sentIndices = sentIndices.sorted().joinToString(",")
            )
        }
        return null
    }

    /**
     * Conditionally updates handshake status to READY on Responder only if neither handshakeStatus
     * nor identityState is KEY_CHANGED_ALERT. Prevents overwriting identity tamper warnings.
     */
    @Query("""
        UPDATE conversations
        SET handshakeStatus = 'READY',
            pendingConfirmationKeyBase64 = NULL,
            pendingConfirmMessageId = NULL,
            pendingConfirmTotalParts = 0,
            pendingConfirmSentIndices = '',
            identityState = 'PINNED_TOFU',
            lastMessage = :lastMsg,
            lastMessageTimestamp = :timestamp
        WHERE id = :id
          AND handshakeStatus != 'KEY_CHANGED_ALERT'
          AND identityState != 'KEY_CHANGED_ALERT'
    """)
    suspend fun markResponderReady(id: String, lastMsg: String, timestamp: Long): Int

    @Query("DELETE FROM conversations WHERE id = :id")
    suspend fun deleteById(id: String)

    @Query("DELETE FROM conversations WHERE id IN (:ids)")
    suspend fun deleteByIds(ids: List<String>)
}
