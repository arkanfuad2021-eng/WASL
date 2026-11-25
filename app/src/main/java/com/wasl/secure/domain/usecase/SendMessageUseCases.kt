package com.wasl.secure.domain.usecase

import com.wasl.secure.data.local.WaslDatabase
import com.wasl.secure.domain.model.MessageStatus
import com.wasl.secure.telephony.SimCardManager
import com.wasl.secure.telephony.WaslSmsSender
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * UseCase for sending a new encrypted message.
 * Enforces SIM resolution hierarchy and dispatches via WaslSmsSender.
 */
class SendMessageUseCase(
    private val smsSender: WaslSmsSender,
    private val simCardManager: SimCardManager,
    private val database: WaslDatabase
) {
    suspend operator fun invoke(
        conversationId: String,
        plainText: String,
        targetPhone: String,
        requestedSubId: Int? = null
    ): Result<String> = withContext(Dispatchers.IO) {
        // Respect explicitly chosen SIM if valid; otherwise resolve per conversation/system/active hierarchy
        val effectiveSubId = if (requestedSubId != null && requestedSubId != -1) {
            requestedSubId
        } else {
            simCardManager.resolveEffectiveSimForConversation(conversationId)
        }

        smsSender.sendEncryptedMessage(
            conversationId = conversationId,
            plainText = plainText,
            targetPhone = targetPhone,
            subscriptionId = effectiveSubId
        )
    }
}

/**
 * UseCase for manually retrying a previously failed message.
 * Reuses the stored ciphertext, Nonce, and original SIM, creating only a new attemptId.
 */
class RetrySendMessageUseCase(
    private val smsSender: WaslSmsSender,
    private val database: WaslDatabase
) {
    suspend operator fun invoke(
        conversationId: String,
        messageId: String,
        targetPhone: String
    ): Result<String> = withContext(Dispatchers.IO) {
        val message = database.messageDao().getMessageByConversationAndId(conversationId, messageId)
            ?: return@withContext Result.failure(IllegalStateException("الرسالة غير موجودة في هذه المحادثة"))

        if (message.status != MessageStatus.FAILED.name) {
            return@withContext Result.failure(IllegalStateException("لا يمكن إعادة إرسال رسالة لم تفشل"))
        }

        smsSender.resendMessage(
            conversationId = conversationId,
            messageId = messageId,
            targetPhone = targetPhone,
            subscriptionId = message.simSubscriptionId
        )
    }
}
