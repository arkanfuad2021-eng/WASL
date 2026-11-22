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
        // Resolve SIM card according to the agreed hierarchy
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
 * Conforms to Section 10.4: Never retries automatically; strictly manual upon user click.
 */
class RetrySendMessageUseCase(
    private val smsSender: WaslSmsSender,
    private val simCardManager: SimCardManager,
    private val database: WaslDatabase
) {
    suspend operator fun invoke(
        messageId: String,
        targetPhone: String
    ): Result<String> = withContext(Dispatchers.IO) {
        val message = database.messageDao().getMessageById(messageId)
            ?: return@withContext Result.failure(IllegalStateException("الرسالة غير موجودة"))

        if (message.status != MessageStatus.FAILED.name) {
            return@withContext Result.failure(IllegalStateException("لا يمكن إعادة إرسال رسالة لم تفشل"))
        }

        // Set status to SENDING
        database.messageDao().updateStatus(messageId, MessageStatus.SENDING.name)

        // Resolve SIM and re-transmit
        val effectiveSubId = message.simSubscriptionId
            ?: simCardManager.resolveEffectiveSimForConversation(message.conversationId)

        smsSender.sendEncryptedMessage(
            conversationId = message.conversationId,
            plainText = message.content,
            targetPhone = targetPhone,
            subscriptionId = effectiveSubId
        )
    }
}
