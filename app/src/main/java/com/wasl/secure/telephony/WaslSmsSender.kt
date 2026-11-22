package com.wasl.secure.telephony

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.telephony.SmsManager
import android.util.Base64
import com.wasl.secure.core.crypto.AesGcmCipher
import com.wasl.secure.core.crypto.MonotonicNonceManager
import com.wasl.secure.core.protocol.ChatMessageCodec
import com.wasl.secure.data.local.WaslDatabase
import com.wasl.secure.data.local.entity.MessageEntity
import com.wasl.secure.domain.model.MessageStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.UUID

class WaslSmsSender(
    private val context: Context,
    private val database: WaslDatabase
) {
    companion object {
        const val ACTION_SMS_SENT = "com.wasl.secure.SMS_SENT_ACTION"
        const val ACTION_SMS_DELIVERED = "com.wasl.secure.SMS_DELIVERED_ACTION"
        const val EXTRA_MESSAGE_ID = "extra_message_id"
        const val EXTRA_CONVERSATION_ID = "extra_conversation_id"
        const val EXTRA_CHUNK_INDEX = "extra_chunk_index"
    }

    /**
     * Encrypts, fragments (if needed), and transmits an SMS message.
     * Guaranteed rule from Section 7: ALL chunks are sent from the exact same SIM.
     */
    suspend fun sendEncryptedMessage(
        conversationId: String,
        plainText: String,
        targetPhone: String,
        subscriptionId: Int?
    ): Result<String> = withContext(Dispatchers.IO) {
        try {
            val conv = database.conversationDao().getConversationById(conversationId)
                ?: return@withContext Result.failure(IllegalStateException("المحادثة غير موجودة"))

            val sessionKeyB64 = conv.sessionKeyBase64
                ?: return@withContext Result.failure(IllegalStateException("لم يتم تأسيس مفاتيح المحادثة بعد"))

            val outboundKey = Base64.decode(sessionKeyB64, Base64.NO_WRAP)
            val currentCounter = conv.nextOutboundCounter
            val messageId = UUID.randomUUID().toString()

            // 1. Generate guaranteed unique Nonce
            val nonceManager = MonotonicNonceManager(initialCounter = currentCounter)
            val (nonce, _) = nonceManager.generateNextNonce()

            // Persist the updated counter before transmission
            database.conversationDao().incrementOutboundCounter(conversationId)

            // 2. Encrypt plaintext via AES-256-GCM
            val plainBytes = plainText.toByteArray(Charsets.UTF_8)

            // Prepare AAD placeholder to determine chunks
            val testPackets = MessageChunkManager.fragmentCiphertext(
                conversationId, messageId, currentCounter, nonce, ByteArray(plainBytes.size + 16)
            )
            val totalExpectedChunks = testPackets.size

            val aad = "$conversationId:$messageId:$currentCounter:1/$totalExpectedChunks".toByteArray(Charsets.UTF_8)
            val encryptResult = AesGcmCipher.encrypt(outboundKey, nonce, plainBytes, aad)

            // 3. Fragment ciphertext into SMS packets
            val packets = MessageChunkManager.fragmentCiphertext(
                conversationId = conversationId,
                messageId = messageId,
                sequenceNumber = currentCounter,
                nonce = nonce,
                ciphertextWithTag = encryptResult.ciphertextWithTag
            )

            // 4. Insert parent message into Room database
            val messageEntity = MessageEntity(
                id = messageId,
                conversationId = conversationId,
                direction = "OUTGOING",
                content = plainText,
                timestamp = System.currentTimeMillis(),
                status = MessageStatus.SENDING.name,
                simSubscriptionId = subscriptionId,
                totalParts = packets.size,
                deliveredParts = 0,
                nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP),
                chunkSequence = 1
            )
            database.messageDao().insert(messageEntity)

            // 5. Obtain fixed SmsManager for the designated SIM (All chunks use this SIM)
            val smsManager = if (subscriptionId != null && subscriptionId != -1) {
                SmsManager.getSmsManagerForSubscriptionId(subscriptionId)
            } else {
                SmsManager.getDefault()
            }

            // 6. Transmit all chunks from the designated SIM
            for (packet in packets) {
                val smsBody = ChatMessageCodec.encode(packet)

                val sentIntent = PendingIntent.getBroadcast(
                    context,
                    (messageId + "_" + packet.chunkIndex).hashCode(),
                    Intent(ACTION_SMS_SENT).apply {
                        putExtra(EXTRA_MESSAGE_ID, messageId)
                        putExtra(EXTRA_CONVERSATION_ID, conversationId)
                        putExtra(EXTRA_CHUNK_INDEX, packet.chunkIndex)
                    },
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )

                val deliveredIntent = PendingIntent.getBroadcast(
                    context,
                    (messageId + "_" + packet.chunkIndex + "_del").hashCode(),
                    Intent(ACTION_SMS_DELIVERED).apply {
                        putExtra(EXTRA_MESSAGE_ID, messageId)
                        putExtra(EXTRA_CONVERSATION_ID, conversationId)
                        putExtra(EXTRA_CHUNK_INDEX, packet.chunkIndex)
                    },
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )

                smsManager.sendTextMessage(
                    targetPhone,
                    null,
                    smsBody,
                    sentIntent,
                    deliveredIntent
                )
            }

            Result.success(messageId)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
