package com.wasl.secure.telephony

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.telephony.SmsManager
import android.util.Base64
import androidx.room.withTransaction
import com.wasl.secure.core.crypto.AesGcmCipher
import com.wasl.secure.core.crypto.MonotonicNonceManager
import com.wasl.secure.core.protocol.ChatMessageCodec
import com.wasl.secure.core.protocol.ChatMessagePacket
import com.wasl.secure.data.local.WaslDatabase
import com.wasl.secure.data.local.entity.MessageEntity
import com.wasl.secure.data.local.entity.OutboundAttemptEntity
import com.wasl.secure.domain.model.MessageStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicInteger

class WaslSmsSender(
    private val context: Context,
    private val database: WaslDatabase
) {
    companion object {
        const val ACTION_SMS_SENT = "com.wasl.secure.SMS_SENT_ACTION"
        const val ACTION_SMS_DELIVERED = "com.wasl.secure.SMS_DELIVERED_ACTION"
        const val EXTRA_MESSAGE_ID = "extra_message_id"
        const val EXTRA_CONVERSATION_ID = "extra_conversation_id"
        const val EXTRA_ATTEMPT_ID = "extra_attempt_id"
        const val EXTRA_CHUNK_INDEX = "extra_chunk_index"
        const val EXTRA_IS_CONFIRM = "extra_is_confirm"
        const val EXTRA_TOTAL_PARTS = "extra_total_parts"

        private val counterReservationMutex = Mutex()
        private val secureRandom = SecureRandom()
        private val pendingIntentRequestCounter = AtomicInteger(1)

        private fun nextPendingIntentRequestCode(): Int {
            return pendingIntentRequestCounter.getAndUpdate { current ->
                if (current == Int.MAX_VALUE) 1 else current + 1
            }
        }

        fun generate16HexId(): String {
            val bytes = ByteArray(8)
            secureRandom.nextBytes(bytes)
            return bytes.joinToString("") { "%02x".format(it) }
        }
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

            // Strictly prevent message transmission if identity is compromised or in security alert state
            if (conv.identityState == "KEY_CHANGED_ALERT" || conv.handshakeStatus == "KEY_CHANGED_ALERT") {
                return@withContext Result.failure(
                    IllegalStateException("تم حظر الإرسال: تم رصد تغيير غير موثوق في هوية الطرف الآخر!")
                )
            }

            // Strictly prevent message transmission if handshake is not READY
            if (conv.handshakeStatus != "READY") {
                return@withContext Result.failure(
                    IllegalStateException("لا يمكن إرسال الرسائل: المصافحة غير مكتملة بعد (الحالة الحالية: ${conv.handshakeStatus})")
                )
            }

            val sessionKeyB64 = conv.sessionKeyBase64
                ?: return@withContext Result.failure(IllegalStateException("لم يتم تأسيس مفاتيح المحادثة بعد"))

            // 1. Atomically reserve unique Monotonic Counter from Room DB under mutex & transaction
            val currentCounter = counterReservationMutex.withLock {
                database.conversationDao().reserveNextOutboundCounter(conversationId)
            }
            val messageId = generate16HexId()
            val packetConvId = conv.id.replace("-", "").take(16)

            val outboundKey = Base64.decode(sessionKeyB64, Base64.NO_WRAP)

            // 2. Generate guaranteed unique Nonce (4-byte prefix + 8-byte counter)
            val nonceManager = MonotonicNonceManager(initialCounter = currentCounter)
            val (nonce, _) = nonceManager.generateNextNonce()

            // 3. Encrypt plaintext via AES-256-GCM
            val plainBytes = plainText.toByteArray(Charsets.UTF_8)

            // Prepare AAD placeholder to determine chunks
            val testPackets = MessageChunkManager.fragmentCiphertext(
                conversationId = packetConvId,
                messageId = messageId,
                attemptId = "0001",
                sequenceNumber = currentCounter,
                nonce = nonce,
                ciphertextWithTag = ByteArray(plainBytes.size + 16)
            )
            val totalExpectedChunks = testPackets.size

            val aad = "$packetConvId:$messageId:$currentCounter:1/$totalExpectedChunks".toByteArray(Charsets.UTF_8)
            val encryptResult = AesGcmCipher.encrypt(outboundKey, nonce, plainBytes, aad)
            val ciphertextWithTag = encryptResult.ciphertextWithTag

            // 4. Fragment ciphertext into SMS packets
            val packets = MessageChunkManager.fragmentCiphertext(
                conversationId = packetConvId,
                messageId = messageId,
                attemptId = "0001",
                sequenceNumber = currentCounter,
                nonce = nonce,
                ciphertextWithTag = ciphertextWithTag
            )

            // 5. Obtain fixed SmsManager for the designated SIM (All chunks use this SIM)
            val smsManager = if (subscriptionId != null && subscriptionId != -1) {
                SmsManager.getSmsManagerForSubscriptionId(subscriptionId)
            } else {
                SmsManager.getDefault()
            }

            // Verify that each packet strictly fits within a single SMS segment
            for (packet in packets) {
                val smsBody = ChatMessageCodec.encode(packet)
                val divided = smsManager.divideMessage(smsBody)
                require(divided.size == 1) {
                    "خطأ تشغيلي: الحزمة المشفرة تجاوزت سعة رسالة SMS واحدة (الحجم: ${divided.size})!"
                }
            }

            // 6 & 7. Atomically insert parent message AND initial outbound attempt in a single Room transaction
            val now = System.currentTimeMillis()
            val messageEntity = MessageEntity(
                conversationId = conversationId,
                id = messageId,
                direction = "OUTGOING",
                content = plainText,
                timestamp = now,
                status = MessageStatus.SENDING.name,
                simSubscriptionId = subscriptionId,
                totalParts = packets.size,
                deliveredParts = 0,
                nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP),
                chunkSequence = 1,
                attemptCount = 1,
                currentAttemptId = "0001",
                ciphertextBase64 = Base64.encodeToString(ciphertextWithTag, Base64.NO_WRAP)
            )
            val attemptEntity = OutboundAttemptEntity(
                conversationId = conversationId,
                messageId = messageId,
                attemptId = "0001",
                totalChunks = packets.size,
                sentChunks = 0,
                deliveredChunks = 0,
                sentIndices = "",
                deliveredIndices = "",
                status = "SENDING",
                createdAt = now
            )

            database.withTransaction {
                database.messageDao().insertStrict(messageEntity)
                database.outboundAttemptDao().insert(attemptEntity)
                database.conversationDao().updateLastMessage(conversationId, plainText, now)
            }

            // 8. Transmit all chunks from the designated SIM; atomically mark FAILED on dispatch error
            transmitPacketsOrFailAtomic(
                smsManager = smsManager,
                targetPhone = targetPhone,
                conversationId = conversationId,
                messageId = messageId,
                attemptId = "0001",
                packets = packets
            )

            Result.success(messageId)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Resends an existing message using its persistently stored ciphertext and Nonce.
     * Guaranteed rules from Phase 3:
     * - Strictly requires READY handshake status.
     * - Scoped message lookup strictly by (conversationId, messageId).
     * - Strictly enforces using the original SIM stored in message.simSubscriptionId; rejects SIM changes.
     * - Atomically updates parent message and inserts outbound attempt record in a single Room transaction.
     * - NO re-encryption, NO new counter reservation.
     * - Maximum 65,535 attempts enforced; strictly NO wraparound allowed.
     * - Distinct URI-backed PendingIntents preventing collisions.
     */
    suspend fun resendMessage(
        conversationId: String,
        messageId: String,
        targetPhone: String,
        subscriptionId: Int? = null
    ): Result<String> = withContext(Dispatchers.IO) {
        try {
            val initialMessage = database.messageDao().getMessageByConversationAndId(conversationId, messageId)
                ?: return@withContext Result.failure(IllegalStateException("الرسالة غير موجودة في هذه المحادثة"))

            // Strictly prohibit switching SIM card during retry
            if (subscriptionId != null && subscriptionId != initialMessage.simSubscriptionId) {
                return@withContext Result.failure(
                    IllegalStateException("لا يُسمح بتغيير الشريحة عند إعادة إرسال الرسالة؛ يجب استخدام الشريحة الأصلية المحفوظة فقط")
                )
            }

            // Always use original SIM saved on message
            val originalSubId = initialMessage.simSubscriptionId
            val smsManager = if (originalSubId != null && originalSubId != -1) {
                SmsManager.getSmsManagerForSubscriptionId(originalSubId)
            } else {
                SmsManager.getDefault()
            }

            val ciphertextB64 = initialMessage.ciphertextBase64
                ?: return@withContext Result.failure(IllegalStateException("لا توجد حمولة مشفرة محفوظة لإعادة الإرسال"))
            val nonceB64 = initialMessage.nonceBase64
                ?: return@withContext Result.failure(IllegalStateException("لا يوجد Nonce محفوظ للرسالة"))

            val ciphertextWithTag = Base64.decode(ciphertextB64, Base64.NO_WRAP)
            val nonce = Base64.decode(nonceB64, Base64.NO_WRAP)
            val sequenceNumber = if (nonce.size == 12) ByteBuffer.wrap(nonce).getLong(4) else 0L

            // Atomically verify READY status, reserve next attemptId, validate packets,
            // update message row, and insert new outbound attempt in a single Room transaction
            val (packets, newAttemptId) = database.withTransaction {
                val conv = database.conversationDao().getConversationById(conversationId)
                    ?: throw IllegalStateException("المحادثة غير موجودة")

                if (conv.identityState == "KEY_CHANGED_ALERT" || conv.handshakeStatus == "KEY_CHANGED_ALERT") {
                    throw IllegalStateException("تم حظر الإرسال: تم رصد تغيير غير موثوق في هوية الطرف الآخر!")
                }

                if (conv.handshakeStatus != "READY") {
                    throw IllegalStateException("لا يمكن إعادة إرسال الرسائل: المصافحة غير مكتملة بعد (الحالة الحالية: ${conv.handshakeStatus})")
                }

                val packetConvId = conv.id.replace("-", "").take(16)
                val (_, reservedAttemptId) = database.messageDao().reserveNextAttemptAtomic(conversationId, messageId)

                val generatedPackets = MessageChunkManager.fragmentCiphertext(
                    conversationId = packetConvId,
                    messageId = messageId,
                    attemptId = reservedAttemptId,
                    sequenceNumber = sequenceNumber,
                    nonce = nonce,
                    ciphertextWithTag = ciphertextWithTag
                )

                for (packet in generatedPackets) {
                    val smsBody = ChatMessageCodec.encode(packet)
                    val divided = smsManager.divideMessage(smsBody)
                    require(divided.size == 1) {
                        "خطأ تشغيلي: الحزمة المشفرة تجاوزت سعة رسالة SMS واحدة (الحجم: ${divided.size})!"
                    }
                }

                val attemptEntity = OutboundAttemptEntity(
                    conversationId = conversationId,
                    messageId = messageId,
                    attemptId = reservedAttemptId,
                    totalChunks = generatedPackets.size,
                    sentChunks = 0,
                    deliveredChunks = 0,
                    sentIndices = "",
                    deliveredIndices = "",
                    status = "SENDING",
                    createdAt = System.currentTimeMillis()
                )
                database.outboundAttemptDao().insert(attemptEntity)

                Pair(generatedPackets, reservedAttemptId)
            }

            // Transmit all chunks for new attempt using original SIM; atomically mark FAILED on dispatch error
            transmitPacketsOrFailAtomic(
                smsManager = smsManager,
                targetPhone = targetPhone,
                conversationId = conversationId,
                messageId = messageId,
                attemptId = newAttemptId,
                packets = packets
            )

            Result.success(messageId)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Transmits all packets for an attempt via SmsManager using distinct URI-backed PendingIntents.
     * If any exception occurs during dispatch, atomically marks both the active outbound attempt
     * and parent message as FAILED so late reports cannot revert the status to SENT/DELIVERED.
     */
    private suspend fun transmitPacketsOrFailAtomic(
        smsManager: SmsManager,
        targetPhone: String,
        conversationId: String,
        messageId: String,
        attemptId: String,
        packets: List<ChatMessagePacket>
    ) {
        try {
            for (packet in packets) {
                val smsBody = ChatMessageCodec.encode(packet)

                val sentIntent = PendingIntent.getBroadcast(
                    context,
                    nextPendingIntentRequestCode(),
                    Intent(context, WaslSmsReceiver::class.java).apply {
                        action = ACTION_SMS_SENT
                        data = Uri.parse("wasl://sms/send/$conversationId/$messageId/$attemptId/${packet.chunkIndex}")
                        putExtra(EXTRA_MESSAGE_ID, messageId)
                        putExtra(EXTRA_CONVERSATION_ID, conversationId)
                        putExtra(EXTRA_ATTEMPT_ID, attemptId)
                        putExtra(EXTRA_CHUNK_INDEX, packet.chunkIndex)
                    },
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )

                val deliveredIntent = PendingIntent.getBroadcast(
                    context,
                    nextPendingIntentRequestCode(),
                    Intent(context, WaslSmsReceiver::class.java).apply {
                        action = ACTION_SMS_DELIVERED
                        data = Uri.parse("wasl://sms/delivered/$conversationId/$messageId/$attemptId/${packet.chunkIndex}")
                        putExtra(EXTRA_MESSAGE_ID, messageId)
                        putExtra(EXTRA_CONVERSATION_ID, conversationId)
                        putExtra(EXTRA_ATTEMPT_ID, attemptId)
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
        } catch (e: Exception) {
            withContext(NonCancellable) {
                database.withTransaction {
                    database.outboundAttemptDao().updateStatus(
                        conversationId,
                        messageId,
                        attemptId,
                        MessageStatus.FAILED.name
                    )
                    val currentMessage = database.messageDao().getMessageByConversationAndId(
                        conversationId,
                        messageId
                    )
                    if (currentMessage != null && currentMessage.currentAttemptId == attemptId) {
                        database.messageDao().updateStatus(
                            conversationId,
                            messageId,
                            MessageStatus.FAILED.name
                        )
                    }
                }
            }
            throw e
        }
    }

    /**
     * Transmits a Handshake CONFIRM packet via SMS, persisting part count in DB before dispatch
     * and attaching sent intents so progress survives process restarts before transitioning to READY.
     */
    suspend fun sendConfirmPacket(
        conversationId: String,
        targetPhone: String,
        confirmPayload: String,
        confirmMessageId: String,
        subscriptionId: Int?
    ) = withContext(Dispatchers.IO) {
        val smsManager = if (subscriptionId != null && subscriptionId != -1) {
            SmsManager.getSmsManagerForSubscriptionId(subscriptionId)
        } else {
            SmsManager.getDefault()
        }

        val parts = smsManager.divideMessage(confirmPayload)
        val totalParts = parts.size

        // Persist CONFIRM tracking state in DB BEFORE dispatching SMS parts
        database.conversationDao().initPendingConfirmAttempt(
            id = conversationId,
            confirmMessageId = confirmMessageId,
            totalParts = totalParts
        )

        for (i in parts.indices) {
            val partText = parts[i]
            val sentIntent = PendingIntent.getBroadcast(
                context,
                nextPendingIntentRequestCode(),
                Intent(context, WaslSmsReceiver::class.java).apply {
                    action = ACTION_SMS_SENT
                    data = Uri.parse("wasl://handshake/confirm/$conversationId/$confirmMessageId/${i + 1}")
                    putExtra(EXTRA_MESSAGE_ID, confirmMessageId)
                    putExtra(EXTRA_CONVERSATION_ID, conversationId)
                    putExtra(EXTRA_IS_CONFIRM, true)
                    putExtra(EXTRA_CHUNK_INDEX, i + 1)
                    putExtra(EXTRA_TOTAL_PARTS, totalParts)
                },
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )

            smsManager.sendTextMessage(targetPhone, null, partText, sentIntent, null)
        }
    }
}
