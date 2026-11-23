package com.wasl.secure.telephony

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.telephony.SmsManager
import android.util.Base64
import com.wasl.secure.WaslApplication
import com.wasl.secure.core.crypto.AesGcmCipher
import com.wasl.secure.core.protocol.ChatMessageCodec
import com.wasl.secure.core.protocol.HandshakePacket
import com.wasl.secure.core.protocol.HandshakePacketCodec
import com.wasl.secure.core.util.YemenPhoneUtils
import com.wasl.secure.data.local.entity.ConversationEntity
import com.wasl.secure.data.local.entity.MessageEntity
import com.wasl.secure.domain.model.MessageStatus
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.util.UUID

class WaslSmsReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return

        when (action) {
            Telephony.Sms.Intents.SMS_RECEIVED_ACTION -> {
                handleIncomingSms(context, intent)
            }
            WaslSmsSender.ACTION_SMS_SENT -> {
                handleSmsSentReport(context, intent)
            }
            WaslSmsSender.ACTION_SMS_DELIVERED -> {
                handleSmsDeliveryReport(context, intent)
            }
        }
    }

    private fun handleIncomingSms(context: Context, intent: Intent) {
        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        if (messages.isNullOrEmpty()) return

        val fullBodyBuilder = StringBuilder()
        var originatingAddress = ""

        for (sms in messages) {
            fullBodyBuilder.append(sms.displayMessageBody ?: sms.messageBody ?: "")
            if (originatingAddress.isEmpty()) {
                originatingAddress = sms.displayOriginatingAddress ?: sms.originatingAddress ?: ""
            }
        }

        val smsBody = fullBodyBuilder.toString().trim()

        // Fast Filter: If not a WASL protocol message, exit immediately without interfering
        if (!smsBody.startsWith(HandshakePacketCodec.MAGIC_PREFIX)) {
            return
        }

        val pendingResult = goAsync()
        val app = context.applicationContext as WaslApplication

        CoroutineScope(Dispatchers.IO).launch {
            try {
                if (ChatMessageCodec.isEncryptedChatMessage(smsBody)) {
                    processIncomingEncryptedMessage(context, app, smsBody, originatingAddress)
                } else if (HandshakePacketCodec.isWaslHandshakeMessage(smsBody)) {
                    processIncomingHandshake(context, app, smsBody, originatingAddress)
                }
            } finally {
                pendingResult.finish()
            }
        }
    }

    private suspend fun processIncomingEncryptedMessage(
        context: Context,
        app: WaslApplication,
        smsBody: String,
        fromPhone: String
    ) {
        val packet = ChatMessageCodec.decode(smsBody) ?: return
        val db = app.database

        // 1. Process chunk through Reassembly Buffer
        val reassembled = MessageChunkManager.processIncomingChunk(packet, db.messageChunkDao())
            ?: return // Still waiting for remaining parts

        // 2. Resolve conversation using ID or comparable phone digits
        val comparableDigits = YemenPhoneUtils.extractComparableKey(fromPhone)
        val conv = db.conversationDao().getConversationById(reassembled.conversationId)
            ?: db.conversationDao().getConversationByComparableDigits(comparableDigits)
            ?: return

        val inboundKeyB64 = conv.inboundSessionKeyBase64 ?: return
        val inboundKey = Base64.decode(inboundKeyB64, Base64.NO_WRAP)

        // 3. Decrypt and authenticate reassembled ciphertext using AES-256-GCM
        val aad = reassembled.getParentAad()
        val decryptedBytes = try {
            AesGcmCipher.decrypt(inboundKey, reassembled.nonce, reassembled.fullCiphertextWithTag, aad)
        } catch (e: Exception) {
            return // Reassembly or authentication failed; drop corrupted payload
        }

        val plainText = String(decryptedBytes, Charsets.UTF_8)
        val now = System.currentTimeMillis()

        // 4. Insert complete message into local Room database
        val messageEntity = MessageEntity(
            id = reassembled.messageId,
            conversationId = conv.id,
            direction = "INCOMING",
            content = plainText,
            timestamp = now,
            status = MessageStatus.DECRYPTED.name,
            simSubscriptionId = null,
            totalParts = reassembled.totalChunks,
            deliveredParts = reassembled.totalChunks,
            nonceBase64 = Base64.encodeToString(reassembled.nonce, Base64.NO_WRAP),
            chunkSequence = 1
        )
        db.messageDao().insert(messageEntity)

        // 5. Update conversation snippet
        val updatedConv = conv.copy(
            lastMessage = plainText,
            lastMessageTimestamp = now,
            unreadCount = conv.unreadCount + 1
        )
        db.conversationDao().update(updatedConv)

        // 6. Post discrete notification
        val notificationHelper = NotificationHelper(context)
        notificationHelper.showIncomingMessageNotification(
            conversationId = conv.id,
            senderName = conv.contactName,
            decryptedContent = plainText,
            hideContent = false
        )
    }

    private suspend fun processIncomingHandshake(
        context: Context,
        app: WaslApplication,
        smsBody: String,
        fromPhone: String
    ) {
        val packet = HandshakePacketCodec.decode(smsBody) ?: return
        val db = app.database
        val normalizedPhone = YemenPhoneUtils.normalize(fromPhone)
        val comparableDigits = YemenPhoneUtils.extractComparableKey(fromPhone)

        when (packet) {
            is HandshakePacket.Init -> {
                val isValid = app.handshakeManager.verifyIncomingInit(packet)
                if (!isValid) return

                var conv = db.conversationDao().getConversationByComparableDigits(comparableDigits)
                val now = System.currentTimeMillis()
                val peerIdentityB64 = Base64.encodeToString(packet.identityPublicKey, Base64.NO_WRAP)

                if (conv == null) {
                    conv = ConversationEntity(
                        id = UUID.randomUUID().toString(),
                        contactName = normalizedPhone,
                        phoneNumber = normalizedPhone,
                        lastMessage = "🔒 طلب تأسيس اتصال مشفر",
                        lastMessageTimestamp = now,
                        unreadCount = 1,
                        handshakeStatus = "WAITING",
                        defaultSubscriptionId = null,
                        rejectedAt = null,
                        currentRequestId = packet.requestId,
                        peerIdentityKeyBase64 = peerIdentityB64,
                        sessionKeyBase64 = null,
                        inboundSessionKeyBase64 = null,
                        nextOutboundCounter = 1L
                    )
                    db.conversationDao().insertOrUpdate(conv)
                } else {
                    db.conversationDao().update(
                        conv.copy(
                            handshakeStatus = "WAITING",
                            currentRequestId = packet.requestId,
                            peerIdentityKeyBase64 = peerIdentityB64,
                            lastMessage = "🔒 طلب تأسيس اتصال مشفر",
                            lastMessageTimestamp = now,
                            unreadCount = conv.unreadCount + 1
                        )
                    )
                }

                val notificationHelper = NotificationHelper(context)
                notificationHelper.showIncomingMessageNotification(
                    conversationId = conv.id,
                    senderName = conv.contactName,
                    decryptedContent = "طلب تأسيس اتصال مشفر جديد",
                    hideContent = true
                )
            }
            is HandshakePacket.Response -> {
                val conv = db.conversationDao().getConversationByComparableDigits(comparableDigits) ?: return
                val confirmResult = try {
                    app.handshakeManager.processResponse(packet)
                } catch (e: Exception) {
                    null
                } ?: return

                val outKeyB64 = Base64.encodeToString(confirmResult.sessionKeys.outboundKey, Base64.NO_WRAP)
                val inKeyB64 = Base64.encodeToString(confirmResult.sessionKeys.inboundKey, Base64.NO_WRAP)
                val peerIdentityB64 = Base64.encodeToString(packet.identityPublicKey, Base64.NO_WRAP)

                db.conversationDao().update(
                    conv.copy(
                        handshakeStatus = "READY",
                        peerIdentityKeyBase64 = peerIdentityB64,
                        sessionKeyBase64 = outKeyB64,
                        inboundSessionKeyBase64 = inKeyB64,
                        lastMessage = "✅ تم تأسيس التشفير بنجاح",
                        lastMessageTimestamp = System.currentTimeMillis()
                    )
                )

                // Transmit confirmation SMS back to peer
                try {
                    val smsManager = SmsManager.getDefault()
                    smsManager.sendTextMessage(normalizedPhone, null, confirmResult.smsPayload, null, null)
                } catch (e: Exception) {
                    // Suppressed
                }
            }
            is HandshakePacket.Confirm -> {
                val conv = db.conversationDao().getConversationByComparableDigits(comparableDigits) ?: return
                db.conversationDao().update(
                    conv.copy(
                        handshakeStatus = "READY",
                        lastMessage = "✅ تم تأسيس التشفير بنجاح",
                        lastMessageTimestamp = System.currentTimeMillis()
                    )
                )
            }
            is HandshakePacket.Reject -> {
                val conv = db.conversationDao().getConversationByComparableDigits(comparableDigits) ?: return
                db.conversationDao().update(
                    conv.copy(
                        handshakeStatus = "REJECTED",
                        rejectedAt = System.currentTimeMillis(),
                        lastMessage = "تم رفض طلب الاتصال المشفر",
                        lastMessageTimestamp = System.currentTimeMillis()
                    )
                )
            }
        }
    }

    private fun handleSmsSentReport(context: Context, intent: Intent) {
        val messageId = intent.getStringExtra(WaslSmsSender.EXTRA_MESSAGE_ID) ?: return
        val isSuccess = resultCode == Activity.RESULT_OK
        val app = context.applicationContext as WaslApplication

        CoroutineScope(Dispatchers.IO).launch {
            val status = if (isSuccess) MessageStatus.SENT.name else MessageStatus.FAILED.name
            app.database.messageDao().updateStatus(messageId, status)
        }
    }

    private fun handleSmsDeliveryReport(context: Context, intent: Intent) {
        val messageId = intent.getStringExtra(WaslSmsSender.EXTRA_MESSAGE_ID) ?: return
        val app = context.applicationContext as WaslApplication

        CoroutineScope(Dispatchers.IO).launch {
            app.database.messageDao().recordDeliveryReport(messageId)
        }
    }
}
