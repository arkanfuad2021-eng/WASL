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
import com.wasl.secure.core.crypto.Curve25519Engine
import com.wasl.secure.core.protocol.ChatMessageCodec
import com.wasl.secure.core.protocol.HandshakePacket
import androidx.room.withTransaction
import com.wasl.secure.core.protocol.HandshakePacketCodec
import com.wasl.secure.core.util.YemenPhoneUtils
import com.wasl.secure.data.local.entity.ConversationEntity
import com.wasl.secure.data.local.entity.HandshakeEntity
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

        // 1. Validate sender phone and couple strictly to packet conversationId BEFORE persisting any chunk
        val comparableDigits = YemenPhoneUtils.extractComparableKey(fromPhone)
        if (comparableDigits.isBlank()) return

        val convByPhone = db.conversationDao().getConversationByComparableDigits(comparableDigits)
        val convByPacket = db.conversationDao().getConversationByPacketConvId(packet.conversationId)
            ?: db.conversationDao().getConversationById(packet.conversationId)

        if (convByPhone == null || convByPacket == null || convByPhone.id != convByPacket.id) {
            // Mismatch between carrier sender phone and packet conversation ID!
            // Spoofing or misdirected packet -> drop before buffering any chunk
            return
        }
        val conv = convByPacket

        // Prohibit processing or buffering if identity has changed
        if (conv.identityState == "KEY_CHANGED_ALERT" || conv.handshakeStatus == "KEY_CHANGED_ALERT") {
            return
        }

        val inboundKeyB64 = conv.inboundSessionKeyBase64 ?: return
        val inboundKey = Base64.decode(inboundKeyB64, Base64.NO_WRAP)

        // 2. Purge expired chunks (>24h), then process chunk through Reassembly Buffer
        db.messageChunkDao().deleteExpiredChunks(
            System.currentTimeMillis() - MessageChunkManager.CHUNK_EXPIRY_MS
        )
        val reassembled = MessageChunkManager.processIncomingChunk(packet, db.messageChunkDao())
            ?: return // Still waiting for remaining parts of this attempt

        // 3. Decrypt and authenticate reassembled ciphertext using AES-256-GCM
        val aad = reassembled.getParentAad()
        val decryptedBytes = try {
            AesGcmCipher.decrypt(inboundKey, reassembled.nonce, reassembled.fullCiphertextWithTag, aad)
        } catch (e: Exception) {
            // Decryption or authentication failed; retain chunks in DB for security analysis/retry without deletion
            return
        }

        val plainText = String(decryptedBytes, Charsets.UTF_8)
        val now = System.currentTimeMillis()

        // 4. Construct complete message entity
        val messageEntity = MessageEntity(
            conversationId = conv.id,
            id = reassembled.messageId,
            direction = "INCOMING",
            content = plainText,
            timestamp = now,
            status = MessageStatus.DECRYPTED.name,
            simSubscriptionId = null,
            totalParts = reassembled.totalChunks,
            deliveredParts = reassembled.totalChunks,
            nonceBase64 = Base64.encodeToString(reassembled.nonce, Base64.NO_WRAP),
            chunkSequence = 1,
            attemptCount = 1,
            currentAttemptId = reassembled.attemptId,
            ciphertextBase64 = null
        )

        // 5. Atomically insert and deduplicate inside database transaction
        val isNewlyInserted = db.messageDao().insertReassembledMessageIfNew(
            conversationId = conv.id,
            message = messageEntity,
            conversationSnippet = plainText,
            timestamp = now
        )

        if (isNewlyInserted) {
            // Clean up all pending chunks for this message across all attempts using packet conversationId
            db.messageChunkDao().deleteChunksForMessage(reassembled.conversationId, reassembled.messageId)

            // Discrete notification
            val notificationHelper = NotificationHelper(context)
            notificationHelper.showIncomingMessageNotification(
                conversationId = conv.id,
                senderName = conv.contactName,
                decryptedContent = plainText,
                hideContent = false
            )
        } else {
            // Message already inserted by another concurrent or prior attempt.
            // Quietly suppress notifications, suppress unread count, and delete this attempt's chunks.
            db.messageChunkDao().deleteChunksForAttempt(
                conversationId = reassembled.conversationId,
                messageId = reassembled.messageId,
                attemptId = reassembled.attemptId
            )
        }
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
                val storedIncomingReq = db.handshakeDao().getByRequestId(packet.requestId)
                val persistedPeerEphKeyFromDb = storedIncomingReq?.peerEphemeralPublicKeyBase64?.let {
                    try {
                        Base64.decode(it, Base64.NO_WRAP)
                    } catch (e: Exception) {
                        null
                    }
                }
                if (storedIncomingReq?.peerEphemeralPublicKeyBase64 != null && persistedPeerEphKeyFromDb == null) {
                    return
                }

                val isValid = app.handshakeManager.verifyIncomingInit(
                    packet = packet,
                    expectedPeerEphemeralKey = persistedPeerEphKeyFromDb
                )
                if (!isValid) return

                val conv = db.conversationDao().getConversationByComparableDigits(comparableDigits)
                val now = System.currentTimeMillis()
                val peerIdentityB64 = Base64.encodeToString(packet.identityPublicKey, Base64.NO_WRAP)

                // Guard: Never allow state transitions to bypass KEY_CHANGED_ALERT security lockdown
                if (conv != null && (conv.identityState == "KEY_CHANGED_ALERT" || conv.handshakeStatus == "KEY_CHANGED_ALERT")) {
                    return
                }

                // 1. Peer Identity Pinning & Key Change Detection
                if (conv != null && conv.identityState == "PINNED_TOFU" && conv.peerIdentityKeyBase64 != null) {
                    if (conv.peerIdentityKeyBase64 != peerIdentityB64) {
                        // Key changed for an established contact -> Stop & alert user!
                        var alertedConv: ConversationEntity? = null
                        db.withTransaction {
                            val convTx = db.conversationDao().getConversationById(conv.id) ?: return@withTransaction
                            if (convTx.identityState == "KEY_CHANGED_ALERT" || convTx.handshakeStatus == "KEY_CHANGED_ALERT") {
                                return@withTransaction
                            }
                            convTx.currentRequestId?.let { activeReqId ->
                                val activeReq = db.handshakeDao().getByRequestId(activeReqId)
                                if (activeReq != null && activeReq.status in listOf("WAITING", "ACCEPTED", "PENDING_CONFIRM_SEND")) {
                                    db.handshakeDao().updateStatusAndRejectedAt(
                                        requestId = activeReqId,
                                        status = "KEY_CHANGED_ALERT",
                                        rejectedAt = null
                                    )
                                }
                            }
                            val updated = convTx.copy(
                                identityState = "KEY_CHANGED_ALERT",
                                handshakeStatus = "KEY_CHANGED_ALERT",
                                lastMessage = "⚠️ تحذير أمني: تغيرت الهوية الرقمية للطرف الآخر! تم إيقاف المحادثة.",
                                lastMessageTimestamp = now,
                                unreadCount = convTx.unreadCount + 1
                            )
                            db.conversationDao().update(updated)
                            alertedConv = updated
                        }
                        alertedConv?.let {
                            val notificationHelper = NotificationHelper(context)
                            notificationHelper.showIncomingMessageNotification(
                                conversationId = it.id,
                                senderName = it.contactName,
                                decryptedContent = "تحذير: تغيرت الهوية الرقمية للطرف الآخر!",
                                hideContent = true
                            )
                        }
                        return
                    }
                }

                // 2. Idempotent Retry: If Bob receives duplicate incoming INIT for an already accepted incoming request, re-send RESPONSE using persisted keys & conversation SIM
                if (
                    conv != null &&
                    conv.currentRequestId == packet.requestId &&
                    storedIncomingReq != null &&
                    storedIncomingReq.isIncoming &&
                    storedIncomingReq.status == "ACCEPTED" &&
                    conv.sessionKeyBase64 != null &&
                    conv.pendingConfirmationKeyBase64 != null
                ) {
                    try {
                        val persistedPeerEphKey = persistedPeerEphKeyFromDb ?: return
                        if (!persistedPeerEphKey.contentEquals(packet.ephemeralPublicKey)) {
                            return
                        }
                        val peerIdentityKey = Base64.decode(peerIdentityB64, Base64.NO_WRAP)
                        val ourEphPriv = storedIncomingReq.ephemeralPrivateKeyBase64?.let { Base64.decode(it, Base64.NO_WRAP) }
                        val ourEphKeyPair = ourEphPriv?.let {
                            val pub = Curve25519Engine.getX25519PublicKeyFromPrivateKey(it)
                            Curve25519Engine.KeyPairBytes(it, pub)
                        }
                        if (ourEphKeyPair == null && app.handshakeManager.getEphemeralKeyPair(packet.requestId) == null) {
                            return
                        }
                        val respResult = app.handshakeManager.acceptInitRequest(
                            requestId = packet.requestId,
                            peerIdentityKey = peerIdentityKey,
                            persistedPeerEphemeralKey = persistedPeerEphKey,
                            persistedOurEphemeralKeyPair = ourEphKeyPair,
                            incomingPeerEphemeralKey = packet.ephemeralPublicKey
                        )
                        val effectiveSubId = app.simCardManager.resolveEffectiveSimForConversation(conv.id)
                        val smsManager = if (effectiveSubId != null && effectiveSubId != -1) {
                            SmsManager.getSmsManagerForSubscriptionId(effectiveSubId)
                        } else {
                            SmsManager.getDefault()
                        }
                        smsManager.sendTextMessage(normalizedPhone, null, respResult.smsPayload, null, null)
                    } catch (e: Exception) {
                        // Suppressed
                    }
                    return
                }

                // 3. Normal Incoming INIT Processing (Atomic across conversations & handshake_requests)
                val peerEphemeralB64 = Base64.encodeToString(packet.ephemeralPublicKey, Base64.NO_WRAP)
                val persistedPair = db.withTransaction {
                    val convTx = db.conversationDao().getConversationByComparableDigits(comparableDigits)
                    if (convTx != null && (convTx.identityState == "KEY_CHANGED_ALERT" || convTx.handshakeStatus == "KEY_CHANGED_ALERT")) {
                        return@withTransaction null
                    }

                    // Do not allow replayed INIT packets to reopen already accepted, ready, rejected, or outgoing requestIds,
                    // or to alter a previously saved peer ephemeral public key for the same requestId
                    val existingReqTx = db.handshakeDao().getByRequestId(packet.requestId)
                    if (existingReqTx != null && (!existingReqTx.isIncoming || existingReqTx.status != "WAITING")) {
                        return@withTransaction null
                    }
                    if (existingReqTx?.peerEphemeralPublicKeyBase64 != null && existingReqTx.peerEphemeralPublicKeyBase64 != peerEphemeralB64) {
                        return@withTransaction null
                    }

                    val isNewRequest = convTx == null || convTx.currentRequestId != packet.requestId
                    val savedConv = if (convTx == null) {
                        val newConv = ConversationEntity(
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
                            nextOutboundCounter = 1L,
                            identityState = "UNPINNED"
                        )
                        db.conversationDao().insertOrUpdate(newConv)
                        newConv
                    } else {
                        val updatedConv = convTx.copy(
                            handshakeStatus = "WAITING",
                            rejectedAt = null,
                            currentRequestId = packet.requestId,
                            peerIdentityKeyBase64 = peerIdentityB64,
                            lastMessage = "🔒 طلب تأسيس اتصال مشفر",
                            lastMessageTimestamp = now,
                            unreadCount = if (isNewRequest) convTx.unreadCount + 1 else convTx.unreadCount
                        )
                        db.conversationDao().update(updatedConv)
                        updatedConv
                    }

                    // Persist pending incoming handshake request with peer's ephemeral public key
                    val handshakeReq = HandshakeEntity(
                        requestId = packet.requestId,
                        conversationId = savedConv.id,
                        phoneNumber = normalizedPhone,
                        isIncoming = true,
                        status = "WAITING",
                        createdAt = existingReqTx?.createdAt ?: now,
                        expiredAt = 0L,
                        rejectedAt = null,
                        ephemeralPrivateKeyBase64 = existingReqTx?.ephemeralPrivateKeyBase64,
                        peerEphemeralPublicKeyBase64 = peerEphemeralB64
                    )
                    db.handshakeDao().insertOrUpdate(handshakeReq)
                    Pair(savedConv, isNewRequest)
                } ?: return

                if (persistedPair.second) {
                    val savedConv = persistedPair.first
                    val notificationHelper = NotificationHelper(context)
                    notificationHelper.showIncomingMessageNotification(
                        conversationId = savedConv.id,
                        senderName = savedConv.contactName,
                        decryptedContent = "طلب تأسيس اتصال مشفر جديد",
                        hideContent = true
                    )
                }
            }
            is HandshakePacket.Response -> {
                val conv = db.conversationDao().getConversationByComparableDigits(comparableDigits) ?: return
                // Guard: Never allow state transitions to bypass KEY_CHANGED_ALERT security lockdown
                if (conv.identityState == "KEY_CHANGED_ALERT" || conv.handshakeStatus == "KEY_CHANGED_ALERT") return
                // Strict check: Response must match our active pending outgoing request ID
                if (conv.currentRequestId != packet.requestId || conv.handshakeStatus != "WAITING") return

                val storedReq = db.handshakeDao().getByRequestId(packet.requestId)
                if (storedReq == null || storedReq.isIncoming || storedReq.status != "WAITING") return

                val peerIdentityB64 = Base64.encodeToString(packet.identityPublicKey, Base64.NO_WRAP)
                val now = System.currentTimeMillis()

                // 1. Peer Identity Pinning & Key Change Detection
                if (conv.identityState == "PINNED_TOFU" && conv.peerIdentityKeyBase64 != null) {
                    if (conv.peerIdentityKeyBase64 != peerIdentityB64) {
                        // Key changed for an established contact -> Stop & alert user!
                        var alertedConv: ConversationEntity? = null
                        db.withTransaction {
                            val convTx = db.conversationDao().getConversationById(conv.id) ?: return@withTransaction
                            if (
                                convTx.currentRequestId != packet.requestId ||
                                convTx.handshakeStatus != "WAITING" ||
                                convTx.identityState == "KEY_CHANGED_ALERT" ||
                                convTx.handshakeStatus == "KEY_CHANGED_ALERT"
                            ) {
                                return@withTransaction
                            }
                            val reqTx = db.handshakeDao().getByRequestId(packet.requestId)
                            if (reqTx == null || reqTx.isIncoming || reqTx.status != "WAITING") {
                                return@withTransaction
                            }
                            db.handshakeDao().updateStatusAndRejectedAt(
                                requestId = packet.requestId,
                                status = "KEY_CHANGED_ALERT",
                                rejectedAt = null
                            )
                            val updated = convTx.copy(
                                identityState = "KEY_CHANGED_ALERT",
                                handshakeStatus = "KEY_CHANGED_ALERT",
                                lastMessage = "⚠️ تحذير أمني: تغيرت الهوية الرقمية للطرف الآخر في الرد! تم إيقاف المحادثة.",
                                lastMessageTimestamp = now,
                                unreadCount = convTx.unreadCount + 1
                            )
                            db.conversationDao().update(updated)
                            alertedConv = updated
                        }
                        alertedConv?.let {
                            val notificationHelper = NotificationHelper(context)
                            notificationHelper.showIncomingMessageNotification(
                                conversationId = it.id,
                                senderName = it.contactName,
                                decryptedContent = "تحذير: تغيرت الهوية الرقمية للطرف الآخر في الرد!",
                                hideContent = true
                            )
                        }
                        return
                    }
                }

                // 2. Process RESPONSE & derive session keys using persisted ephemeral key
                val ourEphPriv = storedReq.ephemeralPrivateKeyBase64?.let { Base64.decode(it, Base64.NO_WRAP) }
                val ourEphKeyPair = ourEphPriv?.let {
                    val pub = Curve25519Engine.getX25519PublicKeyFromPrivateKey(it)
                    Curve25519Engine.KeyPairBytes(it, pub)
                }

                val confirmResult = try {
                    app.handshakeManager.processResponse(packet, ourEphKeyPair)
                } catch (e: Exception) {
                    null
                } ?: return

                val outKeyB64 = Base64.encodeToString(confirmResult.sessionKeys.outboundKey, Base64.NO_WRAP)
                val inKeyB64 = Base64.encodeToString(confirmResult.sessionKeys.inboundKey, Base64.NO_WRAP)
                val confirmationKeyB64 = Base64.encodeToString(confirmResult.sessionKeys.confirmationKey, Base64.NO_WRAP)

                // 3. Pin peer key to PINNED_TOFU upon verified RESPONSE, sync handshake_requests & set PENDING_CONFIRM_SEND atomically
                var movedToPendingConfirm = false
                db.withTransaction {
                    val convTx = db.conversationDao().getConversationById(conv.id) ?: return@withTransaction
                    if (
                        convTx.currentRequestId != packet.requestId ||
                        convTx.handshakeStatus != "WAITING" ||
                        convTx.identityState == "KEY_CHANGED_ALERT" ||
                        convTx.handshakeStatus == "KEY_CHANGED_ALERT"
                    ) {
                        return@withTransaction
                    }

                    db.conversationDao().update(
                        convTx.copy(
                            handshakeStatus = "PENDING_CONFIRM_SEND",
                            rejectedAt = null,
                            peerIdentityKeyBase64 = peerIdentityB64,
                            sessionKeyBase64 = outKeyB64,
                            inboundSessionKeyBase64 = inKeyB64,
                            pendingConfirmationKeyBase64 = confirmationKeyB64,
                            pendingConfirmMessageId = null,
                            pendingConfirmTotalParts = 0,
                            pendingConfirmSentIndices = "",
                            identityState = "PINNED_TOFU",
                            lastMessage = "جاري إرسال تأكيد المصافحة (CONFIRM)...",
                            lastMessageTimestamp = now
                        )
                    )
                    db.handshakeDao().updateStatusAndRejectedAt(
                        requestId = packet.requestId,
                        status = "PENDING_CONFIRM_SEND",
                        rejectedAt = null
                    )
                    movedToPendingConfirm = true
                }
                if (!movedToPendingConfirm) return

                // 4. Send CONFIRM SMS with delivery tracking for all parts using conversation SIM
                val confirmMsgId = UUID.randomUUID().toString()
                val effectiveSubId = app.simCardManager.resolveEffectiveSimForConversation(conv.id) ?: conv.defaultSubscriptionId
                app.smsSender.sendConfirmPacket(
                    conversationId = conv.id,
                    targetPhone = normalizedPhone,
                    confirmPayload = confirmResult.smsPayload,
                    confirmMessageId = confirmMsgId,
                    subscriptionId = effectiveSubId
                )
            }
            is HandshakePacket.Confirm -> {
                val conv = db.conversationDao().getConversationByComparableDigits(comparableDigits) ?: return
                // CRITICAL SECURITY: Strictly prohibit transition to READY if identity key changed
                if (conv.identityState == "KEY_CHANGED_ALERT" || conv.handshakeStatus == "KEY_CHANGED_ALERT") return
                // Strict check: Confirm must match our active pending request ID
                if (conv.currentRequestId != packet.requestId) return

                val storedReq = db.handshakeDao().getByRequestId(packet.requestId)
                if (storedReq != null && !storedReq.isIncoming) return

                val confKeyB64 = conv.pendingConfirmationKeyBase64 ?: return
                val confKey = Base64.decode(confKeyB64, Base64.NO_WRAP)

                // Cryptographically verify confirmation MAC before transitioning to READY
                val isMacValid = app.handshakeManager.verifyConfirm(packet, confKey)
                if (!isMacValid) return

                // Conditionally update to READY only if database state is NOT in KEY_CHANGED_ALERT, syncing requestId row
                db.withTransaction {
                    val convTx = db.conversationDao().getConversationById(conv.id) ?: return@withTransaction
                    if (
                        convTx.currentRequestId != packet.requestId ||
                        convTx.identityState == "KEY_CHANGED_ALERT" ||
                        convTx.handshakeStatus == "KEY_CHANGED_ALERT"
                    ) {
                        return@withTransaction
                    }
                    val rowsUpdated = db.conversationDao().markResponderReady(
                        id = convTx.id,
                        lastMsg = "✅ تم تأسيس التشفير بنجاح",
                        timestamp = System.currentTimeMillis()
                    )
                    if (rowsUpdated > 0) {
                        db.handshakeDao().updateStatusAndRejectedAt(
                            requestId = packet.requestId,
                            status = "READY",
                            rejectedAt = null
                        )
                    }
                }
            }
            is HandshakePacket.Reject -> {
                val conv = db.conversationDao().getConversationByComparableDigits(comparableDigits) ?: return
                // Guard: Never allow state transitions to bypass KEY_CHANGED_ALERT security lockdown
                if (conv.identityState == "KEY_CHANGED_ALERT" || conv.handshakeStatus == "KEY_CHANGED_ALERT") return
                // Strict check: Reject must match our active pending outgoing request ID
                if (conv.currentRequestId != packet.requestId || conv.handshakeStatus != "WAITING") return

                val storedReq = db.handshakeDao().getByRequestId(packet.requestId)
                if (storedReq == null || storedReq.isIncoming || storedReq.status != "WAITING") return

                // 1. If peer is UNPINNED (first contact / no pinned key), ignore unauthenticated reject completely!
                if (conv.identityState != "PINNED_TOFU" || conv.peerIdentityKeyBase64 == null) {
                    // Do NOT cancel pending request, do NOT apply cooldown.
                    return
                }

                // 2. Peer is PINNED_TOFU: Verify that reject is authentic and matches the pinned key
                val peerIdentityKey = Base64.decode(conv.peerIdentityKeyBase64, Base64.NO_WRAP)
                val isSigValid = app.handshakeManager.verifyReject(packet, peerIdentityKey)
                if (!isSigValid) return

                // Authentic rejection from pinned contact -> Apply 3-minute cooldown to initiator atomically across both tables
                val now = System.currentTimeMillis()
                db.withTransaction {
                    val convTx = db.conversationDao().getConversationById(conv.id) ?: return@withTransaction
                    if (
                        convTx.currentRequestId != packet.requestId ||
                        convTx.handshakeStatus != "WAITING" ||
                        convTx.identityState != "PINNED_TOFU"
                    ) {
                        return@withTransaction
                    }
                    db.handshakeDao().updateStatusAndRejectedAt(
                        requestId = packet.requestId,
                        status = "REJECTED",
                        rejectedAt = now
                    )
                    db.conversationDao().update(
                        convTx.copy(
                            handshakeStatus = "REJECTED",
                            rejectedAt = now,
                            lastMessage = "تم رفض طلب الاتصال المشفر من جهة الاتصال",
                            lastMessageTimestamp = now
                        )
                    )
                }
            }
        }
    }

    private fun handleSmsSentReport(context: Context, intent: Intent) {
        val messageId = intent.getStringExtra(WaslSmsSender.EXTRA_MESSAGE_ID) ?: return
        val isConfirm = intent.getBooleanExtra(WaslSmsSender.EXTRA_IS_CONFIRM, false)
        val conversationId = intent.getStringExtra(WaslSmsSender.EXTRA_CONVERSATION_ID)
        val isSuccess = resultCode == Activity.RESULT_OK
        val app = context.applicationContext as WaslApplication

        if (isConfirm && conversationId != null) {
            val partIndex = intent.getIntExtra(WaslSmsSender.EXTRA_CHUNK_INDEX, 1)
            val totalParts = intent.getIntExtra(WaslSmsSender.EXTRA_TOTAL_PARTS, 1)
            val pendingResult = goAsync()

            CoroutineScope(Dispatchers.IO).launch {
                try {
                    handleConfirmSentReport(app, conversationId, messageId, partIndex, totalParts, isSuccess)
                } finally {
                    pendingResult?.finish()
                }
            }
            return
        }

        val attemptId = intent.getStringExtra(WaslSmsSender.EXTRA_ATTEMPT_ID) ?: "0001"
        val chunkIndex = intent.getIntExtra(WaslSmsSender.EXTRA_CHUNK_INDEX, 1)
        val pendingResult = goAsync()

        CoroutineScope(Dispatchers.IO).launch {
            try {
                if (conversationId != null) {
                    app.database.withTransaction {
                        val message = app.database.messageDao().getMessageByConversationAndId(conversationId, messageId)
                            ?: return@withTransaction
                        // Strictly tie sent reports to the ACTIVE attempt only
                        if (message.currentAttemptId != attemptId) {
                            return@withTransaction
                        }

                        if (!isSuccess) {
                            // Any failed chunk immediately fails the attempt and parent message
                            app.database.outboundAttemptDao().updateStatus(conversationId, messageId, attemptId, MessageStatus.FAILED.name)
                            app.database.messageDao().updateStatus(conversationId, messageId, MessageStatus.FAILED.name)
                        } else if (message.status != MessageStatus.FAILED.name) {
                            val (isNewlyRecorded, allSent) = app.database.outboundAttemptDao().recordChunkSentAtomic(
                                conversationId, messageId, attemptId, chunkIndex
                            )
                            // Only update message to SENT when all chunks of active attempt succeed
                            if (isNewlyRecorded && allSent) {
                                app.database.messageDao().updateStatusIfNotFailedOrDelivered(
                                    conversationId, messageId, MessageStatus.SENT.name
                                )
                            }
                        }
                    }
                } else {
                    val existing = app.database.messageDao().getMessageById(messageId) ?: return@launch
                    if (!isSuccess) {
                        app.database.messageDao().updateStatus(messageId, MessageStatus.FAILED.name)
                    } else if (existing.status != MessageStatus.FAILED.name && existing.status != MessageStatus.DELIVERED.name) {
                        app.database.messageDao().updateStatus(messageId, MessageStatus.SENT.name)
                    }
                }
            } finally {
                pendingResult?.finish()
            }
        }
    }

    private suspend fun handleConfirmSentReport(
        app: WaslApplication,
        conversationId: String,
        confirmMessageId: String,
        partIndex: Int,
        totalParts: Int,
        isSuccess: Boolean
    ) {
        app.database.withTransaction {
            val completedRequestId = app.database.conversationDao().recordConfirmSentPartAtomic(
                conversationId = conversationId,
                confirmMessageId = confirmMessageId,
                partIndex = partIndex,
                totalParts = totalParts,
                isSuccess = isSuccess,
                timestamp = System.currentTimeMillis()
            )
            if (completedRequestId != null) {
                app.database.handshakeDao().updateStatusAndRejectedAt(
                    requestId = completedRequestId,
                    status = "READY",
                    rejectedAt = null
                )
            }
        }
    }

    private fun handleSmsDeliveryReport(context: Context, intent: Intent) {
        val messageId = intent.getStringExtra(WaslSmsSender.EXTRA_MESSAGE_ID) ?: return
        val conversationId = intent.getStringExtra(WaslSmsSender.EXTRA_CONVERSATION_ID)
        val attemptId = intent.getStringExtra(WaslSmsSender.EXTRA_ATTEMPT_ID) ?: "0001"
        val chunkIndex = intent.getIntExtra(WaslSmsSender.EXTRA_CHUNK_INDEX, 1)
        val app = context.applicationContext as WaslApplication
        val pendingResult = goAsync()

        CoroutineScope(Dispatchers.IO).launch {
            try {
                if (conversationId != null) {
                    app.database.withTransaction {
                        val message = app.database.messageDao().getMessageByConversationAndId(conversationId, messageId)
                            ?: return@withTransaction
                        // Strictly tie delivery reports to the ACTIVE attempt only
                        if (message.currentAttemptId != attemptId) {
                            return@withTransaction
                        }
                        if (message.status == MessageStatus.FAILED.name) {
                            return@withTransaction
                        }

                        val (isNewlyRecorded, allDelivered) = app.database.outboundAttemptDao().recordChunkDeliveredAtomic(
                            conversationId, messageId, attemptId, chunkIndex
                        )
                        // Only increment message deliveredParts once per newly delivered chunk,
                        // and transition to DELIVERED only when all chunks of active attempt are confirmed
                        if (isNewlyRecorded) {
                            app.database.messageDao().recordDeliveryReport(conversationId, messageId)
                            if (allDelivered) {
                                app.database.messageDao().updateStatus(conversationId, messageId, MessageStatus.DELIVERED.name)
                            }
                        }
                    }
                } else {
                    val existing = app.database.messageDao().getMessageById(messageId) ?: return@launch
                    if (existing.status != MessageStatus.FAILED.name) {
                        app.database.messageDao().recordDeliveryReport(messageId)
                    }
                }
            } finally {
                pendingResult?.finish()
            }
        }
    }
}
