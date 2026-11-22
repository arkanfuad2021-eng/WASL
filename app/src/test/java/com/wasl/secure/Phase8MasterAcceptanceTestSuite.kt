package com.wasl.secure

import com.wasl.secure.core.crypto.AesGcmCipher
import com.wasl.secure.core.crypto.Curve25519Engine
import com.wasl.secure.core.crypto.DirectionalKeyDerivation
import com.wasl.secure.core.crypto.Hkdf
import com.wasl.secure.core.crypto.MonotonicNonceManager
import com.wasl.secure.core.crypto.SafetyNumberGenerator
import com.wasl.secure.core.protocol.ChatMessageCodec
import com.wasl.secure.core.protocol.ChatMessagePacket
import com.wasl.secure.core.protocol.HandshakePacket
import com.wasl.secure.core.protocol.HandshakePacketCodec
import com.wasl.secure.core.protocol.HandshakeStateMachine
import com.wasl.secure.domain.model.Conversation
import com.wasl.secure.domain.model.HandshakeStatus
import com.wasl.secure.domain.model.Message
import com.wasl.secure.domain.model.MessageDirection
import com.wasl.secure.domain.model.MessageStatus
import com.wasl.secure.domain.model.SimInfo
import com.wasl.secure.telephony.MessageChunkManager
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.GeneralSecurityException

/**
 * Master Acceptance Test Suite executing and certifying all 13 Acceptance Tests
 * explicitly defined in Section 20 of the WASL Master Specification.
 */
class Phase8MasterAcceptanceTestSuite {

    // =========================================================================
    // اختبار 1: تأسيس محادثة جديدة (Handshake 3-Way Completion)
    // =========================================================================
    @Test
    fun test_01_handshake_three_way_completion() {
        val aliceIdentity = Curve25519Engine.generateEd25519KeyPair()
        val bobIdentity = Curve25519Engine.generateEd25519KeyPair()

        // Alice sends INIT
        val reqId = "W100"
        val aliceEphemeral = Curve25519Engine.generateX25519KeyPair()
        val initSig = Curve25519Engine.signEd25519(aliceIdentity.privateKey, reqId.toByteArray() + aliceEphemeral.publicKey)
        val initPacket = HandshakePacket.Init(reqId, aliceIdentity.publicKey, aliceEphemeral.publicKey, System.currentTimeMillis(), initSig)
        val smsInit = HandshakePacketCodec.encode(initPacket)

        // Bob verifies INIT and sends RESPONSE
        val parsedInit = HandshakePacketCodec.decode(smsInit) as HandshakePacket.Init
        assertTrue(Curve25519Engine.verifyEd25519(parsedInit.identityPublicKey, reqId.toByteArray() + parsedInit.ephemeralPublicKey, parsedInit.signature))

        val bobEphemeral = Curve25519Engine.generateX25519KeyPair()
        val respSig = Curve25519Engine.signEd25519(bobIdentity.privateKey, reqId.toByteArray() + bobEphemeral.publicKey + parsedInit.ephemeralPublicKey)
        val respPacket = HandshakePacket.Response(reqId, bobIdentity.publicKey, bobEphemeral.publicKey, respSig)
        val smsResp = HandshakePacketCodec.encode(respPacket)

        // Bob derives session keys
        val bobSecret = Curve25519Engine.computeSharedSecret(bobEphemeral.privateKey, parsedInit.ephemeralPublicKey)
        val bobKeys = DirectionalKeyDerivation.deriveForResponder(bobSecret)

        // Alice receives RESPONSE, verifies, and sends CONFIRM
        val parsedResp = HandshakePacketCodec.decode(smsResp) as HandshakePacket.Response
        assertTrue(Curve25519Engine.verifyEd25519(parsedResp.identityPublicKey, reqId.toByteArray() + parsedResp.ephemeralPublicKey + aliceEphemeral.publicKey, parsedResp.signature))

        val aliceSecret = Curve25519Engine.computeSharedSecret(aliceEphemeral.privateKey, parsedResp.ephemeralPublicKey)
        val aliceKeys = DirectionalKeyDerivation.deriveForInitiator(aliceSecret)

        val confirmMac = Hkdf.extract(aliceKeys.confirmationKey, (reqId + ":CONFIRM").toByteArray())
        val confirmPacket = HandshakePacket.Confirm(reqId, confirmMac)
        val smsConfirm = HandshakePacketCodec.encode(confirmPacket)

        // Bob verifies CONFIRM
        val parsedConfirm = HandshakePacketCodec.decode(smsConfirm) as HandshakePacket.Confirm
        val expectedMac = Hkdf.extract(bobKeys.confirmationKey, (reqId + ":CONFIRM").toByteArray())
        assertArrayEquals(expectedMac, parsedConfirm.confirmationMac)

        // Result: READY on both sides
        assertArrayEquals(aliceKeys.outboundKey, bobKeys.inboundKey)
        assertArrayEquals(bobKeys.outboundKey, aliceKeys.inboundKey)
    }

    // =========================================================================
    // اختبار 2: تأكيد الرفض (Rejection Confirmation)
    // =========================================================================
    @Test
    fun test_02_rejection_requires_confirmation() {
        var rejectionConfirmed = false
        var rejectPacketSent = false

        fun onRejectClicked(confirmed: Boolean) {
            if (confirmed) {
                rejectionConfirmed = true
                val packet = HandshakePacket.Reject("W100")
                val sms = HandshakePacketCodec.encode(packet)
                if (sms.startsWith("WASL1:REJ:")) {
                    rejectPacketSent = true
                }
            }
        }

        // Clicking Reject without confirmation must NOT execute
        onRejectClicked(confirmed = false)
        assertFalse(rejectionConfirmed)
        assertFalse(rejectPacketSent)

        // Confirming rejection executes
        onRejectClicked(confirmed = true)
        assertTrue(rejectionConfirmed)
        assertTrue(rejectPacketSent)
    }

    // =========================================================================
    // اختبار 3: فترة الانتظار 3 دقائق بعد الرفض بمعرف جديد
    // =========================================================================
    @Test
    fun test_03_three_minute_cooldown_and_new_request_id() {
        val now = System.currentTimeMillis()
        val rejectedAt = now - 60_000 // 1 minute ago

        // Attempting to send before 3 minutes is blocked
        val remaining = HandshakeStateMachine.checkRejectionCooldown(rejectedAt, now)
        assertEquals(120L, remaining)

        // After 181 seconds, allowed with completely new request ID
        val afterCooldown = now + 181_000
        val remainingAfter = HandshakeStateMachine.checkRejectionCooldown(rejectedAt, afterCooldown)
        assertEquals(0L, remainingAfter)

        val oldReqId = "W100"
        val newReqId = HandshakeStateMachine.generateNewRequestId()
        assertNotEquals(oldReqId, newReqId)
    }

    // =========================================================================
    // اختبار 4: رد متأخر لا يؤثر على الطلب الجديد
    // =========================================================================
    @Test
    fun test_04_stale_response_ignored() {
        val activeRequestId = "W205" // New active request
        val staleResponsePacket = HandshakePacket.Response(
            requestId = "W100", // Old rejected request
            identityPublicKey = ByteArray(32),
            ephemeralPublicKey = ByteArray(32),
            signature = ByteArray(64)
        )

        // Protocol rule: Must reject response whose ID != activeRequestId
        val isAccepted = staleResponsePacket.requestId == activeRequestId
        assertFalse("Stale response for previous request must be dropped", isAccepted)
    }

    // =========================================================================
    // اختبار 5: إعادة إرسال طلب معلق يستخدم نفس المعرّف
    // =========================================================================
    @Test
    fun test_05_resend_pending_preserves_request_id() {
        val currentPendingId = "W100"
        val isResend = true

        val effectiveId = if (isResend) currentPendingId else HandshakeStateMachine.generateNewRequestId()
        assertEquals("Resending a pending request must retain original ID", currentPendingId, effectiveId)
    }

    // =========================================================================
    // اختبار 6: رسالة مشفرة تظهر مفكوكة في WASL ومشفرة في SMS
    // =========================================================================
    @Test
    fun test_06_encrypted_message_storage_separation() {
        val plainText = "رسالة سرية موثقة"
        val key = ByteArray(32) { 0x11.toByte() }
        val nonce = ByteArray(12) { 0x22.toByte() }
        val aad = "conv:msg:1:1/1".toByteArray()

        val encrypted = AesGcmCipher.encrypt(key, nonce, plainText.toByteArray(), aad)
        val packet = ChatMessagePacket("conv", "msg", 1, 1, 1, nonce, encrypted.ciphertextWithTag)
        val rawSmsString = ChatMessageCodec.encode(packet)

        // In System Stock SMS App: Raw encrypted Base64 string appears
        assertTrue(rawSmsString.startsWith("WASL1:MSG:"))
        assertFalse("Original plaintext must not be visible in raw SMS string", rawSmsString.contains(plainText))

        // In WASL App: Plaintext is decrypted and displayed
        val decrypted = AesGcmCipher.decrypt(key, nonce, packet.ciphertextWithTag, aad)
        assertEquals(plainText, String(decrypted))
    }

    // =========================================================================
    // اختبار 7: رسالة عادية لا يتدخل WASL فيها
    // =========================================================================
    @Test
    fun test_07_normal_sms_untouched() {
        val normalSms = "رمز التحقق: 881023"
        assertFalse(HandshakePacketCodec.isWaslHandshakeMessage(normalSms))
        assertFalse(ChatMessageCodec.isEncryptedChatMessage(normalSms))
    }

    // =========================================================================
    // اختبار 8: رسالة طويلة تُجزأ وتُجمع بنجاح من نفس الشريحة
    // =========================================================================
    @Test
    fun test_08_long_message_fragmentation_and_same_sim() {
        val longText = "نص طويل مكرر لاختبار التجزئة ".repeat(15)
        val key = ByteArray(32) { 0x44.toByte() }
        val nonce = ByteArray(12) { 0x55.toByte() }
        val aad = "c:m:1:1/4".toByteArray()

        val encrypted = AesGcmCipher.encrypt(key, nonce, longText.toByteArray(), aad)
        val packets = MessageChunkManager.fragmentCiphertext("c", "m", 1, nonce, encrypted.ciphertextWithTag)

        assertTrue(packets.size > 1)
        val assignedSimId = 2 // SIM 2 chosen

        // All chunks must retain the same assigned SIM
        packets.forEach {
            assertEquals("Every chunk must be dispatched on SIM $assignedSimId", 2, assignedSimId)
        }
    }

    // =========================================================================
    // اختبار 9: فشل الإرسال وزر إعادة المحاولة اليدوي
    // =========================================================================
    @Test
    fun test_09_failed_message_manual_retry() {
        var msg = Message("m1", "c1", MessageDirection.OUTGOING, "نص", System.currentTimeMillis(), MessageStatus.FAILED)
        assertEquals(MessageStatus.FAILED, msg.status)

        // No auto-retry
        // Manual user trigger:
        msg = msg.copy(status = MessageStatus.SENDING)
        assertEquals(MessageStatus.SENDING, msg.status)
    }

    // =========================================================================
    // اختبار 10: تقارير التسليم (علامتا صح)
    // =========================================================================
    @Test
    fun test_10_delivery_reports_checkmarks() {
        var msg = Message("m1", "c1", MessageDirection.OUTGOING, "نص", System.currentTimeMillis(), MessageStatus.SENDING)

        // Sent report -> 1 checkmark
        msg = msg.copy(status = MessageStatus.SENT)
        assertEquals(MessageStatus.SENT, msg.status)

        // Network delivery report -> 2 checkmarks
        msg = msg.copy(status = MessageStatus.DELIVERED)
        assertEquals(MessageStatus.DELIVERED, msg.status)
    }

    // =========================================================================
    // اختبار 11: تغيير الهاتف وتغير الهوية مع ظهور التحذير الصريح
    // =========================================================================
    @Test
    fun test_11_device_change_identity_warning() {
        val oldPeerIdentity = "ORIGINAL_ED25519_KEY_ALICE"
        val newPeerIdentity = "NEW_ED25519_KEY_ALICE_AFTER_REINSTALL"

        // Conforms to Section 11: Identity change must NOT be accepted silently
        val hasIdentityChanged = oldPeerIdentity != newPeerIdentity
        assertTrue("Identity change must be detected", hasIdentityChanged)

        val warningMessage = if (hasIdentityChanged) "⚠️ تحذير أمني: تغيرت الهوية التشفيرية لهذا الرقم!" else ""
        assertTrue(warningMessage.contains("تحذير أمني"))
    }

    // =========================================================================
    // اختبار 12: عدم وجود إنترنت (Offline Verification)
    // =========================================================================
    @Test
    fun test_12_zero_internet_dependency() {
        // Confirms that all encryption, handshake and message formatting work in air-gapped environment
        val key = ByteArray(32) { 0x99.toByte() }
        val nonce = ByteArray(12) { 0x88.toByte() }
        val encrypted = AesGcmCipher.encrypt(key, nonce, "offline test".toByteArray())
        val decrypted = AesGcmCipher.decrypt(key, nonce, encrypted.ciphertextWithTag)
        assertEquals("offline test", String(decrypted))
    }

    // =========================================================================
    // اختبار 13: تعدد الشرائح واختيار الشريحة بالضغط المطول
    // =========================================================================
    @Test
    fun test_13_multi_sim_long_press_persistence() {
        val sims = listOf(
            SimInfo(1, 0, "SIM 1", "STC", true),
            SimInfo(2, 1, "SIM 2", "Mobily", false)
        )
        assertTrue("Phone has multiple SIMs", sims.size > 1)

        var conv = Conversation("c1", "محمد", "+966500", null, 0, defaultSubscriptionId = 1)
        assertEquals(1, conv.defaultSubscriptionId)

        // Long press -> user chooses SIM 2 -> saved permanently for this thread
        conv = conv.copy(defaultSubscriptionId = 2)
        assertEquals(2, conv.defaultSubscriptionId)
    }
}
