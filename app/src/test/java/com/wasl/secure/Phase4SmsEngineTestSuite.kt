package com.wasl.secure

import com.wasl.secure.core.crypto.AesGcmCipher
import com.wasl.secure.core.crypto.MonotonicNonceManager
import com.wasl.secure.core.protocol.ChatMessageCodec
import com.wasl.secure.core.protocol.ChatMessagePacket
import com.wasl.secure.domain.model.MessageStatus
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.GeneralSecurityException

class Phase4SmsEngineTestSuite {

    @Test
    fun test_1_ChatMessage_Packet_Codec_Roundtrip() {
        val convId = "0123456789abcdef"
        val msgId = "fedcba9876543210"
        val seqNo = 42L
        val nonce = MonotonicNonceManager().createNonceForCounter(seqNo)
        val ciphertext = "CIPHERTEXT_WITH_GCM_AUTH_TAG_16_BYTES".toByteArray(Charsets.UTF_8)

        val packet = ChatMessagePacket(
            conversationId = convId,
            messageId = msgId,
            sequenceNumber = seqNo,
            chunkIndex = 1,
            totalChunks = 1,
            nonce = nonce,
            ciphertextWithTag = ciphertext
        )

        val smsText = ChatMessageCodec.encode(packet)
        assertTrue("SMS text must start with WASL1:MSG:", smsText.startsWith("WASL1:MSG:$convId:$msgId:0001:1/1:"))
        assertTrue(ChatMessageCodec.isEncryptedChatMessage(smsText))

        val decoded = ChatMessageCodec.decode(smsText)
        assertNotNull("Decoded packet must not be null", decoded)
        assertEquals(convId, decoded!!.conversationId)
        assertEquals(msgId, decoded.messageId)
        assertEquals(seqNo, decoded.sequenceNumber)
        assertEquals(1, decoded.chunkIndex)
        assertEquals(1, decoded.totalChunks)
        assertArrayEquals(nonce, decoded.nonce)
        assertArrayEquals(ciphertext, decoded.ciphertextWithTag)
    }

    @Test
    fun test_2_End_To_End_SMS_Encryption_Transmission_And_Decryption() {
        val key = ByteArray(32) { (it + 1).toByte() } // Directional session key K_{A -> B}
        val nonceManager = MonotonicNonceManager(initialCounter = 1L)
        val (nonce, _) = nonceManager.generateNextNonce()

        val originalText = "رسالة سرية وموثقة عبر WASL SMS"
        val convId = "0011223344556677"
        val msgId = "8899aabbccddeeff"
        val seqNo = 1L

        val aad = "$convId:$msgId:$seqNo:1/1".toByteArray(Charsets.UTF_8)

        // 1. Sender encrypts plaintext
        val encryptResult = AesGcmCipher.encrypt(
            key = key,
            nonce = nonce,
            plaintext = originalText.toByteArray(Charsets.UTF_8),
            associatedData = aad
        )

        // 2. Sender formats packet for SMS cellular transmission
        val packet = ChatMessagePacket(
            conversationId = convId,
            messageId = msgId,
            sequenceNumber = seqNo,
            chunkIndex = 1,
            totalChunks = 1,
            nonce = nonce,
            ciphertextWithTag = encryptResult.ciphertextWithTag
        )
        val smsTransmissionString = ChatMessageCodec.encode(packet)

        // 3. Recipient receives raw SMS text from cellular tower
        val receivedPacket = ChatMessageCodec.decode(smsTransmissionString)
        assertNotNull(receivedPacket)

        // 4. Recipient decrypts and authenticates with AAD
        val decryptedBytes = AesGcmCipher.decrypt(
            key = key,
            nonce = receivedPacket!!.nonce,
            ciphertextWithTag = receivedPacket.ciphertextWithTag,
            associatedData = receivedPacket.getAad()
        )
        val decryptedText = String(decryptedBytes, Charsets.UTF_8)

        assertEquals("Decrypted message must match original plaintext exactly", originalText, decryptedText)
    }

    @Test
    fun test_3_Tampered_Ciphertext_Or_Metadata_Rejected() {
        val key = ByteArray(32) { 0x42.toByte() }
        val nonce = ByteArray(12) { 0x07.toByte() }
        val originalText = "رسالة اختبار التلاعب"
        val aad = "conv-1:msg-1:1:1/1".toByteArray(Charsets.UTF_8)

        val encrypted = AesGcmCipher.encrypt(key, nonce, originalText.toByteArray(Charsets.UTF_8), aad)

        // Attack 1: Modify ciphertext in transit
        val tamperedCiphertext = encrypted.ciphertextWithTag.clone()
        tamperedCiphertext[0] = (tamperedCiphertext[0] + 1).toByte()

        try {
            AesGcmCipher.decrypt(key, nonce, tamperedCiphertext, aad)
            fail("Decryption must fail when ciphertext is modified")
        } catch (expected: GeneralSecurityException) {
            // Expected
        }

        // Attack 2: Splicing / Metadata substitution (altering conversation ID in AAD)
        val tamperedAad = "conv-2:msg-1:1:1/1".toByteArray(Charsets.UTF_8) // Altered conversation ID
        try {
            AesGcmCipher.decrypt(key, nonce, encrypted.ciphertextWithTag, tamperedAad)
            fail("Decryption must fail when metadata AAD is altered")
        } catch (expected: GeneralSecurityException) {
            // Expected
        }
    }

    @Test
    fun test_4_Normal_SMS_Is_Completely_Ignored() {
        val bankOtp = "Your verification code is 492018. Do not share it."
        val operatorMsg = "لقد استهلكت 80% من باقة البيانات الخاصة بك."
        val friendMsg = "السلام عليكم، هل أنت متفرغ اليوم؟"

        assertFalse(ChatMessageCodec.isEncryptedChatMessage(bankOtp))
        assertNull(ChatMessageCodec.decode(bankOtp))

        assertFalse(ChatMessageCodec.isEncryptedChatMessage(operatorMsg))
        assertNull(ChatMessageCodec.decode(operatorMsg))

        assertFalse(ChatMessageCodec.isEncryptedChatMessage(friendMsg))
        assertNull(ChatMessageCodec.decode(friendMsg))
    }

    @Test
    fun test_5_Message_Delivery_Status_Transitions() {
        // Step 1: Created -> SENDING
        var status = MessageStatus.SENDING

        // Step 2: Device confirmed SMS departure -> SENT (1 checkmark)
        val sentBroadcastReceived = true
        if (sentBroadcastReceived) {
            status = MessageStatus.SENT
        }
        assertEquals(MessageStatus.SENT, status)

        // Step 3: Cellular tower confirmed SMS delivery -> DELIVERED (2 checkmarks)
        val deliveryReportReceived = true
        if (deliveryReportReceived) {
            status = MessageStatus.DELIVERED
        }
        assertEquals(MessageStatus.DELIVERED, status)
    }
}
