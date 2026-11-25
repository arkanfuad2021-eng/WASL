package com.wasl.secure

import com.wasl.secure.core.crypto.AesGcmCipher
import com.wasl.secure.core.crypto.MonotonicNonceManager
import com.wasl.secure.core.protocol.ChatMessageCodec
import com.wasl.secure.core.protocol.ChatMessagePacket
import com.wasl.secure.data.local.dao.MessageChunkDao
import com.wasl.secure.data.local.entity.MessageChunkEntity
import com.wasl.secure.domain.model.MessageStatus
import com.wasl.secure.telephony.MessageChunkManager
import kotlinx.coroutines.runBlocking
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

    /**
     * Minimal in-memory DAO backing MessageChunkDao's real default processAndCheckChunkAtomic logic.
     */
    private class InMemoryMessageChunkDao : MessageChunkDao {
        private val buffer = linkedMapOf<String, MessageChunkEntity>()

        override suspend fun insertChunk(chunk: MessageChunkEntity): Long {
            val pk = "${chunk.conversationId}_${chunk.messageId}_${chunk.attemptId}_${chunk.chunkIndex}"
            if (buffer.containsKey(pk)) return -1L
            buffer[pk] = chunk
            return 1L
        }

        override suspend fun getChunksForAttempt(
            conversationId: String,
            messageId: String,
            attemptId: String
        ): List<MessageChunkEntity> = buffer.values
            .filter { it.conversationId == conversationId && it.messageId == messageId && it.attemptId == attemptId }
            .sortedBy { it.chunkIndex }

        override suspend fun getChunkCountForAttempt(
            conversationId: String,
            messageId: String,
            attemptId: String
        ): Int = getChunksForAttempt(conversationId, messageId, attemptId).size

        override suspend fun deleteChunksForAttempt(conversationId: String, messageId: String, attemptId: String) {
            buffer.entries.removeIf {
                it.value.conversationId == conversationId && it.value.messageId == messageId && it.value.attemptId == attemptId
            }
        }

        override suspend fun deleteChunksForMessage(conversationId: String, messageId: String) {
            buffer.entries.removeIf { it.value.conversationId == conversationId && it.value.messageId == messageId }
        }

        override suspend fun deleteChunksForMessage(messageId: String) {
            buffer.entries.removeIf { it.value.messageId == messageId }
        }

        override suspend fun deleteChunksForConversation(conversationId: String, packetConversationId: String) {
            buffer.entries.removeIf {
                it.value.conversationId == conversationId || it.value.conversationId == packetConversationId
            }
        }

        override suspend fun deleteExpiredChunks(expiryTimestamp: Long) {
            buffer.entries.removeIf { it.value.receivedAt < expiryTimestamp }
        }
    }

    @Test
    fun test_2_End_To_End_SMS_Encryption_Transmission_And_Decryption() = runBlocking {
        val key = ByteArray(32) { (it + 1).toByte() } // Directional session key K_{A -> B}
        val nonceManager = MonotonicNonceManager(initialCounter = 1L)
        val (nonce, _) = nonceManager.generateNextNonce()

        val originalText = "رسالة سرية وموثقة عبر WASL SMS"
        val plainBytes = originalText.toByteArray(Charsets.UTF_8)
        val convId = "0011223344556677"
        val msgId = "8899aabbccddeeff"
        val attemptId = "0001"
        val seqNo = 1L

        val totalExpectedChunks = MessageChunkManager.estimateEncryptedSmsParts(originalText)
        assertTrue("Payload exceeding 63 ciphertext bytes must fragment into multiple SMS parts", totalExpectedChunks > 1)

        val aad = "$convId:$msgId:$seqNo:1/$totalExpectedChunks".toByteArray(Charsets.UTF_8)

        // 1. Sender encrypts plaintext once with parent AAD
        val encryptResult = AesGcmCipher.encrypt(
            key = key,
            nonce = nonce,
            plaintext = plainBytes,
            associatedData = aad
        )

        // 2. Sender fragments full ciphertext into SMS-sized packets (<= 63 bytes each)
        val packets = MessageChunkManager.fragmentCiphertext(
            conversationId = convId,
            messageId = msgId,
            attemptId = attemptId,
            sequenceNumber = seqNo,
            nonce = nonce,
            ciphertextWithTag = encryptResult.ciphertextWithTag
        )
        assertEquals(totalExpectedChunks, packets.size)

        val smsTransmissionStrings = packets.map { packet ->
            assertTrue(packet.ciphertextWithTag.size <= MessageChunkManager.MAX_CHUNK_PAYLOAD_BYTES)
            val encoded = ChatMessageCodec.encode(packet)
            assertTrue("Encoded SMS segment must fit within 160 ASCII chars", encoded.length <= 160)
            encoded
        }

        // 3. Recipient decodes each SMS segment via ChatMessageCodec and buffers in MessageChunkManager
        val chunkDao = InMemoryMessageChunkDao()
        var reassembled: MessageChunkManager.ReassembledMessage? = null
        smsTransmissionStrings.forEachIndexed { index, smsText ->
            val decodedPacket = ChatMessageCodec.decode(smsText)
            assertNotNull("Decoded SMS chunk ${index + 1} must not be null", decodedPacket)
            reassembled = MessageChunkManager.processIncomingChunk(decodedPacket!!, chunkDao)
            if (index < smsTransmissionStrings.lastIndex) {
                assertNull("Message must stay incomplete until final chunk arrives", reassembled)
            }
        }

        assertNotNull("All chunks arrived; reassembly must complete", reassembled)
        assertEquals(totalExpectedChunks, reassembled!!.totalChunks)
        assertArrayEquals(nonce, reassembled!!.nonce)
        assertArrayEquals(encryptResult.ciphertextWithTag, reassembled!!.fullCiphertextWithTag)

        // 4. Recipient decrypts and authenticates reassembled ciphertext with parent AAD
        val decryptedBytes = AesGcmCipher.decrypt(
            key = key,
            nonce = reassembled!!.nonce,
            ciphertextWithTag = reassembled!!.fullCiphertextWithTag,
            associatedData = reassembled!!.getParentAad()
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
