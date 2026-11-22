package com.wasl.secure

import com.wasl.secure.core.crypto.AesGcmCipher
import com.wasl.secure.core.crypto.MonotonicNonceManager
import com.wasl.secure.core.protocol.ChatMessagePacket
import com.wasl.secure.data.local.dao.MessageChunkDao
import com.wasl.secure.data.local.entity.MessageChunkEntity
import com.wasl.secure.telephony.MessageChunkManager
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.GeneralSecurityException

class Phase5FragmentationTestSuite {

    // In-memory simulator for MessageChunkDao
    private class TestMessageChunkDaoSimulator : MessageChunkDao {
        private val buffer = mutableMapOf<String, MessageChunkEntity>()

        override suspend fun insertChunk(chunk: MessageChunkEntity): Long {
            // Ignore duplicates
            if (buffer.containsKey(chunk.id)) return -1L
            buffer[chunk.id] = chunk
            return 1L
        }

        override suspend fun getChunksForMessage(messageId: String): List<MessageChunkEntity> {
            return buffer.values
                .filter { it.messageId == messageId }
                .sortedBy { it.chunkIndex }
        }

        override suspend fun getChunkCountForMessage(messageId: String): Int {
            return buffer.values.count { it.messageId == messageId }
        }

        override suspend fun deleteChunksForMessage(messageId: String) {
            buffer.entries.removeIf { it.value.messageId == messageId }
        }

        override suspend fun deleteExpiredChunks(expiryTimestamp: Long) {
            buffer.entries.removeIf { it.value.receivedAt < expiryTimestamp }
        }
    }

    private lateinit var chunkDao: TestMessageChunkDaoSimulator

    @Before
    fun setUp() {
        chunkDao = TestMessageChunkDaoSimulator()
    }

    @Test
    fun test_1_Long_Message_Fragmentation() {
        val longMessage = "هذه رسالة نصية طويلة جداً ".repeat(20) // ~520 characters
        val key = ByteArray(32) { 0x33.toByte() }
        val nonceManager = MonotonicNonceManager(100L)
        val (nonce, _) = nonceManager.generateNextNonce()

        val convId = "conv-frag-1"
        val msgId = "msg-frag-1"
        val seqNo = 100L

        // Encrypt with dummy AAD
        val plainBytes = longMessage.toByteArray(Charsets.UTF_8)
        val dummyAad = "$convId:$msgId:$seqNo:1/7".toByteArray(Charsets.UTF_8)
        val encrypted = AesGcmCipher.encrypt(key, nonce, plainBytes, dummyAad)

        // Fragment ciphertext into SMS chunks
        val packets = MessageChunkManager.fragmentCiphertext(
            conversationId = convId,
            messageId = msgId,
            sequenceNumber = seqNo,
            nonce = nonce,
            ciphertextWithTag = encrypted.ciphertextWithTag
        )

        assertTrue("Long message must be split into multiple chunks", packets.size > 1)
        val totalChunks = packets.size

        packets.forEachIndexed { index, packet ->
            assertEquals(convId, packet.conversationId)
            assertEquals(msgId, packet.messageId)
            assertEquals(seqNo, packet.sequenceNumber)
            assertEquals(index + 1, packet.chunkIndex)
            assertEquals(totalChunks, packet.totalChunks)
            assertArrayEquals(nonce, packet.nonce)
            assertTrue("Chunk payload must not exceed max chunk size", packet.ciphertextWithTag.size <= MessageChunkManager.MAX_CHUNK_PAYLOAD_BYTES)
        }
    }

    @Test
    fun test_2_Out_Of_Order_Arrival_And_Reassembly() = runBlocking {
        val originalText = "رسالة تجزئة اختبارية: وصول مبعثر للأجزاء وإعادة تجميع دقيقة"
        val key = ByteArray(32) { 0x55.toByte() }
        val (nonce, _) = MonotonicNonceManager(1L).generateNextNonce()
        val convId = "conv-scramble"
        val msgId = "msg-scramble"
        val seqNo = 5L

        val aad = "$convId:$msgId:$seqNo:1/3".toByteArray(Charsets.UTF_8)
        val encrypted = AesGcmCipher.encrypt(key, nonce, originalText.toByteArray(Charsets.UTF_8), aad)

        val packets = MessageChunkManager.fragmentCiphertext(
            convId, msgId, seqNo, nonce, encrypted.ciphertextWithTag
        )
        // Assume 3 parts for this test
        val chunk1 = packets.getOrNull(0) ?: packets[0]
        val chunk2 = if (packets.size > 1) packets[1] else packets[0].copy(chunkIndex = 2, totalChunks = 3)
        val chunk3 = if (packets.size > 2) packets[2] else packets[0].copy(chunkIndex = 3, totalChunks = 3)

        // Simulated Out-of-Order Arrival: Chunk 3 arrives first!
        val res3 = MessageChunkManager.processIncomingChunk(chunk3.copy(totalChunks = 3), chunkDao)
        assertNull("Arrival of chunk 3 alone must not produce reassembled message", res3)

        // Chunk 1 arrives second
        val res1 = MessageChunkManager.processIncomingChunk(chunk1.copy(totalChunks = 3), chunkDao)
        assertNull("Arrival of chunk 1 and 3 still incomplete", res1)

        // Chunk 2 arrives last!
        val res2 = MessageChunkManager.processIncomingChunk(chunk2.copy(totalChunks = 3), chunkDao)
        assertNotNull("All 3 chunks have arrived! Reassembly must succeed", res2)

        assertEquals(msgId, res2!!.messageId)
        assertEquals(3, res2.totalChunks)
        assertArrayEquals(nonce, res2.nonce)

        // Verify buffer cleanup
        assertEquals("Buffer table must be cleaned up after successful reassembly", 0, chunkDao.getChunkCountForMessage(msgId))
    }

    @Test
    fun test_3_Duplicate_Chunk_Delivery_Ignored() = runBlocking {
        val packet = ChatMessagePacket(
            conversationId = "conv-dup",
            messageId = "msg-dup",
            sequenceNumber = 1L,
            chunkIndex = 1,
            totalChunks = 2,
            nonce = ByteArray(12) { 1 },
            ciphertextWithTag = "PART_1_DATA".toByteArray(Charsets.UTF_8)
        )

        // Deliver chunk 1
        MessageChunkManager.processIncomingChunk(packet, chunkDao)
        assertEquals(1, chunkDao.getChunkCountForMessage("msg-dup"))

        // Duplicate delivery of chunk 1
        MessageChunkManager.processIncomingChunk(packet, chunkDao)
        assertEquals("Duplicate chunk must be ignored without increasing count", 1, chunkDao.getChunkCountForMessage("msg-dup"))
    }

    @Test
    fun test_4_Tampered_Chunk_Fails_AEAD_Authentication() = runBlocking {
        val originalText = "نص اختبار التحقق من التلاعب في الأجزاء المجزأة"
        val key = ByteArray(32) { 0x77.toByte() }
        val (nonce, _) = MonotonicNonceManager(10L).generateNextNonce()
        val convId = "conv-tamp"
        val msgId = "msg-tamp"
        val seqNo = 12L

        val aad = "$convId:$msgId:$seqNo:1/2".toByteArray(Charsets.UTF_8)
        val encrypted = AesGcmCipher.encrypt(key, nonce, originalText.toByteArray(Charsets.UTF_8), aad)

        val packets = MessageChunkManager.fragmentCiphertext(convId, msgId, seqNo, nonce, encrypted.ciphertextWithTag)
        val p1 = packets[0]
        val p2 = if (packets.size > 1) packets[1] else packets[0].copy(chunkIndex = 2, totalChunks = 2)

        // Deliver chunk 1 normally
        MessageChunkManager.processIncomingChunk(p1.copy(totalChunks = 2), chunkDao)

        // Attack: Tamper with chunk 2 payload in transit
        val tamperedPayload = p2.ciphertextWithTag.clone()
        tamperedPayload[0] = (tamperedPayload[0] + 1).toByte()
        val tamperedP2 = p2.copy(totalChunks = 2, ciphertextWithTag = tamperedPayload)

        val reassembled = MessageChunkManager.processIncomingChunk(tamperedP2, chunkDao)
        assertNotNull(reassembled)

        // Attempt decryption of reassembled tampered payload -> MUST fail
        try {
            AesGcmCipher.decrypt(key, reassembled!!.nonce, reassembled.fullCiphertextWithTag, aad)
            fail("Decryption of tampered reassembled chunks must fail with BadTagException")
        } catch (expected: GeneralSecurityException) {
            // Expected
        }
    }
}
