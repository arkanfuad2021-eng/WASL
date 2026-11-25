package com.wasl.secure.telephony

import com.wasl.secure.core.protocol.ChatMessagePacket
import com.wasl.secure.data.local.dao.MessageChunkDao
import com.wasl.secure.data.local.dao.ProcessChunkResult
import com.wasl.secure.data.local.entity.MessageChunkEntity
import java.io.ByteArrayOutputStream
import java.util.Base64
import kotlin.math.ceil

/**
 * Manages the splitting of long encrypted messages into SMS-sized chunks,
 * and the atomic out-of-order reassembly upon receipt, strictly isolated by (conversationId, messageId, attemptId).
 * Conforms to Section 7 of the Master Specification.
 */
object MessageChunkManager {

    // Maximum raw ciphertext bytes per SMS segment (leaving room for 72-char headers in 160-char SMS)
    // 63 raw bytes * (4/3) = 84 Base64url characters. 72 + 84 = 156 characters <= 160 characters.
    const val MAX_CHUNK_PAYLOAD_BYTES = 63
    const val CHUNK_EXPIRY_MS = 24L * 60L * 60L * 1000L // 24 hours
    private const val GCM_TAG_LENGTH_BYTES = 16
    private val b64Encoder = Base64.getUrlEncoder().withoutPadding()
    private val b64Decoder = Base64.getUrlDecoder()

    /**
     * Calculates the exact number of single-segment SMS chunks required for plaintext
     * after AES-256-GCM encryption (UTF-8 payload + 16-byte tag) at 63 raw bytes per chunk.
     */
    fun estimateEncryptedSmsParts(plainText: String): Int {
        if (plainText.isEmpty()) return 1
        val totalCipherBytes = plainText.toByteArray(Charsets.UTF_8).size + GCM_TAG_LENGTH_BYTES
        val parts = ceil(totalCipherBytes.toDouble() / MAX_CHUNK_PAYLOAD_BYTES).toInt()
        return parts.coerceAtLeast(1)
    }

    data class ReassembledMessage(
        val conversationId: String,
        val messageId: String,
        val attemptId: String,
        val sequenceNumber: Long,
        val totalChunks: Int,
        val nonce: ByteArray,
        val fullCiphertextWithTag: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as ReassembledMessage
            if (conversationId != other.conversationId) return false
            if (messageId != other.messageId) return false
            if (attemptId != other.attemptId) return false
            if (sequenceNumber != other.sequenceNumber) return false
            if (totalChunks != other.totalChunks) return false
            if (!nonce.contentEquals(other.nonce)) return false
            if (!fullCiphertextWithTag.contentEquals(other.fullCiphertextWithTag)) return false
            return true
        }

        override fun hashCode(): Int {
            var result = conversationId.hashCode()
            result = 31 * result + messageId.hashCode()
            result = 31 * result + attemptId.hashCode()
            result = 31 * result + sequenceNumber.hashCode()
            result = 31 * result + totalChunks
            result = 31 * result + nonce.contentHashCode()
            result = 31 * result + fullCiphertextWithTag.contentHashCode()
            return result
        }

        /**
         * Reconstructs the complete AAD matching the parent message.
         */
        fun getParentAad(): ByteArray {
            return "$conversationId:$messageId:$sequenceNumber:1/$totalChunks".toByteArray(Charsets.UTF_8)
        }
    }

    /**
     * Splits full ciphertext into sequenced ChatMessagePackets.
     */
    fun fragmentCiphertext(
        conversationId: String,
        messageId: String,
        attemptId: String = "0001",
        sequenceNumber: Long,
        nonce: ByteArray,
        ciphertextWithTag: ByteArray
    ): List<ChatMessagePacket> {
        val totalBytes = ciphertextWithTag.size
        if (totalBytes <= MAX_CHUNK_PAYLOAD_BYTES) {
            // Single chunk message
            return listOf(
                ChatMessagePacket(
                    conversationId = conversationId,
                    messageId = messageId,
                    attemptId = attemptId,
                    sequenceNumber = sequenceNumber,
                    chunkIndex = 1,
                    totalChunks = 1,
                    nonce = nonce,
                    ciphertextWithTag = ciphertextWithTag
                )
            )
        }

        val totalChunks = ceil(totalBytes.toDouble() / MAX_CHUNK_PAYLOAD_BYTES).toInt()
        val packets = ArrayList<ChatMessagePacket>(totalChunks)

        var offset = 0
        for (i in 1..totalChunks) {
            val chunkSize = minOf(MAX_CHUNK_PAYLOAD_BYTES, totalBytes - offset)
            val chunkSlice = ByteArray(chunkSize)
            System.arraycopy(ciphertextWithTag, offset, chunkSlice, 0, chunkSize)
            offset += chunkSize

            packets.add(
                ChatMessagePacket(
                    conversationId = conversationId,
                    messageId = messageId,
                    attemptId = attemptId,
                    sequenceNumber = sequenceNumber,
                    chunkIndex = i,
                    totalChunks = totalChunks,
                    nonce = nonce,
                    ciphertextWithTag = chunkSlice
                )
            )
        }

        return packets
    }

    /**
     * Processes an incoming chunk atomically. Validates metadata consistency, detects conflicts,
     * buffers the chunk, and if complete, reassembles the full ciphertext and returns it.
     * Note: Chunks are NOT deleted here; they are preserved until AES-GCM decryption succeeds in Receiver.
     */
    suspend fun processIncomingChunk(
        packet: ChatMessagePacket,
        chunkDao: MessageChunkDao
    ): ReassembledMessage? {
        val chunkEntity = MessageChunkEntity(
            conversationId = packet.conversationId,
            messageId = packet.messageId,
            attemptId = packet.attemptId,
            chunkIndex = packet.chunkIndex,
            totalChunks = packet.totalChunks,
            chunkPayloadBase64 = b64Encoder.encodeToString(packet.ciphertextWithTag),
            nonceBase64 = b64Encoder.encodeToString(packet.nonce),
            sequenceNumber = packet.sequenceNumber
        )

        val result = chunkDao.processAndCheckChunkAtomic(chunkEntity)

        return when (result) {
            is ProcessChunkResult.Complete -> {
                // Assemble full ciphertext in exact numerical order (1..N)
                val outputStream = ByteArrayOutputStream()
                for (chunk in result.sortedChunks) {
                    val sliceBytes = b64Decoder.decode(chunk.chunkPayloadBase64)
                    outputStream.write(sliceBytes)
                }
                val fullCiphertext = outputStream.toByteArray()

                ReassembledMessage(
                    conversationId = packet.conversationId,
                    messageId = packet.messageId,
                    attemptId = packet.attemptId,
                    sequenceNumber = packet.sequenceNumber,
                    totalChunks = packet.totalChunks,
                    nonce = packet.nonce,
                    fullCiphertextWithTag = fullCiphertext
                )
            }
            is ProcessChunkResult.Conflicted -> null
            is ProcessChunkResult.Incomplete -> null
        }
    }
}
