package com.wasl.secure.telephony

import com.wasl.secure.core.protocol.ChatMessagePacket
import com.wasl.secure.data.local.dao.MessageChunkDao
import com.wasl.secure.data.local.entity.MessageChunkEntity
import java.io.ByteArrayOutputStream
import java.util.Base64
import kotlin.math.ceil

/**
 * Manages the splitting of long encrypted messages into SMS-sized chunks,
 * and the out-of-order reassembly upon receipt.
 * Conforms to Section 7 of the Master Specification.
 */
object MessageChunkManager {

    // Maximum raw ciphertext bytes per SMS segment (leaving room for headers and Base64 expansion)
    const val MAX_CHUNK_PAYLOAD_BYTES = 95
    private val b64Encoder = Base64.getUrlEncoder().withoutPadding()
    private val b64Decoder = Base64.getUrlDecoder()

    data class ReassembledMessage(
        val conversationId: String,
        val messageId: String,
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
            if (sequenceNumber != other.sequenceNumber) return false
            if (totalChunks != other.totalChunks) return false
            if (!nonce.contentEquals(other.nonce)) return false
            if (!fullCiphertextWithTag.contentEquals(other.fullCiphertextWithTag)) return false
            return true
        }

        override fun hashCode(): Int {
            var result = conversationId.hashCode()
            result = 31 * result + messageId.hashCode()
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
     * Processes an incoming chunk. If all chunks for this message have arrived,
     * reassembles the full ciphertext and returns it. Otherwise returns null.
     */
    suspend fun processIncomingChunk(
        packet: ChatMessagePacket,
        chunkDao: MessageChunkDao
    ): ReassembledMessage? {
        // Fast path for single-chunk messages
        if (packet.totalChunks == 1) {
            return ReassembledMessage(
                conversationId = packet.conversationId,
                messageId = packet.messageId,
                sequenceNumber = packet.sequenceNumber,
                totalChunks = 1,
                nonce = packet.nonce,
                fullCiphertextWithTag = packet.ciphertextWithTag
            )
        }

        // 1. Buffer the chunk in persistent database (Ignore duplicates)
        val chunkEntity = MessageChunkEntity(
            id = "${packet.messageId}_${packet.chunkIndex}",
            messageId = packet.messageId,
            conversationId = packet.conversationId,
            chunkIndex = packet.chunkIndex,
            totalChunks = packet.totalChunks,
            chunkPayloadBase64 = b64Encoder.encodeToString(packet.ciphertextWithTag),
            nonceBase64 = b64Encoder.encodeToString(packet.nonce),
            sequenceNumber = packet.sequenceNumber
        )
        chunkDao.insertChunk(chunkEntity)

        // 2. Check if all required chunks have arrived
        val arrivedCount = chunkDao.getChunkCountForMessage(packet.messageId)
        if (arrivedCount < packet.totalChunks) {
            // Still waiting for remaining parts
            return null
        }

        // 3. All chunks are present! Reassemble in exact numerical order (1..N)
        val allChunks = chunkDao.getChunksForMessage(packet.messageId)
        if (allChunks.size != packet.totalChunks) {
            return null
        }

        val outputStream = ByteArrayOutputStream()
        for (chunk in allChunks) {
            val sliceBytes = b64Decoder.decode(chunk.chunkPayloadBase64)
            outputStream.write(sliceBytes)
        }

        val fullCiphertext = outputStream.toByteArray()

        // 4. Clean up temporary buffer table
        chunkDao.deleteChunksForMessage(packet.messageId)

        return ReassembledMessage(
            conversationId = packet.conversationId,
            messageId = packet.messageId,
            sequenceNumber = packet.sequenceNumber,
            totalChunks = packet.totalChunks,
            nonce = packet.nonce,
            fullCiphertextWithTag = fullCiphertext
        )
    }
}
