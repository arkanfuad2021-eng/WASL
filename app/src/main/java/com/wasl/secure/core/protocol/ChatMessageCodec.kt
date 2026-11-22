package com.wasl.secure.core.protocol

import java.util.Base64

/**
 * Data model representing an encrypted WASL chat message transported via SMS.
 */
data class ChatMessagePacket(
    val conversationId: String,
    val messageId: String,
    val sequenceNumber: Long,
    val chunkIndex: Int = 1,
    val totalChunks: Int = 1,
    val nonce: ByteArray,
    val ciphertextWithTag: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as ChatMessagePacket
        if (conversationId != other.conversationId) return false
        if (messageId != other.messageId) return false
        if (sequenceNumber != other.sequenceNumber) return false
        if (chunkIndex != other.chunkIndex) return false
        if (totalChunks != other.totalChunks) return false
        if (!nonce.contentEquals(other.nonce)) return false
        if (!ciphertextWithTag.contentEquals(other.ciphertextWithTag)) return false
        return true
    }

    override fun hashCode(): Int {
        var result = conversationId.hashCode()
        result = 31 * result + messageId.hashCode()
        result = 31 * result + sequenceNumber.hashCode()
        result = 31 * result + chunkIndex
        result = 31 * result + totalChunks
        result = 31 * result + nonce.contentHashCode()
        result = 31 * result + ciphertextWithTag.contentHashCode()
        return result
    }

    /**
     * Constructs the Additional Authenticated Data (AAD) bound to the ciphertext.
     */
    fun getAad(): ByteArray {
        return "$conversationId:$messageId:$sequenceNumber:$chunkIndex/$totalChunks".toByteArray(Charsets.UTF_8)
    }
}

/**
 * Encodes and decodes encrypted chat message packets for SMS transport.
 * Format: WASL1:MSG:<convId>:<msgId>:<seqNo>:<chunk>/<total>:<nonceB64>:<ciphertextB64>
 */
object ChatMessageCodec {

    private const val PREFIX = "WASL1:MSG:"
    private const val DELIMITER = ":"

    private val b64Encoder = Base64.getUrlEncoder().withoutPadding()
    private val b64Decoder = Base64.getUrlDecoder()

    fun isEncryptedChatMessage(smsBody: String): Boolean {
        return smsBody.startsWith(PREFIX)
    }

    fun encode(packet: ChatMessagePacket): String {
        val nonceB64 = b64Encoder.encodeToString(packet.nonce)
        val cipherB64 = b64Encoder.encodeToString(packet.ciphertextWithTag)
        val chunkStr = "${packet.chunkIndex}/${packet.totalChunks}"

        return "WASL1:MSG:${packet.conversationId}:${packet.messageId}:${packet.sequenceNumber}:$chunkStr:$nonceB64:$cipherB64"
    }

    fun decode(smsBody: String): ChatMessagePacket? {
        return try {
            if (!smsBody.startsWith(PREFIX)) return null
            val parts = smsBody.split(DELIMITER)
            // parts: ["WASL1", "MSG", convId, msgId, seqNo, chunkStr, nonceB64, cipherB64]
            if (parts.size != 8) return null

            val convId = parts[2]
            val msgId = parts[3]
            val seqNo = parts[4].toLong()
            val chunkParts = parts[5].split("/")
            val chunkIndex = chunkParts[0].toInt()
            val totalChunks = chunkParts[1].toInt()
            val nonce = b64Decoder.decode(parts[6])
            val ciphertext = b64Decoder.decode(parts[7])

            ChatMessagePacket(
                conversationId = convId,
                messageId = msgId,
                sequenceNumber = seqNo,
                chunkIndex = chunkIndex,
                totalChunks = totalChunks,
                nonce = nonce,
                ciphertextWithTag = ciphertext
            )
        } catch (e: Exception) {
            null
        }
    }
}
