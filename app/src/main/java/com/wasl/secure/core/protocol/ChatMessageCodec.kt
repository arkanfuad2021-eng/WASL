package com.wasl.secure.core.protocol

import java.nio.ByteBuffer
import java.util.Base64

/**
 * Data model representing an encrypted WASL chat message transported via SMS.
 * Conforms to Phase 3 specification with 64-bit entropy IDs and isolated attempt tracking.
 */
data class ChatMessagePacket(
    val conversationId: String,       // 16-hex characters (64-bit entropy)
    val messageId: String,            // 16-hex characters (64-bit entropy)
    val attemptId: String = "0001",   // 4-hex characters (e.g. "0001" to "FFFF")
    val sequenceNumber: Long = 0L,    // Monotonic counter extracted from Nonce
    val chunkIndex: Int = 1,
    val totalChunks: Int = 1,
    val nonce: ByteArray,             // 12-byte Nonce (4-byte prefix + 8-byte counter)
    val ciphertextWithTag: ByteArray  // Max 63 bytes per SMS slice
) {
    // Secondary constructor for positional calls passing (convId, msgId, seqNo, chunkIndex, totalChunks, nonce, ciphertext)
    constructor(
        conversationId: String,
        messageId: String,
        sequenceNumber: Long,
        chunkIndex: Int,
        totalChunks: Int,
        nonce: ByteArray,
        ciphertextWithTag: ByteArray
    ) : this(
        conversationId = conversationId,
        messageId = messageId,
        attemptId = "0001",
        sequenceNumber = sequenceNumber,
        chunkIndex = chunkIndex,
        totalChunks = totalChunks,
        nonce = nonce,
        ciphertextWithTag = ciphertextWithTag
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as ChatMessagePacket
        if (conversationId != other.conversationId) return false
        if (messageId != other.messageId) return false
        if (attemptId != other.attemptId) return false
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
        result = 31 * result + attemptId.hashCode()
        result = 31 * result + sequenceNumber.hashCode()
        result = 31 * result + chunkIndex
        result = 31 * result + totalChunks
        result = 31 * result + nonce.contentHashCode()
        result = 31 * result + ciphertextWithTag.contentHashCode()
        return result
    }

    /**
     * Constructs the Additional Authenticated Data (AAD) bound to the ciphertext.
     * Note: AAD is bound to the parent message and original sequence number,
     * allowing identical ciphertext to be resent across attempts without breaking integrity.
     */
    fun getAad(): ByteArray {
        return "$conversationId:$messageId:$sequenceNumber:1/$totalChunks".toByteArray(Charsets.UTF_8)
    }
}

/**
 * Encodes and decodes encrypted chat message packets for single-segment SMS transport.
 * Format: WASL1:MSG:<convId>:<msgId>:<attemptId>:<chunk>/<total>:<nonceB64>:<ciphertextB64>
 */
object ChatMessageCodec {

    private const val PREFIX = "WASL1:MSG:"
    private const val DELIMITER = ":"

    private val HEX_16_REGEX = Regex("^[0-9a-fA-F]{16}$")
    private val HEX_4_REGEX = Regex("^[0-9a-fA-F]{4}$")

    private val b64Encoder = Base64.getUrlEncoder().withoutPadding()
    private val b64Decoder = Base64.getUrlDecoder()

    fun isEncryptedChatMessage(smsBody: String): Boolean {
        return smsBody.startsWith(PREFIX)
    }

    fun encode(packet: ChatMessagePacket): String {
        val nonceB64 = b64Encoder.encodeToString(packet.nonce)
        val cipherB64 = b64Encoder.encodeToString(packet.ciphertextWithTag)
        val chunkStr = "${packet.chunkIndex}/${packet.totalChunks}"

        return "WASL1:MSG:${packet.conversationId}:${packet.messageId}:${packet.attemptId}:$chunkStr:$nonceB64:$cipherB64"
    }

    fun decode(smsBody: String): ChatMessagePacket? {
        return try {
            if (!smsBody.startsWith(PREFIX)) return null
            val parts = smsBody.split(DELIMITER)
            // Expected: ["WASL1", "MSG", convId, msgId, attemptId, chunkStr, nonceB64, cipherB64]
            if (parts.size != 8) return null

            val convId = parts[2]
            val msgId = parts[3]
            val attemptId = parts[4]
            val chunkStr = parts[5]

            // 1. Strict validation of 16-hex convId and msgId (64 bits of entropy)
            if (!HEX_16_REGEX.matches(convId) || !HEX_16_REGEX.matches(msgId)) return null

            // 2. Strict validation of 4-hex attemptId (range 1..65535)
            if (!HEX_4_REGEX.matches(attemptId)) return null
            val attemptVal = attemptId.toInt(16)
            if (attemptVal < 1 || attemptVal > 0xFFFF) return null

            // 3. Strict validation of chunk numbers
            val chunkParts = chunkStr.split("/")
            if (chunkParts.size != 2) return null
            val chunkIndex = chunkParts[0].toIntOrNull() ?: return null
            val totalChunks = chunkParts[1].toIntOrNull() ?: return null
            if (totalChunks < 1 || totalChunks > 99) return null
            if (chunkIndex < 1 || chunkIndex > totalChunks) return null

            // 4. Strict validation of Nonce (must decode to exactly 12 bytes)
            val nonce = b64Decoder.decode(parts[6])
            if (nonce.size != 12) return null

            // 5. Strict validation of Ciphertext payload (1..63 bytes; >= 16 bytes for single chunk messages)
            val ciphertext = b64Decoder.decode(parts[7])
            if (ciphertext.isEmpty() || ciphertext.size > 63) return null
            if (totalChunks == 1 && ciphertext.size < 16) return null

            // Extract 64-bit monotonic sequence counter from bytes 4..11 of the 12-byte Nonce
            val seqNo = ByteBuffer.wrap(nonce).getLong(4)

            ChatMessagePacket(
                conversationId = convId,
                messageId = msgId,
                attemptId = attemptId,
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
