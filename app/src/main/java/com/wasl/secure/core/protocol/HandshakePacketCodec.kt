package com.wasl.secure.core.protocol

import java.util.Base64

/**
 * Serializes and deserializes WASL Handshake protocol packets for SMS transmission.
 * Enforces the WASL1 protocol magic prefix and validates packet structure.
 */
object HandshakePacketCodec {

    const val MAGIC_PREFIX = "WASL1"
    private const val DELIMITER = ":"

    private const val TYPE_INIT = "INIT"
    private const val TYPE_RESP = "RESP"
    private const val TYPE_CONF = "CONF"
    private const val TYPE_REJ = "REJ"

    private val b64Encoder = Base64.getUrlEncoder().withoutPadding()
    private val b64Decoder = Base64.getUrlDecoder()

    /**
     * Checks if a raw SMS string is a WASL handshake protocol message.
     */
    fun isWaslHandshakeMessage(smsBody: String): Boolean {
        if (!smsBody.startsWith(MAGIC_PREFIX + DELIMITER)) return false
        val parts = smsBody.split(DELIMITER)
        return parts.size >= 3 && (parts[1] in listOf(TYPE_INIT, TYPE_RESP, TYPE_CONF, TYPE_REJ))
    }

    /**
     * Serializes a HandshakePacket into an SMS-compatible string.
     */
    fun encode(packet: HandshakePacket): String {
        return when (packet) {
            is HandshakePacket.Init -> {
                val ikB64 = b64Encoder.encodeToString(packet.identityPublicKey)
                val ekB64 = b64Encoder.encodeToString(packet.ephemeralPublicKey)
                val sigB64 = b64Encoder.encodeToString(packet.signature)
                "$MAGIC_PREFIX:$TYPE_INIT:${packet.requestId}:${packet.timestamp}:$ikB64:$ekB64:$sigB64"
            }
            is HandshakePacket.Response -> {
                val ikB64 = b64Encoder.encodeToString(packet.identityPublicKey)
                val ekB64 = b64Encoder.encodeToString(packet.ephemeralPublicKey)
                val sigB64 = b64Encoder.encodeToString(packet.signature)
                "$MAGIC_PREFIX:$TYPE_RESP:${packet.requestId}:$ikB64:$ekB64:$sigB64"
            }
            is HandshakePacket.Confirm -> {
                val macB64 = b64Encoder.encodeToString(packet.confirmationMac)
                "$MAGIC_PREFIX:$TYPE_CONF:${packet.requestId}:$macB64"
            }
            is HandshakePacket.Reject -> {
                val ikB64 = b64Encoder.encodeToString(packet.identityPublicKey)
                val sigB64 = b64Encoder.encodeToString(packet.signature)
                "$MAGIC_PREFIX:$TYPE_REJ:${packet.requestId}:${packet.timestamp}:$ikB64:$sigB64"
            }
        }
    }

    /**
     * Parses an incoming SMS text into a HandshakePacket.
     * Returns null if the SMS does not belong to WASL or is corrupted.
     */
    fun decode(smsBody: String): HandshakePacket? {
        return try {
            val parts = smsBody.trim().split(DELIMITER)
            if (parts.size < 3 || parts[0] != MAGIC_PREFIX) return null

            val type = parts[1]
            val requestId = parts[2]

            when (type) {
                TYPE_INIT -> {
                    if (parts.size != 7) return null
                    val timestamp = parts[3].toLong()
                    val identityKey = b64Decoder.decode(parts[4])
                    val ephemeralKey = b64Decoder.decode(parts[5])
                    val signature = b64Decoder.decode(parts[6])
                    HandshakePacket.Init(requestId, identityKey, ephemeralKey, timestamp, signature)
                }
                TYPE_RESP -> {
                    if (parts.size != 6) return null
                    val identityKey = b64Decoder.decode(parts[3])
                    val ephemeralKey = b64Decoder.decode(parts[4])
                    val signature = b64Decoder.decode(parts[5])
                    HandshakePacket.Response(requestId, identityKey, ephemeralKey, signature)
                }
                TYPE_CONF -> {
                    if (parts.size != 4) return null
                    val mac = b64Decoder.decode(parts[3])
                    HandshakePacket.Confirm(requestId, mac)
                }
                TYPE_REJ -> {
                    if (parts.size == 6) {
                        val timestamp = parts[3].toLong()
                        val identityKey = b64Decoder.decode(parts[4])
                        val signature = b64Decoder.decode(parts[5])
                        HandshakePacket.Reject(requestId, timestamp, identityKey, signature)
                    } else if (parts.size == 5) {
                        val timestamp = parts[3].toLong()
                        val signature = b64Decoder.decode(parts[4])
                        HandshakePacket.Reject(requestId, timestamp, ByteArray(0), signature)
                    } else {
                        null
                    }
                }
                else -> null
            }
        } catch (e: Exception) {
            null
        }
    }
}
