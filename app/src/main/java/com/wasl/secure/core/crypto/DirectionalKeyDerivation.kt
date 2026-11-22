package com.wasl.secure.core.crypto

/**
 * Derives distinct, directional AES-256 session keys from the X25519 shared secret.
 * Conforms to Section 4.3 of the WASL Master Specification.
 */
object DirectionalKeyDerivation {

    private val SALT = "WASL_PROTOCOL_V1_KEY_SALT".toByteArray(Charsets.UTF_8)
    private val INFO_INITIATOR_TO_RESPONDER = "WASL_V1_KEY_INITIATOR_TO_RESPONDER".toByteArray(Charsets.UTF_8)
    private val INFO_RESPONDER_TO_INITIATOR = "WASL_V1_KEY_RESPONDER_TO_INITIATOR".toByteArray(Charsets.UTF_8)
    private val INFO_CONFIRMATION_MAC = "WASL_V1_KEY_CONFIRMATION_MAC".toByteArray(Charsets.UTF_8)

    data class SessionKeys(
        val outboundKey: ByteArray,   // Key used to encrypt outgoing messages from THIS device
        val inboundKey: ByteArray,    // Key used to decrypt incoming messages from PEER device
        val confirmationKey: ByteArray // Key used to authenticate the CONFIRM handshake message
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as SessionKeys
            if (!outboundKey.contentEquals(other.outboundKey)) return false
            if (!inboundKey.contentEquals(other.inboundKey)) return false
            if (!confirmationKey.contentEquals(other.confirmationKey)) return false
            return true
        }

        override fun hashCode(): Int {
            var result = outboundKey.contentHashCode()
            result = 31 * result + inboundKey.contentHashCode()
            result = 31 * result + confirmationKey.contentHashCode()
            return result
        }
    }

    /**
     * Derives session keys for the INITIATOR (Alice).
     * Outbound key = K_{A -> B}
     * Inbound key = K_{B -> A}
     */
    fun deriveForInitiator(sharedSecret: ByteArray): SessionKeys {
        val prk = Hkdf.extract(SALT, sharedSecret)
        val kAB = Hkdf.expand(prk, INFO_INITIATOR_TO_RESPONDER, 32)
        val kBA = Hkdf.expand(prk, INFO_RESPONDER_TO_INITIATOR, 32)
        val kConf = Hkdf.expand(prk, INFO_CONFIRMATION_MAC, 32)

        return SessionKeys(
            outboundKey = kAB,
            inboundKey = kBA,
            confirmationKey = kConf
        )
    }

    /**
     * Derives session keys for the RESPONDER (Bob).
     * Outbound key = K_{B -> A}
     * Inbound key = K_{A -> B}
     */
    fun deriveForResponder(sharedSecret: ByteArray): SessionKeys {
        val prk = Hkdf.extract(SALT, sharedSecret)
        val kAB = Hkdf.expand(prk, INFO_INITIATOR_TO_RESPONDER, 32)
        val kBA = Hkdf.expand(prk, INFO_RESPONDER_TO_INITIATOR, 32)
        val kConf = Hkdf.expand(prk, INFO_CONFIRMATION_MAC, 32)

        return SessionKeys(
            outboundKey = kBA,
            inboundKey = kAB,
            confirmationKey = kConf
        )
    }
}
