package com.wasl.secure.core.protocol

sealed class HandshakePacket {
    abstract val requestId: String

    data class Init(
        override val requestId: String,
        val identityPublicKey: ByteArray,
        val ephemeralPublicKey: ByteArray,
        val timestamp: Long,
        val signature: ByteArray
    ) : HandshakePacket() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as Init
            if (requestId != other.requestId) return false
            if (!identityPublicKey.contentEquals(other.identityPublicKey)) return false
            if (!ephemeralPublicKey.contentEquals(other.ephemeralPublicKey)) return false
            if (timestamp != other.timestamp) return false
            if (!signature.contentEquals(other.signature)) return false
            return true
        }

        override fun hashCode(): Int {
            var result = requestId.hashCode()
            result = 31 * result + identityPublicKey.contentHashCode()
            result = 31 * result + ephemeralPublicKey.contentHashCode()
            result = 31 * result + timestamp.hashCode()
            result = 31 * result + signature.contentHashCode()
            return result
        }
    }

    data class Response(
        override val requestId: String,
        val identityPublicKey: ByteArray,
        val ephemeralPublicKey: ByteArray,
        val signature: ByteArray
    ) : HandshakePacket() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as Response
            if (requestId != other.requestId) return false
            if (!identityPublicKey.contentEquals(other.identityPublicKey)) return false
            if (!ephemeralPublicKey.contentEquals(other.ephemeralPublicKey)) return false
            if (!signature.contentEquals(other.signature)) return false
            return true
        }

        override fun hashCode(): Int {
            var result = requestId.hashCode()
            result = 31 * result + identityPublicKey.contentHashCode()
            result = 31 * result + ephemeralPublicKey.contentHashCode()
            result = 31 * result + signature.contentHashCode()
            return result
        }
    }

    data class Confirm(
        override val requestId: String,
        val confirmationMac: ByteArray
    ) : HandshakePacket() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as Confirm
            if (requestId != other.requestId) return false
            if (!confirmationMac.contentEquals(other.confirmationMac)) return false
            return true
        }

        override fun hashCode(): Int {
            var result = requestId.hashCode()
            result = 31 * result + confirmationMac.contentHashCode()
            return result
        }
    }

    data class Reject(
        override val requestId: String
    ) : HandshakePacket()
}
