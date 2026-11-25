package com.wasl.secure.core.protocol

import com.wasl.secure.core.crypto.Curve25519Engine
import com.wasl.secure.core.crypto.DirectionalKeyDerivation
import com.wasl.secure.core.crypto.Hkdf
import com.wasl.secure.core.crypto.IdentityManager
import java.nio.ByteBuffer
import java.security.GeneralSecurityException

/**
 * Orchestrates the cryptographic handshake lifecycle for both Initiator and Responder.
 * Enforces canonical signatures with domain separation, binds request IDs,
 * supports idempotent retries, and validates confirmation MACs.
 */
class HandshakeManager(
    private val identityManager: IdentityManager
) {
    // In-memory active handshake sessions (ephemeral state kept during handshake)
    private val keyCacheLock = Any()
    private val activeEphemeralKeys = mutableMapOf<String, Curve25519Engine.KeyPairBytes>()
    private val pendingPeerEphemeralKeys = mutableMapOf<String, ByteArray>()

    fun registerEphemeralKeyPair(requestId: String, keyPair: Curve25519Engine.KeyPairBytes) {
        synchronized(keyCacheLock) {
            activeEphemeralKeys[requestId] = keyPair
        }
    }

    fun getEphemeralKeyPair(requestId: String): Curve25519Engine.KeyPairBytes? {
        return synchronized(keyCacheLock) {
            activeEphemeralKeys[requestId]
        }
    }

    fun registerPendingPeerEphemeralKey(requestId: String, peerEphemeralKey: ByteArray) {
        synchronized(keyCacheLock) {
            val existing = pendingPeerEphemeralKeys[requestId]
            if (existing != null && !existing.contentEquals(peerEphemeralKey)) {
                throw SecurityException("تعارض في المفتاح المؤقت للطرف الآخر للطلب ($requestId)")
            }
            if (existing == null) {
                pendingPeerEphemeralKeys[requestId] = peerEphemeralKey.copyOf()
            }
        }
    }

    fun getPendingPeerEphemeralKey(requestId: String): ByteArray? {
        return synchronized(keyCacheLock) {
            pendingPeerEphemeralKeys[requestId]?.copyOf()
        }
    }

    fun clearEphemeralKeys(requestId: String) {
        synchronized(keyCacheLock) {
            activeEphemeralKeys.remove(requestId)
            pendingPeerEphemeralKeys.remove(requestId)
        }
    }

    data class InitResult(
        val packet: HandshakePacket.Init,
        val smsPayload: String
    )

    data class ResponseResult(
        val packet: HandshakePacket.Response,
        val smsPayload: String,
        val sessionKeys: DirectionalKeyDerivation.SessionKeys
    )

    data class ConfirmResult(
        val packet: HandshakePacket.Confirm,
        val smsPayload: String,
        val sessionKeys: DirectionalKeyDerivation.SessionKeys
    )

    companion object {
        private const val DOMAIN_INIT = "WASL1:INIT:v1:"
        private const val DOMAIN_RESP = "WASL1:RESP:v1:"
        private const val DOMAIN_REJ  = "WASL1:REJ:v1:"
    }

    // ==========================================
    // Canonical Domain-Separated Signature Builders
    // ==========================================

    private fun buildInitSignData(
        requestId: String,
        ourIdentityKey: ByteArray,
        ephemeralPublicKey: ByteArray,
        timestamp: Long
    ): ByteArray {
        val domainBytes = DOMAIN_INIT.toByteArray(Charsets.UTF_8)
        val reqBytes = requestId.toByteArray(Charsets.UTF_8)
        return ByteBuffer.allocate(domainBytes.size + 2 + reqBytes.size + 32 + 32 + 8)
            .put(domainBytes)
            .putShort(reqBytes.size.toShort())
            .put(reqBytes)
            .put(ourIdentityKey)
            .put(ephemeralPublicKey)
            .putLong(timestamp)
            .array()
    }

    private fun buildResponseSignData(
        requestId: String,
        responderIdentityKey: ByteArray,
        responderEphemeralKey: ByteArray,
        initiatorIdentityKey: ByteArray,
        initiatorEphemeralKey: ByteArray
    ): ByteArray {
        val domainBytes = DOMAIN_RESP.toByteArray(Charsets.UTF_8)
        val reqBytes = requestId.toByteArray(Charsets.UTF_8)
        return ByteBuffer.allocate(domainBytes.size + 2 + reqBytes.size + 32 + 32 + 32 + 32)
            .put(domainBytes)
            .putShort(reqBytes.size.toShort())
            .put(reqBytes)
            .put(responderIdentityKey)
            .put(responderEphemeralKey)
            .put(initiatorIdentityKey)
            .put(initiatorEphemeralKey)
            .array()
    }

    private fun buildRejectSignData(
        requestId: String,
        rejectorIdentityKey: ByteArray,
        timestamp: Long
    ): ByteArray {
        val domainBytes = DOMAIN_REJ.toByteArray(Charsets.UTF_8)
        val reqBytes = requestId.toByteArray(Charsets.UTF_8)
        return ByteBuffer.allocate(domainBytes.size + 2 + reqBytes.size + 32 + 8)
            .put(domainBytes)
            .putShort(reqBytes.size.toShort())
            .put(reqBytes)
            .put(rejectorIdentityKey)
            .putLong(timestamp)
            .array()
    }

    // ==========================================
    // 1. Initiator: Create INIT Request (Supports Retry)
    // ==========================================

    fun createInitRequest(
        existingRequestId: String? = null,
        rejectedAt: Long? = null,
        persistedEphemeralKeyPair: Curve25519Engine.KeyPairBytes? = null
    ): InitResult {
        // Enforce 3-minute post-rejection cooldown
        val remainingCooldown = HandshakeStateMachine.checkRejectionCooldown(rejectedAt)
        if (remainingCooldown > 0) {
            throw IllegalStateException("لا يمكن إرسال طلب جديد قبل انقضاء المهلة ($remainingCooldown ثانية)")
        }

        // Reuse existing requestId and ephemeral key if resending a pending request
        val requestId = existingRequestId ?: HandshakeStateMachine.generateNewRequestId()
        val timestamp = System.currentTimeMillis()

        val ephemeralKeyPair = if (persistedEphemeralKeyPair != null) {
            activeEphemeralKeys[requestId] = persistedEphemeralKeyPair
            persistedEphemeralKeyPair
        } else if (existingRequestId != null && activeEphemeralKeys.containsKey(existingRequestId)) {
            activeEphemeralKeys[existingRequestId]!!
        } else if (existingRequestId != null) {
            // Strictly prohibit generating a new key pair for an existing requestId!
            throw IllegalStateException("لا يمكن إنشاء مفتاح جديد لمعرف طلب سابق ($existingRequestId) دون مفتاحه الأصلي")
        } else {
            val generated = Curve25519Engine.generateX25519KeyPair()
            activeEphemeralKeys[requestId] = generated
            generated
        }

        val ourIdentityKey = identityManager.getPublicIdentityKey()
        val signData = buildInitSignData(requestId, ourIdentityKey, ephemeralKeyPair.publicKey, timestamp)
        val signature = identityManager.sign(signData)

        val packet = HandshakePacket.Init(
            requestId = requestId,
            identityPublicKey = ourIdentityKey,
            ephemeralPublicKey = ephemeralKeyPair.publicKey,
            timestamp = timestamp,
            signature = signature
        )

        return InitResult(packet, HandshakePacketCodec.encode(packet))
    }

    // ==========================================
    // 2. Responder: Process Incoming INIT Request
    // ==========================================

    fun verifyIncomingInit(
        packet: HandshakePacket.Init,
        expectedPeerEphemeralKey: ByteArray? = null
    ): Boolean {
        if (expectedPeerEphemeralKey != null && !expectedPeerEphemeralKey.contentEquals(packet.ephemeralPublicKey)) {
            return false
        }

        synchronized(keyCacheLock) {
            val existingCached = pendingPeerEphemeralKeys[packet.requestId]
            if (existingCached != null && !existingCached.contentEquals(packet.ephemeralPublicKey)) {
                return false
            }
        }

        val signData = buildInitSignData(
            requestId = packet.requestId,
            ourIdentityKey = packet.identityPublicKey,
            ephemeralPublicKey = packet.ephemeralPublicKey,
            timestamp = packet.timestamp
        )

        val isValid = identityManager.verifyPeerSignature(
            peerPublicKey = packet.identityPublicKey,
            data = signData,
            signature = packet.signature
        )
        if (!isValid) return false

        synchronized(keyCacheLock) {
            if (expectedPeerEphemeralKey != null && !expectedPeerEphemeralKey.contentEquals(packet.ephemeralPublicKey)) {
                return false
            }
            val existingCached = pendingPeerEphemeralKeys[packet.requestId]
            if (existingCached != null && !existingCached.contentEquals(packet.ephemeralPublicKey)) {
                return false
            }
            if (existingCached == null) {
                pendingPeerEphemeralKeys[packet.requestId] = packet.ephemeralPublicKey.copyOf()
            }
        }

        return true
    }

    // ==========================================
    // 3. Responder: Approve and Create RESPONSE
    // ==========================================

    fun acceptInitRequest(
        requestId: String,
        peerIdentityKey: ByteArray,
        persistedPeerEphemeralKey: ByteArray? = null,
        persistedOurEphemeralKeyPair: Curve25519Engine.KeyPairBytes? = null,
        incomingPeerEphemeralKey: ByteArray? = null
    ): ResponseResult {
        val cachedPeerEphemeral = synchronized(keyCacheLock) {
            pendingPeerEphemeralKeys[requestId]?.copyOf()
        }

        val peerEphemeralKey = persistedPeerEphemeralKey
            ?: cachedPeerEphemeral
            ?: throw IllegalStateException("طلب التأسيس غير موجود أو منتهي الصلاحية")

        if (cachedPeerEphemeral != null && !cachedPeerEphemeral.contentEquals(peerEphemeralKey)) {
            throw SecurityException("تعارض المفتاح المؤقت للطرف الآخر مع المفتاح المحفوظ بالذاكرة للطلب ($requestId)")
        }
        if (incomingPeerEphemeralKey != null && !incomingPeerEphemeralKey.contentEquals(peerEphemeralKey)) {
            throw SecurityException("تعارض المفتاح المؤقت الوارد مع المفتاح المحفوظ للطلب ($requestId)")
        }

        synchronized(keyCacheLock) {
            val currentCached = pendingPeerEphemeralKeys[requestId]
            if (currentCached != null && !currentCached.contentEquals(peerEphemeralKey)) {
                throw SecurityException("تعارض المفتاح المؤقت للطرف الآخر مع المفتاح المحفوظ للطلب ($requestId)")
            }
            if (currentCached == null) {
                pendingPeerEphemeralKeys[requestId] = peerEphemeralKey.copyOf()
            }
        }

        // Retrieve existing or generate Responder's ephemeral X25519 key pair
        val ourEphemeral = synchronized(keyCacheLock) {
            val resolved = persistedOurEphemeralKeyPair
                ?: activeEphemeralKeys[requestId]
                ?: run {
                    val generated = Curve25519Engine.generateX25519KeyPair()
                    activeEphemeralKeys[requestId] = generated
                    generated
                }
            activeEphemeralKeys[requestId] = resolved
            resolved
        }

        val ourIdentityKey = identityManager.getPublicIdentityKey()

        val signData = buildResponseSignData(
            requestId = requestId,
            responderIdentityKey = ourIdentityKey,
            responderEphemeralKey = ourEphemeral.publicKey,
            initiatorIdentityKey = peerIdentityKey,
            initiatorEphemeralKey = peerEphemeralKey
        )

        val signature = identityManager.sign(signData)

        // Compute shared secret and derive directional session keys
        val sharedSecret = Curve25519Engine.computeSharedSecret(ourEphemeral.privateKey, peerEphemeralKey)
        val sessionKeys = DirectionalKeyDerivation.deriveForResponder(sharedSecret)

        val packet = HandshakePacket.Response(
            requestId = requestId,
            identityPublicKey = ourIdentityKey,
            ephemeralPublicKey = ourEphemeral.publicKey,
            signature = signature
        )

        return ResponseResult(packet, HandshakePacketCodec.encode(packet), sessionKeys)
    }

    // ==========================================
    // 4. Initiator: Process RESPONSE & Create CONFIRM
    // ==========================================

    fun processResponse(
        packet: HandshakePacket.Response,
        persistedOurEphemeralKeyPair: Curve25519Engine.KeyPairBytes? = null
    ): ConfirmResult {
        val ourEphemeral = activeEphemeralKeys[packet.requestId]
            ?: persistedOurEphemeralKeyPair
            ?: throw IllegalStateException("لم يتم العثور على طلب معلق مطابق لهذا المعرّف (${packet.requestId})")

        val ourIdentityKey = identityManager.getPublicIdentityKey()

        // Verify responder's canonical signature on (Domain || reqId || IK_B || EK_B || IK_A || EK_A)
        val signData = buildResponseSignData(
            requestId = packet.requestId,
            responderIdentityKey = packet.identityPublicKey,
            responderEphemeralKey = packet.ephemeralPublicKey,
            initiatorIdentityKey = ourIdentityKey,
            initiatorEphemeralKey = ourEphemeral.publicKey
        )

        val isSigValid = identityManager.verifyPeerSignature(
            peerPublicKey = packet.identityPublicKey,
            data = signData,
            signature = packet.signature
        )

        if (!isSigValid) {
            throw GeneralSecurityException("فشل التحقق من التوقيع الرقمي للمستلم! احتمال وجود تلاعب")
        }

        // Compute identical shared secret and derive session keys
        val sharedSecret = Curve25519Engine.computeSharedSecret(ourEphemeral.privateKey, packet.ephemeralPublicKey)
        val sessionKeys = DirectionalKeyDerivation.deriveForInitiator(sharedSecret)

        // Compute confirmation MAC
        val confirmData = (packet.requestId + ":CONFIRM").toByteArray(Charsets.UTF_8)
        val confirmMac = Hkdf.extract(sessionKeys.confirmationKey, confirmData)

        val confirmPacket = HandshakePacket.Confirm(packet.requestId, confirmMac)

        // Clean up temporary ephemeral key
        activeEphemeralKeys.remove(packet.requestId)

        return ConfirmResult(confirmPacket, HandshakePacketCodec.encode(confirmPacket), sessionKeys)
    }

    /**
     * Recreates a CONFIRM packet for resending when initial transmission failed.
     */
    fun createConfirmPacket(requestId: String, confirmationKey: ByteArray): Pair<HandshakePacket.Confirm, String> {
        val confirmData = (requestId + ":CONFIRM").toByteArray(Charsets.UTF_8)
        val confirmMac = Hkdf.extract(confirmationKey, confirmData)
        val packet = HandshakePacket.Confirm(requestId, confirmMac)
        return Pair(packet, HandshakePacketCodec.encode(packet))
    }

    // ==========================================
    // 5. Responder: Verify Final CONFIRM
    // ==========================================

    fun verifyConfirm(packet: HandshakePacket.Confirm, confirmationKey: ByteArray): Boolean {
        val confirmData = (packet.requestId + ":CONFIRM").toByteArray(Charsets.UTF_8)
        val expectedMac = Hkdf.extract(confirmationKey, confirmData)

        val isValid = packet.confirmationMac.contentEquals(expectedMac)
        if (isValid) {
            activeEphemeralKeys.remove(packet.requestId)
            pendingPeerEphemeralKeys.remove(packet.requestId)
        }
        return isValid
    }

    // ==========================================
    // 6. Responder: Create Signed REJECT
    // ==========================================

    fun createRejectPacket(requestId: String): Pair<HandshakePacket.Reject, String> {
        activeEphemeralKeys.remove(requestId)
        pendingPeerEphemeralKeys.remove(requestId)

        val timestamp = System.currentTimeMillis()
        val ourIdentityKey = identityManager.getPublicIdentityKey()
        val signData = buildRejectSignData(requestId, ourIdentityKey, timestamp)
        val signature = identityManager.sign(signData)

        val packet = HandshakePacket.Reject(
            requestId = requestId,
            timestamp = timestamp,
            identityPublicKey = ourIdentityKey,
            signature = signature
        )
        return Pair(packet, HandshakePacketCodec.encode(packet))
    }

    // ==========================================
    // 7. Initiator: Verify Incoming Signed REJECT
    // ==========================================

    fun verifyReject(packet: HandshakePacket.Reject, expectedPeerIdentityKey: ByteArray): Boolean {
        // 1. Identity key in packet must match expected pinned key
        if (packet.identityPublicKey.isNotEmpty() && !packet.identityPublicKey.contentEquals(expectedPeerIdentityKey)) {
            return false
        }
        // 2. Freshness check: Reject packet must be within 10 minutes
        val now = System.currentTimeMillis()
        if (Math.abs(now - packet.timestamp) > 10 * 60 * 1000L) {
            return false
        }
        // 3. Verify canonical Ed25519 signature
        val signData = buildRejectSignData(packet.requestId, expectedPeerIdentityKey, packet.timestamp)
        return identityManager.verifyPeerSignature(
            peerPublicKey = expectedPeerIdentityKey,
            data = signData,
            signature = packet.signature
        )
    }
}
