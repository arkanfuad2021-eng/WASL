package com.wasl.secure.core.protocol

import com.wasl.secure.core.crypto.Curve25519Engine
import com.wasl.secure.core.crypto.DirectionalKeyDerivation
import com.wasl.secure.core.crypto.Hkdf
import com.wasl.secure.core.crypto.IdentityManager
import java.nio.ByteBuffer
import java.security.GeneralSecurityException

/**
 * Orchestrates the full cryptographic handshake lifecycle for both Initiator and Responder.
 * Handles packet construction, verification, state transitions, and directional key installation.
 */
class HandshakeManager(
    private val identityManager: IdentityManager
) {
    // In-memory active handshake sessions (ephemeral state kept during handshake)
    private val activeEphemeralKeys = mutableMapOf<String, Curve25519Engine.KeyPairBytes>()
    private val pendingPeerEphemeralKeys = mutableMapOf<String, ByteArray>()

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

    // ==========================================
    // 1. Initiator: Create INIT Request
    // ==========================================

    fun createInitRequest(
        existingRequestId: String? = null,
        rejectedAt: Long? = null
    ): InitResult {
        // Enforce 3-minute post-rejection cooldown
        val remainingCooldown = HandshakeStateMachine.checkRejectionCooldown(rejectedAt)
        if (remainingCooldown > 0) {
            throw IllegalStateException("لا يمكن إرسال طلب جديد قبل انقضاء المهلة ($remainingCooldown ثانية)")
        }

        // Reuse existing requestId if resending pending; otherwise generate new
        val requestId = existingRequestId ?: HandshakeStateMachine.generateNewRequestId()
        val timestamp = System.currentTimeMillis()

        // Generate ephemeral X25519 key pair for this session
        val ephemeralKeyPair = Curve25519Engine.generateX25519KeyPair()
        activeEphemeralKeys[requestId] = ephemeralKeyPair

        // Sign (requestId || ephemeralPublicKey || timestamp) with our Ed25519 identity key
        val signData = ByteBuffer.allocate(requestId.toByteArray().size + ephemeralKeyPair.publicKey.size + 8)
            .put(requestId.toByteArray())
            .put(ephemeralKeyPair.publicKey)
            .putLong(timestamp)
            .array()

        val signature = identityManager.sign(signData)
        val ourIdentityKey = identityManager.getPublicIdentityKey()

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

    fun verifyIncomingInit(packet: HandshakePacket.Init): Boolean {
        // Verify signature of the initiator
        val signData = ByteBuffer.allocate(packet.requestId.toByteArray().size + packet.ephemeralPublicKey.size + 8)
            .put(packet.requestId.toByteArray())
            .put(packet.ephemeralPublicKey)
            .putLong(packet.timestamp)
            .array()

        val isValid = identityManager.verifyPeerSignature(
            peerPublicKey = packet.identityPublicKey,
            data = signData,
            signature = packet.signature
        )

        if (isValid) {
            // Cache peer ephemeral public key for when the user approves
            pendingPeerEphemeralKeys[packet.requestId] = packet.ephemeralPublicKey
        }

        return isValid
    }

    // ==========================================
    // 3. Responder: Approve and Create RESPONSE
    // ==========================================

    fun acceptInitRequest(requestId: String): ResponseResult {
        val peerEphemeralKey = pendingPeerEphemeralKeys[requestId]
            ?: throw IllegalStateException("طلب التأسيس غير موجود أو منتهي الصلاحية")

        // Generate Responder's ephemeral X25519 key pair
        val ourEphemeral = Curve25519Engine.generateX25519KeyPair()
        activeEphemeralKeys[requestId] = ourEphemeral

        // Sign (requestId || ourEphemeralKey || peerEphemeralKey)
        val signData = ByteBuffer.allocate(requestId.toByteArray().size + ourEphemeral.publicKey.size + peerEphemeralKey.size)
            .put(requestId.toByteArray())
            .put(ourEphemeral.publicKey)
            .put(peerEphemeralKey)
            .array()

        val signature = identityManager.sign(signData)
        val ourIdentityKey = identityManager.getPublicIdentityKey()

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

    fun processResponse(packet: HandshakePacket.Response): ConfirmResult {
        val ourEphemeral = activeEphemeralKeys[packet.requestId]
            ?: throw IllegalStateException("لم يتم العثور على طلب معلق مطابق لهذا المعرّف (${packet.requestId})")

        // Verify responder's signature on (requestId || peerEphemeralKey || ourEphemeralKey)
        val signData = ByteBuffer.allocate(packet.requestId.toByteArray().size + packet.ephemeralPublicKey.size + ourEphemeral.publicKey.size)
            .put(packet.requestId.toByteArray())
            .put(packet.ephemeralPublicKey)
            .put(ourEphemeral.publicKey)
            .array()

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

    // ==========================================
    // 5. Responder: Verify Final CONFIRM
    // ==========================================

    fun verifyConfirm(packet: HandshakePacket.Confirm, expectedSessionKeys: DirectionalKeyDerivation.SessionKeys): Boolean {
        val confirmData = (packet.requestId + ":CONFIRM").toByteArray(Charsets.UTF_8)
        val expectedMac = Hkdf.extract(expectedSessionKeys.confirmationKey, confirmData)

        val isValid = packet.confirmationMac.contentEquals(expectedMac)
        if (isValid) {
            activeEphemeralKeys.remove(packet.requestId)
            pendingPeerEphemeralKeys.remove(packet.requestId)
        }
        return isValid
    }

    // ==========================================
    // 6. Responder: Create REJECT
    // ==========================================

    fun createRejectPacket(requestId: String): String {
        activeEphemeralKeys.remove(requestId)
        pendingPeerEphemeralKeys.remove(requestId)
        val packet = HandshakePacket.Reject(requestId)
        return HandshakePacketCodec.encode(packet)
    }
}
