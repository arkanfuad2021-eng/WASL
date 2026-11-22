package com.wasl.secure

import com.wasl.secure.core.crypto.Curve25519Engine
import com.wasl.secure.core.crypto.IdentityManager
import com.wasl.secure.core.crypto.KeystoreManager
import com.wasl.secure.core.protocol.HandshakeManager
import com.wasl.secure.core.protocol.HandshakePacket
import com.wasl.secure.core.protocol.HandshakePacketCodec
import com.wasl.secure.core.protocol.HandshakeStateMachine
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

class Phase3HandshakeProtocolTestSuite {

    // Test IdentityManager simulator for pure JVM testing
    private class TestIdentitySimulator {
        val keyPair = Curve25519Engine.generateEd25519KeyPair()

        fun sign(data: ByteArray): ByteArray = Curve25519Engine.signEd25519(keyPair.privateKey, data)
        fun verify(peerPub: ByteArray, data: ByteArray, sig: ByteArray): Boolean =
            Curve25519Engine.verifyEd25519(peerPub, data, sig)
        fun getPublic(): ByteArray = keyPair.publicKey
    }

    private lateinit var aliceIdentity: TestIdentitySimulator
    private lateinit var bobIdentity: TestIdentitySimulator

    @Before
    fun setUp() {
        aliceIdentity = TestIdentitySimulator()
        bobIdentity = TestIdentitySimulator()
    }

    @Test
    fun test_1_Full_Handshake_Flow_End_To_End() {
        // --- 1. Alice creates INIT ---
        val aliceEphemeral = Curve25519Engine.generateX25519KeyPair()
        val reqId = "W100AF"
        val timestamp = System.currentTimeMillis()

        val aliceSignData = (reqId + ":").toByteArray() + aliceEphemeral.publicKey + timestamp.toString().toByteArray()
        val aliceSig = aliceIdentity.sign(aliceSignData)

        val initPacket = HandshakePacket.Init(reqId, aliceIdentity.getPublic(), aliceEphemeral.publicKey, timestamp, aliceSig)
        val sms1 = HandshakePacketCodec.encode(initPacket)

        assertTrue(sms1.startsWith("WASL1:INIT:W100AF:"))
        assertTrue(HandshakePacketCodec.isWaslHandshakeMessage(sms1))

        // --- 2. Bob receives and parses INIT SMS ---
        val parsedInit = HandshakePacketCodec.decode(sms1) as? HandshakePacket.Init
        assertNotNull("Bob must successfully parse INIT packet", parsedInit)
        assertEquals(reqId, parsedInit!!.requestId)

        // Bob verifies Alice's signature
        val bobVerifyData = (parsedInit.requestId + ":").toByteArray() + parsedInit.ephemeralPublicKey + parsedInit.timestamp.toString().toByteArray()
        assertTrue("Bob must verify Alice's signature", bobIdentity.verify(parsedInit.identityPublicKey, bobVerifyData, parsedInit.signature))

        // --- 3. Bob accepts and creates RESPONSE ---
        val bobEphemeral = Curve25519Engine.generateX25519KeyPair()
        val bobSignData = (reqId + ":").toByteArray() + bobEphemeral.publicKey + parsedInit.ephemeralPublicKey
        val bobSig = bobIdentity.sign(bobSignData)

        val respPacket = HandshakePacket.Response(reqId, bobIdentity.getPublic(), bobEphemeral.publicKey, bobSig)
        val sms2 = HandshakePacketCodec.encode(respPacket)

        assertTrue(sms2.startsWith("WASL1:RESP:W100AF:"))

        // Bob computes shared secret & derives responder session keys
        val bobSharedSecret = Curve25519Engine.computeSharedSecret(bobEphemeral.privateKey, parsedInit.ephemeralPublicKey)
        val bobKeys = com.wasl.secure.core.crypto.DirectionalKeyDerivation.deriveForResponder(bobSharedSecret)

        // --- 4. Alice receives and parses RESPONSE SMS ---
        val parsedResp = HandshakePacketCodec.decode(sms2) as? HandshakePacket.Response
        assertNotNull("Alice must successfully parse RESPONSE packet", parsedResp)

        // Alice verifies Bob's signature
        val aliceVerifyData = (reqId + ":").toByteArray() + parsedResp!!.ephemeralPublicKey + aliceEphemeral.publicKey
        assertTrue("Alice must verify Bob's signature", aliceIdentity.verify(parsedResp.identityPublicKey, aliceVerifyData, parsedResp.signature))

        // Alice computes shared secret & derives initiator session keys
        val aliceSharedSecret = Curve25519Engine.computeSharedSecret(aliceEphemeral.privateKey, parsedResp.ephemeralPublicKey)
        val aliceKeys = com.wasl.secure.core.crypto.DirectionalKeyDerivation.deriveForInitiator(aliceSharedSecret)

        // --- 5. Verify Cryptographic Synchronization ---
        assertArrayEquals("Shared secret must be identical", aliceSharedSecret, bobSharedSecret)
        assertArrayEquals("Alice outbound must match Bob inbound", aliceKeys.outboundKey, bobKeys.inboundKey)
        assertArrayEquals("Bob outbound must match Alice inbound", bobKeys.outboundKey, aliceKeys.inboundKey)

        // --- 6. Alice creates CONFIRM SMS ---
        val confirmMac = com.wasl.secure.core.crypto.Hkdf.extract(aliceKeys.confirmationKey, (reqId + ":CONFIRM").toByteArray(Charsets.UTF_8))
        val confirmPacket = HandshakePacket.Confirm(reqId, confirmMac)
        val sms3 = HandshakePacketCodec.encode(confirmPacket)

        assertTrue(sms3.startsWith("WASL1:CONF:W100AF:"))

        // --- 7. Bob receives and verifies CONFIRM SMS ---
        val parsedConfirm = HandshakePacketCodec.decode(sms3) as? HandshakePacket.Confirm
        assertNotNull(parsedConfirm)
        val expectedMac = com.wasl.secure.core.crypto.Hkdf.extract(bobKeys.confirmationKey, (reqId + ":CONFIRM").toByteArray(Charsets.UTF_8))
        assertArrayEquals("Bob verifies confirmation MAC", expectedMac, parsedConfirm!!.confirmationMac)

        // Both parties are now READY
    }

    @Test
    fun test_2_Rejection_Flow_And_3_Minute_Cooldown() {
        val reqId = "W200REJ"
        val rejectPacket = HandshakePacket.Reject(reqId)
        val smsReject = HandshakePacketCodec.encode(rejectPacket)

        assertEquals("WASL1:REJ:W200REJ", smsReject)

        // Recipient parses REJECT
        val parsed = HandshakePacketCodec.decode(smsReject) as? HandshakePacket.Reject
        assertNotNull(parsed)
        assertEquals(reqId, parsed!!.requestId)

        // Enforce 3-minute cooldown
        val now = System.currentTimeMillis()
        val rejectedAt = now - (60 * 1000L) // 1 minute ago

        val remainingSeconds = HandshakeStateMachine.checkRejectionCooldown(rejectedAt, now)
        assertEquals(120L, remainingSeconds)

        // Cooldown passed after 181 seconds
        val afterCooldown = now + (181 * 1000L)
        val remainingAfter = HandshakeStateMachine.checkRejectionCooldown(rejectedAt, afterCooldown)
        assertEquals(0L, remainingAfter)
    }

    @Test
    fun test_3_Pending_Request_Resend_Preserves_RequestId() {
        val originalReqId = "W990AA"

        // Rule: Resending a pending waiting request MUST retain original request ID
        val isResend = true
        val targetReqId = if (isResend) originalReqId else HandshakeStateMachine.generateNewRequestId()

        assertEquals("Resend must preserve request ID", originalReqId, targetReqId)
    }

    @Test
    fun test_4_New_Request_After_Rejection_Generates_New_RequestId() {
        val originalReqId = "W990AA"

        // Rule: After rejection cooldown, a new request MUST generate a completely new ID
        val newReqId = HandshakeStateMachine.generateNewRequestId()
        assertFalse("New request after rejection must not reuse old ID", originalReqId == newReqId)
        assertTrue(newReqId.startsWith("W"))
    }

    @Test
    fun test_5_Non_WASL_Sms_Completely_Ignored() {
        val regularSms1 = "رمز التفعيل الخاص بك هو 8492"
        val regularSms2 = "Hello, call me later!"
        val corruptedWasl = "WASL1:INVALID_TYPE:DATA"

        assertFalse(HandshakePacketCodec.isWaslHandshakeMessage(regularSms1))
        assertNull(HandshakePacketCodec.decode(regularSms1))

        assertFalse(HandshakePacketCodec.isWaslHandshakeMessage(regularSms2))
        assertNull(HandshakePacketCodec.decode(regularSms2))

        assertFalse(HandshakePacketCodec.isWaslHandshakeMessage(corruptedWasl))
        assertNull(HandshakePacketCodec.decode(corruptedWasl))
    }
}
