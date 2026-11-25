package com.wasl.secure

import com.wasl.secure.core.crypto.Curve25519Engine
import com.wasl.secure.core.crypto.IdentityManager
import com.wasl.secure.core.crypto.KeystoreManager
import com.wasl.secure.core.crypto.SafetyNumberGenerator
import com.wasl.secure.core.protocol.HandshakeManager
import com.wasl.secure.core.protocol.HandshakePacket
import com.wasl.secure.core.protocol.HandshakePacketCodec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class Phase2HandshakeSecurityTest {

    private lateinit var aliceContext: TestMockContext
    private lateinit var bobContext: TestMockContext

    private lateinit var aliceKeystore: KeystoreManager
    private lateinit var bobKeystore: KeystoreManager

    private lateinit var aliceIdentity: IdentityManager
    private lateinit var bobIdentity: IdentityManager

    private lateinit var aliceHandshakeManager: HandshakeManager
    private lateinit var bobHandshakeManager: HandshakeManager

    @Before
    fun setUp() {
        aliceContext = TestMockContext()
        bobContext = TestMockContext()

        aliceKeystore = KeystoreManager("TEST_JVM_FALLBACK")
        bobKeystore = KeystoreManager("TEST_JVM_FALLBACK")

        aliceIdentity = IdentityManager(aliceContext, aliceKeystore)
        bobIdentity = IdentityManager(bobContext, bobKeystore)

        aliceHandshakeManager = HandshakeManager(aliceIdentity)
        bobHandshakeManager = HandshakeManager(bobIdentity)
    }

    @Test
    fun test_safety_number_matching_between_alice_and_bob() {
        val alicePubKey = aliceIdentity.getPublicIdentityKey()
        val bobPubKey = bobIdentity.getPublicIdentityKey()

        // 1. Both devices calculate Safety Number
        val aliceSafetyNumber = SafetyNumberGenerator.generateSafetyNumber(alicePubKey, bobPubKey)
        val bobSafetyNumber = SafetyNumberGenerator.generateSafetyNumber(bobPubKey, alicePubKey)

        // 2. Both numbers must match identically
        assertNotNull(aliceSafetyNumber)
        assertEquals(
            "Safety Numbers calculated on Alice and Bob's devices must match 100%",
            aliceSafetyNumber,
            bobSafetyNumber
        )

        // 3. QR Code payload validation
        val bobQrPayload = SafetyNumberGenerator.generateQrPayload(bobPubKey, alicePubKey)
        val isQrMatch = SafetyNumberGenerator.parseAndVerifyQrPayload(bobQrPayload, alicePubKey, bobPubKey)
        assertTrue("Scanned QR code must verify matching key pair", isQrMatch)

        // 4. QR with mismatched key must fail
        val fakeKey = Curve25519Engine.generateEd25519KeyPair().publicKey
        val isFakeMatch = SafetyNumberGenerator.parseAndVerifyQrPayload(bobQrPayload, fakeKey, bobPubKey)
        assertFalse("Scanned QR code with foreign key must fail verification", isFakeMatch)
    }

    @Test
    fun test_handshake_canonical_signatures_and_confirm_mac_verification() {
        // Step 1: Alice creates INIT request
        val initResult = aliceHandshakeManager.createInitRequest()
        assertNotNull(initResult.packet)

        // Step 2: Bob receives and verifies INIT
        val isInitValid = bobHandshakeManager.verifyIncomingInit(initResult.packet)
        assertTrue("Bob must verify Alice's canonical INIT signature", isInitValid)

        // Step 3: Bob accepts INIT and creates RESPONSE
        val respResult = bobHandshakeManager.acceptInitRequest(
            requestId = initResult.packet.requestId,
            peerIdentityKey = initResult.packet.identityPublicKey
        )
        assertNotNull(respResult.packet)

        // Step 4: Alice processes RESPONSE and creates CONFIRM
        val confirmResult = aliceHandshakeManager.processResponse(respResult.packet)
        assertNotNull(confirmResult.packet)

        // Verify that directional session keys on both sides match
        assertArrayEquals(
            "Alice's outbound key must equal Bob's inbound key",
            confirmResult.sessionKeys.outboundKey,
            respResult.sessionKeys.inboundKey
        )
        assertArrayEquals(
            "Alice's inbound key must equal Bob's outbound key",
            confirmResult.sessionKeys.inboundKey,
            respResult.sessionKeys.outboundKey
        )

        // Step 5: Bob verifies final CONFIRM packet
        val isConfirmValid = bobHandshakeManager.verifyConfirm(
            packet = confirmResult.packet,
            confirmationKey = respResult.sessionKeys.confirmationKey
        )
        assertTrue("Bob must verify Alice's confirmation MAC successfully", isConfirmValid)

        // Step 6: Test corrupted confirmation MAC -> MUST FAIL
        val corruptedMac = confirmResult.packet.confirmationMac.clone()
        corruptedMac[0] = (corruptedMac[0] + 1).toByte()
        val badConfirmPacket = HandshakePacket.Confirm(confirmResult.packet.requestId, corruptedMac)

        val isCorruptedConfirmValid = bobHandshakeManager.verifyConfirm(
            packet = badConfirmPacket,
            confirmationKey = respResult.sessionKeys.confirmationKey
        )
        assertFalse("Corrupted confirmation MAC must fail verification", isCorruptedConfirmValid)
    }

    @Test
    fun test_reject_packet_signature_and_verification() {
        val requestId = "req_test_12345"

        // Bob creates signed REJECT packet
        val (rejectPacket, encodedPayload) = bobHandshakeManager.createRejectPacket(requestId)
        assertEquals(requestId, rejectPacket.requestId)
        assertTrue("Reject packet must be digitally signed", rejectPacket.signature.isNotEmpty())
        assertArrayEquals("Reject packet must embed rejector public identity key", bobIdentity.getPublicIdentityKey(), rejectPacket.identityPublicKey)

        // Codec roundtrip test
        val decodedPacket = HandshakePacketCodec.decode(encodedPayload)
        assertNotNull(decodedPacket)
        assertTrue(decodedPacket is HandshakePacket.Reject)
        val decodedReject = decodedPacket as HandshakePacket.Reject
        assertArrayEquals("Decoded packet must preserve identity public key", bobIdentity.getPublicIdentityKey(), decodedReject.identityPublicKey)

        // Alice verifies Bob's signature with Bob's pinned identity key
        val isSignatureValid = aliceHandshakeManager.verifyReject(decodedReject, bobIdentity.getPublicIdentityKey())
        assertTrue("Alice must verify Bob's signature on REJECT packet", isSignatureValid)

        // Mismatched public key (attacker trying to substitute rejector key) must fail
        val attackerKey = Curve25519Engine.generateEd25519KeyPair().publicKey
        val attackerReject = decodedReject.copy(identityPublicKey = attackerKey)
        val isMismatchedKeyValid = aliceHandshakeManager.verifyReject(attackerReject, bobIdentity.getPublicIdentityKey())
        assertFalse("REJECT packet with swapped public key must fail verification", isMismatchedKeyValid)

        // Expired or future timestamp outside 10 minutes must fail
        val expiredReject = decodedReject.copy(timestamp = System.currentTimeMillis() - 15 * 60 * 1000L)
        val isExpiredValid = aliceHandshakeManager.verifyReject(expiredReject, bobIdentity.getPublicIdentityKey())
        assertFalse("REJECT packet older than 10 minutes must fail freshness verification", isExpiredValid)
    }

    @Test
    fun test_response_key_change_detection() {
        // Alice creates INIT
        val initResult = aliceHandshakeManager.createInitRequest()

        // Bob must verify incoming INIT first so Alice's ephemeral key is pinned
        assertTrue(bobHandshakeManager.verifyIncomingInit(initResult.packet))

        // Bob creates normal RESPONSE
        val bobRespResult = bobHandshakeManager.acceptInitRequest(
            requestId = initResult.packet.requestId,
            peerIdentityKey = initResult.packet.identityPublicKey
        )

        // Alice already pinned Bob's identity key previously
        val pinnedBobKey = bobIdentity.getPublicIdentityKey()

        // Attacker Eve intercepts and replaces Bob's response with Eve's key
        val eveKeyPair = Curve25519Engine.generateEd25519KeyPair()
        val eveSignData = bobRespResult.packet.signature.clone() // corrupted/different
        val evePacket = HandshakePacket.Response(
            requestId = initResult.packet.requestId,
            identityPublicKey = eveKeyPair.publicKey,
            ephemeralPublicKey = bobRespResult.packet.ephemeralPublicKey,
            signature = eveSignData
        )

        // When Alice checks if pinnedBobKey != evePacket.identityPublicKey
        val isKeyChanged = !pinnedBobKey.contentEquals(evePacket.identityPublicKey)
        assertTrue("Alice must detect that peer identity key changed from previously pinned key", isKeyChanged)

        // Attempting to process Eve's tampered packet must throw GeneralSecurityException
        try {
            aliceHandshakeManager.processResponse(evePacket)
            org.junit.Assert.fail("Processing response with foreign key or forged signature must throw exception")
        } catch (e: Exception) {
            assertTrue("Expected security exception on key tampering", e is java.security.GeneralSecurityException || e is IllegalStateException)
        }
    }

    @Test
    fun test_ephemeral_key_persistence_and_idempotent_init_handling() {
        // Alice creates INIT
        val initResult = aliceHandshakeManager.createInitRequest()
        val requestId = initResult.packet.requestId

        // Bob verifies and accepts INIT
        assertTrue(bobHandshakeManager.verifyIncomingInit(initResult.packet))
        val respResult1 = bobHandshakeManager.acceptInitRequest(
            requestId = requestId,
            peerIdentityKey = initResult.packet.identityPublicKey
        )

        // Simulate app restart / process kill:
        // Bob's ephemeral private key is saved and reloaded from DB
        val bobEphKeyPair = bobHandshakeManager.getEphemeralKeyPair(requestId)
        assertNotNull(bobEphKeyPair)
        val persistedBobPriv = bobEphKeyPair!!.privateKey.clone()
        val reconstructedBobPub = Curve25519Engine.getX25519PublicKeyFromPrivateKey(persistedBobPriv)
        assertArrayEquals("Reconstructed public key must match original ephemeral public key", bobEphKeyPair.publicKey, reconstructedBobPub)

        // Bob's in-memory state is cleared (simulating fresh app process)
        bobHandshakeManager.clearEphemeralKeys(requestId)

        // Duplicate INIT arrives at Bob with identical requestId and ephemeral key
        val reconstructedKeyPair = Curve25519Engine.KeyPairBytes(persistedBobPriv, reconstructedBobPub)
        val respResult2 = bobHandshakeManager.acceptInitRequest(
            requestId = requestId,
            peerIdentityKey = initResult.packet.identityPublicKey,
            persistedPeerEphemeralKey = initResult.packet.ephemeralPublicKey,
            persistedOurEphemeralKeyPair = reconstructedKeyPair
        )

        // Assert identical RESPONSE packet and identical derived session keys
        assertArrayEquals(
            "Idempotent retry must produce identical outbound session keys even after app restart",
            respResult1.sessionKeys.outboundKey,
            respResult2.sessionKeys.outboundKey
        )
        assertArrayEquals(
            "Idempotent retry must produce identical inbound session keys even after app restart",
            respResult1.sessionKeys.inboundKey,
            respResult2.sessionKeys.inboundKey
        )
        assertArrayEquals(
            "Idempotent retry must produce identical confirmation keys even after app restart",
            respResult1.sessionKeys.confirmationKey,
            respResult2.sessionKeys.confirmationKey
        )
        assertArrayEquals(
            "Idempotent retry must produce identical ephemeral public keys",
            respResult1.packet.ephemeralPublicKey,
            respResult2.packet.ephemeralPublicKey
        )
    }

    @Test
    fun test_init_retry_reuses_same_request_id_and_ephemeral_key() {
        // Alice creates initial INIT request
        val initResult1 = aliceHandshakeManager.createInitRequest()
        val originalRequestId = initResult1.packet.requestId
        val originalEphemeralKey = initResult1.packet.ephemeralPublicKey

        // Alice manually retries pending request using existing requestId
        val initResult2 = aliceHandshakeManager.createInitRequest(existingRequestId = originalRequestId)

        // Assert that requestId and ephemeral key are strictly reused
        assertEquals(
            "Manual retry of pending INIT must reuse the exact same requestId",
            originalRequestId,
            initResult2.packet.requestId
        )
        assertArrayEquals(
            "Manual retry of pending INIT must reuse the exact same ephemeral key",
            originalEphemeralKey,
            initResult2.packet.ephemeralPublicKey
        )
    }

    @Test
    fun test_init_retry_after_restart_with_persisted_key() {
        // Alice creates initial INIT request
        val initResult1 = aliceHandshakeManager.createInitRequest()
        val originalRequestId = initResult1.packet.requestId
        val ephKeyPair = aliceHandshakeManager.getEphemeralKeyPair(originalRequestId)
        assertNotNull(ephKeyPair)

        // Simulate app death: clear in-memory keys
        aliceHandshakeManager.clearEphemeralKeys(originalRequestId)

        // Restore ephemeral key from persisted bytes (as saved in HandshakeEntity)
        val privBytes = ephKeyPair!!.privateKey.clone()
        val pubBytes = Curve25519Engine.getX25519PublicKeyFromPrivateKey(privBytes)
        val restoredKeyPair = Curve25519Engine.KeyPairBytes(privBytes, pubBytes)

        // Alice retries INIT after restart passing persistedEphemeralKeyPair
        val initResult2 = aliceHandshakeManager.createInitRequest(
            existingRequestId = originalRequestId,
            persistedEphemeralKeyPair = restoredKeyPair
        )

        assertEquals("Must reuse same requestId", originalRequestId, initResult2.packet.requestId)
        assertArrayEquals("Must preserve exact same ephemeral public key after restart", ephKeyPair.publicKey, initResult2.packet.ephemeralPublicKey)
    }

    @Test
    fun test_init_retry_with_missing_key_throws_exception() {
        val originalRequestId = "req_test_restart_missing"
        // Ensure in-memory cache does not have it
        aliceHandshakeManager.clearEphemeralKeys(originalRequestId)

        try {
            // Calling createInitRequest with existingRequestId but no persisted key must fail
            aliceHandshakeManager.createInitRequest(
                existingRequestId = originalRequestId,
                persistedEphemeralKeyPair = null
            )
            org.junit.Assert.fail("Attempting to retry INIT with missing ephemeral key must throw IllegalStateException")
        } catch (e: IllegalStateException) {
            assertTrue("Expected rejection when key is missing for existing requestId", e.message?.contains(originalRequestId) == true)
        }
    }
}
