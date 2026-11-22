package com.wasl.secure

import com.wasl.secure.core.crypto.AesGcmCipher
import com.wasl.secure.core.crypto.Curve25519Engine
import com.wasl.secure.core.crypto.DirectionalKeyDerivation
import com.wasl.secure.core.crypto.Hkdf
import com.wasl.secure.core.crypto.MonotonicNonceManager
import com.wasl.secure.core.crypto.SafetyNumberGenerator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.GeneralSecurityException

class Phase2CryptographicTestSuite {

    @Test
    fun test_1_X25519_Diffie_Hellman_Agreement() {
        // Alice generates ephemeral pair
        val alice = Curve25519Engine.generateX25519KeyPair()
        // Bob generates ephemeral pair
        val bob = Curve25519Engine.generateX25519KeyPair()

        // Alice computes shared secret using Bob's public key
        val secretAlice = Curve25519Engine.computeSharedSecret(alice.privateKey, bob.publicKey)
        // Bob computes shared secret using Alice's public key
        val secretBob = Curve25519Engine.computeSharedSecret(bob.privateKey, alice.publicKey)

        assertEquals(32, secretAlice.size)
        assertEquals(32, secretBob.size)
        assertArrayEquals("Shared secret between Alice and Bob must be identical", secretAlice, secretBob)
    }

    @Test
    fun test_2_Ed25519_Digital_Signatures_and_Tamper_Rejection() {
        val aliceIdentity = Curve25519Engine.generateEd25519KeyPair()
        val handshakePayload = "WASL1:INIT:REQ_9921:PUB_KEY_DATA".toByteArray(Charsets.UTF_8)

        // Alice signs the payload
        val signature = Curve25519Engine.signEd25519(aliceIdentity.privateKey, handshakePayload)
        assertEquals(64, signature.size)

        // Bob verifies the valid signature
        val isValid = Curve25519Engine.verifyEd25519(aliceIdentity.publicKey, handshakePayload, signature)
        assertTrue("Signature verification must pass for untampered data", isValid)

        // Tamper test: Modify 1 byte of the payload
        val tamperedPayload = handshakePayload.clone()
        tamperedPayload[tamperedPayload.size - 1] = (tamperedPayload[tamperedPayload.size - 1] + 1).toByte()
        val isTamperedValid = Curve25519Engine.verifyEd25519(aliceIdentity.publicKey, tamperedPayload, signature)
        assertFalse("Tampered payload must be rejected by Ed25519", isTamperedValid)

        // Tamper test 2: Corrupted signature
        val corruptedSig = signature.clone()
        corruptedSig[0] = (corruptedSig[0] + 1).toByte()
        val isSigCorruptedValid = Curve25519Engine.verifyEd25519(aliceIdentity.publicKey, handshakePayload, corruptedSig)
        assertFalse("Corrupted signature must be rejected", isSigCorruptedValid)
    }

    @Test
    fun test_3_HKDF_Directional_Key_Separation() {
        val sharedSecret = "WASL_TEST_SHARED_SECRET_32_BYTES".toByteArray(Charsets.UTF_8)
        assertEquals(32, sharedSecret.size)

        // Alice derives keys as Initiator
        val aliceKeys = DirectionalKeyDerivation.deriveForInitiator(sharedSecret)
        // Bob derives keys as Responder
        val bobKeys = DirectionalKeyDerivation.deriveForResponder(sharedSecret)

        // Outbound Alice == Inbound Bob
        assertArrayEquals("Alice outbound must match Bob inbound", aliceKeys.outboundKey, bobKeys.inboundKey)
        // Outbound Bob == Inbound Alice
        assertArrayEquals("Bob outbound must match Alice inbound", bobKeys.outboundKey, aliceKeys.inboundKey)
        // Confirmation keys match
        assertArrayEquals("Confirmation keys must match", aliceKeys.confirmationKey, bobKeys.confirmationKey)

        // Reflection attack prevention: Outbound key must NEVER equal Inbound key
        assertFalse(
            "Directional keys must be distinct to prevent reflection attacks",
            aliceKeys.outboundKey.contentEquals(aliceKeys.inboundKey)
        )
    }

    @Test
    fun test_4_AES_256_GCM_AEAD_Encryption_and_Authentication() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = ByteArray(12) { (it * 3).toByte() }
        val originalMessage = "رسالة سرية مشفرة عبر WASL".toByteArray(Charsets.UTF_8)
        val associatedData = "CONV_ID_104:MSG_ID_992:SEQ_1".toByteArray(Charsets.UTF_8)

        // Encrypt with AAD
        val result = AesGcmCipher.encrypt(key, nonce, originalMessage, associatedData)
        assertNotEquals(0, result.ciphertextWithTag.size)

        // Decrypt with correct AAD
        val decrypted = AesGcmCipher.decrypt(key, nonce, result.ciphertextWithTag, associatedData)
        assertArrayEquals("Decrypted bytes must match original plaintext", originalMessage, decrypted)
        assertEquals("رسالة سرية مشفرة عبر WASL", String(decrypted, Charsets.UTF_8))

        // Tamper test 1: Tampered ciphertext
        val tamperedCiphertext = result.ciphertextWithTag.clone()
        tamperedCiphertext[0] = (tamperedCiphertext[0] + 1).toByte()
        try {
            AesGcmCipher.decrypt(key, nonce, tamperedCiphertext, associatedData)
            fail("Decryption must fail with BadTagException on tampered ciphertext")
        } catch (expected: GeneralSecurityException) {
            // Expected
        }

        // Tamper test 2: Tampered AAD (Metadata substitution attack)
        val tamperedAad = "CONV_ID_104:MSG_ID_992:SEQ_2".toByteArray(Charsets.UTF_8) // Changed sequence
        try {
            AesGcmCipher.decrypt(key, nonce, result.ciphertextWithTag, tamperedAad)
            fail("Decryption must fail when AAD metadata is altered")
        } catch (expected: GeneralSecurityException) {
            // Expected
        }
    }

    @Test
    fun test_5_Monotonic_Nonce_Strict_Uniqueness() {
        val nonceManager = MonotonicNonceManager(initialCounter = 1L)
        val generatedNonces = HashSet<String>()
        val count = 10_000

        for (i in 1..count) {
            val (nonce, newCounter) = nonceManager.generateNextNonce()
            assertEquals(12, nonce.size)
            assertEquals((i + 1).toLong(), newCounter)

            val hexString = nonce.joinToString("") { "%02x".format(it) }
            assertTrue("Nonce collision detected at iteration $i!", generatedNonces.add(hexString))
        }

        assertEquals(count, generatedNonces.size)
    }

    @Test
    fun test_6_Safety_Number_Deterministic_Match() {
        val aliceIdentity = ByteArray(32) { (it + 5).toByte() }
        val bobIdentity = ByteArray(32) { (it + 12).toByte() }

        // Alice computes safety number passing (Alice, Bob)
        val safetyNumberAlice = SafetyNumberGenerator.generateSafetyNumber(aliceIdentity, bobIdentity)
        // Bob computes safety number passing (Bob, Alice)
        val safetyNumberBob = SafetyNumberGenerator.generateSafetyNumber(bobIdentity, aliceIdentity)

        assertEquals("Safety number must be 18 chars (3 groups of 4 with separators)", 18, safetyNumberAlice.length)
        assertEquals("Safety number must be identical on both devices", safetyNumberAlice, safetyNumberBob)
        assertTrue(safetyNumberAlice.matches(Regex("\\d{4} - \\d{4} - \\d{4}")))
    }
}
