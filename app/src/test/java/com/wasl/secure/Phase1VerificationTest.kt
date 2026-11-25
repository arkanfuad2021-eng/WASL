package com.wasl.secure

import com.wasl.secure.domain.model.Conversation
import com.wasl.secure.domain.model.HandshakeStatus
import com.wasl.secure.telephony.MessageChunkManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class Phase1VerificationTest {

    @Test
    fun test_3_minute_cooldown_calculation() {
        val now = System.currentTimeMillis()
        
        // Scenario 1: Rejected 1 minute ago -> Should have ~120 seconds left
        val rejected1MinAgo = Conversation(
            id = "c1",
            contactName = "سالم",
            phoneNumber = "+966500000000",
            lastMessage = null,
            lastMessageTimestamp = now - 60_000,
            handshakeStatus = HandshakeStatus.REJECTED,
            rejectedAt = now - 60_000
        )
        val remaining1 = rejected1MinAgo.remainingCooldownSeconds(now)
        assertEquals(120L, remaining1)

        // Scenario 2: Rejected 3.5 minutes ago -> Cooldown finished, should be 0
        val rejectedPastCooldown = Conversation(
            id = "c2",
            contactName = "سالم",
            phoneNumber = "+966500000000",
            lastMessage = null,
            lastMessageTimestamp = now - 210_000,
            handshakeStatus = HandshakeStatus.REJECTED,
            rejectedAt = now - 210_000
        )
        val remaining2 = rejectedPastCooldown.remainingCooldownSeconds(now)
        assertEquals(0L, remaining2)

        // Scenario 3: Non-rejected conversation -> Should be 0
        val readyConv = Conversation(
            id = "c3",
            contactName = "محمد",
            phoneNumber = "+966500000000",
            lastMessage = "مرحبا",
            lastMessageTimestamp = now,
            handshakeStatus = HandshakeStatus.READY,
            rejectedAt = null
        )
        assertEquals(0L, readyConv.remainingCooldownSeconds(now))
    }

    @Test
    fun test_post_encryption_sms_parts_estimation() {
        // Short text (e.g. "مرحبا يا محمد") -> 23 UTF-8 bytes + 16 GCM tag = 39 <= 63 -> Fits in 1 SMS
        val shortText = "مرحبا يا محمد"
        val parts1 = MessageChunkManager.estimateEncryptedSmsParts(shortText)
        assertEquals(1, parts1)

        // Long text (500 Arabic chars = 1000 UTF-8 bytes + 16 GCM tag = 1016 bytes -> ceil(1016/63) = 17 SMS parts)
        val longText = "أ".repeat(500)
        val parts2 = MessageChunkManager.estimateEncryptedSmsParts(longText)
        assertEquals(17, parts2)
        assertTrue("Estimated parts should exceed 10-part high-cost warning threshold", parts2 > 10)
    }
}
