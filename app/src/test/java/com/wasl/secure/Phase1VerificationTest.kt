package com.wasl.secure

import com.wasl.secure.domain.model.Conversation
import com.wasl.secure.domain.model.HandshakeStatus
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
        // Short text (e.g. "مرحبا") -> Should fit in 1 SMS
        val shortText = "مرحبا يا محمد"
        val parts1 = calculateEstimatedParts(shortText)
        assertEquals(1, parts1)

        // Long text (e.g. 500 characters) -> Must accurately exceed 1 SMS
        val longText = "أ".repeat(500)
        val parts2 = calculateEstimatedParts(longText)
        assertTrue("Estimated parts should be greater than 3 for 500 chars", parts2 >= 4)
    }

    private fun calculateEstimatedParts(plainText: String): Int {
        if (plainText.isEmpty()) return 1
        val plainBytes = plainText.toByteArray(Charsets.UTF_8).size
        val totalCipherBytes = plainBytes + 16 + 12 + 26
        val base64Length = ((totalCipherBytes + 2) / 3) * 4
        val parts = (base64Length + 129) / 130
        return if (parts < 1) 1 else parts
    }
}
