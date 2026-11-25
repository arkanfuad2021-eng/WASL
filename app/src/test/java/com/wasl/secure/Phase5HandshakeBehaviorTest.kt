package com.wasl.secure

import android.content.Context
import android.util.Base64
import androidx.room.Room
import com.wasl.secure.core.crypto.Curve25519Engine
import com.wasl.secure.core.crypto.IdentityManager
import com.wasl.secure.core.crypto.KeystoreManager
import com.wasl.secure.core.protocol.HandshakeManager
import com.wasl.secure.core.protocol.HandshakePacket
import com.wasl.secure.core.protocol.HandshakePacketCodec
import com.wasl.secure.core.protocol.HandshakeStateMachine
import com.wasl.secure.data.local.WaslDatabase
import com.wasl.secure.data.local.dao.ConversationDao
import com.wasl.secure.data.local.dao.HandshakeDao
import com.wasl.secure.data.local.entity.ConversationEntity
import com.wasl.secure.data.local.entity.HandshakeEntity
import com.wasl.secure.domain.model.Conversation
import com.wasl.secure.domain.model.HandshakeStatus
import com.wasl.secure.telephony.WaslSmsReceiver
import com.wasl.secure.telephony.WaslSmsSender
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.lang.reflect.InvocationTargetException
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import kotlin.coroutines.Continuation
import kotlin.coroutines.intrinsics.suspendCoroutineUninterceptedOrReturn

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class Phase5HandshakeBehaviorTest {

    private lateinit var aliceIdentity: IdentityManager
    private lateinit var bobIdentity: IdentityManager
    private lateinit var eveIdentity: IdentityManager

    private lateinit var aliceManager: HandshakeManager
    private lateinit var bobManager: HandshakeManager

    private lateinit var database: WaslDatabase
    private lateinit var handshakeDao: HandshakeDao
    private lateinit var conversationDao: ConversationDao

    @Before
    fun setUp() {
        aliceIdentity = IdentityManager(TestMockContext(), KeystoreManager("TEST_JVM_FALLBACK"))
        bobIdentity = IdentityManager(TestMockContext(), KeystoreManager("TEST_JVM_FALLBACK"))
        eveIdentity = IdentityManager(TestMockContext(), KeystoreManager("TEST_JVM_FALLBACK"))

        aliceManager = HandshakeManager(aliceIdentity)
        bobManager = HandshakeManager(bobIdentity)

        database = Room.inMemoryDatabaseBuilder(
            RuntimeEnvironment.getApplication(),
            WaslDatabase::class.java
        ).allowMainThreadQueries().build()

        handshakeDao = database.handshakeDao()
        conversationDao = database.conversationDao()
    }

    @After
    fun tearDown() {
        database.close()
    }

    private suspend fun seedConversation(
        id: String,
        phone: String = "+967770000001",
        handshakeStatus: String = "WAITING",
        identityState: String = "PINNED_TOFU",
        currentRequestId: String? = null,
        rejectedAt: Long? = null,
        peerIdentityKeyBase64: String? = null,
        sessionKeyBase64: String? = null,
        pendingConfirmMessageId: String? = null,
        pendingConfirmTotalParts: Int = 0
    ): ConversationEntity {
        val entity = ConversationEntity(
            id = id,
            contactName = "جهة اتصال",
            phoneNumber = phone,
            lastMessage = null,
            lastMessageTimestamp = System.currentTimeMillis(),
            unreadCount = 0,
            handshakeStatus = handshakeStatus,
            defaultSubscriptionId = null,
            rejectedAt = rejectedAt,
            currentRequestId = currentRequestId,
            peerIdentityKeyBase64 = peerIdentityKeyBase64,
            sessionKeyBase64 = sessionKeyBase64,
            inboundSessionKeyBase64 = sessionKeyBase64,
            nextOutboundCounter = 1L,
            identityState = identityState,
            pendingConfirmationKeyBase64 = null,
            pendingConfirmMessageId = pendingConfirmMessageId,
            pendingConfirmTotalParts = pendingConfirmTotalParts,
            pendingConfirmSentIndices = ""
        )
        conversationDao.insertOrUpdate(entity)
        return entity
    }

    private suspend fun seedHandshake(
        requestId: String,
        conversationId: String,
        phone: String = "+967770000001",
        isIncoming: Boolean,
        status: String = "WAITING",
        createdAt: Long = System.currentTimeMillis(),
        expiredAt: Long = 0L,
        rejectedAt: Long? = null,
        ourEphemeralPrivateKey: ByteArray? = null,
        peerEphemeralPublicKey: ByteArray? = null
    ): HandshakeEntity {
        val entity = HandshakeEntity(
            requestId = requestId,
            conversationId = conversationId,
            phoneNumber = phone,
            isIncoming = isIncoming,
            status = status,
            createdAt = createdAt,
            expiredAt = expiredAt,
            rejectedAt = rejectedAt,
            ephemeralPrivateKeyBase64 = ourEphemeralPrivateKey?.let { Base64.encodeToString(it, Base64.NO_WRAP) },
            peerEphemeralPublicKeyBase64 = peerEphemeralPublicKey?.let { Base64.encodeToString(it, Base64.NO_WRAP) }
        )
        handshakeDao.insertOrUpdate(entity)
        return entity
    }

    private fun restoreKeyPairFromDb(entity: HandshakeEntity): Curve25519Engine.KeyPairBytes {
        val priv = Base64.decode(requireNotNull(entity.ephemeralPrivateKeyBase64), Base64.NO_WRAP)
        val pub = Curve25519Engine.getX25519PublicKeyFromPrivateKey(priv)
        return Curve25519Engine.KeyPairBytes(priv, pub)
    }

    private fun createAppForReceiverTest(handshakeManager: HandshakeManager): WaslApplication {
        val app = WaslApplication()
        WaslApplication::class.java.getDeclaredField("database").apply {
            isAccessible = true
            set(app, database)
        }
        WaslApplication::class.java.getDeclaredField("handshakeManager").apply {
            isAccessible = true
            set(app, handshakeManager)
        }
        return app
    }

    private suspend fun invokeReceiverHandshake(
        receiver: WaslSmsReceiver,
        app: WaslApplication,
        smsBody: String,
        fromPhone: String
    ) {
        val method = WaslSmsReceiver::class.java.getDeclaredMethod(
            "processIncomingHandshake",
            Context::class.java,
            WaslApplication::class.java,
            String::class.java,
            String::class.java,
            Continuation::class.java
        ).apply { isAccessible = true }

        suspendCoroutineUninterceptedOrReturn<Unit> { cont ->
            try {
                method.invoke(receiver, RuntimeEnvironment.getApplication(), app, smsBody, fromPhone, cont)
            } catch (e: InvocationTargetException) {
                throw e.targetException
            }
        }
    }

    // =========================================================================
    // المحور 1: منع استبدال المفتاح المؤقت المحفوظ بمفتاح مختلف
    // =========================================================================

    @Test
    fun test_peer_ephemeral_key_pinning_rejects_replacement_across_cache_and_recreated_manager() = runBlocking {
        val init1 = aliceManager.createInitRequest().packet
        val reqId = init1.requestId
        val convId = "conv_pin_01"

        // Responder verifies incoming INIT and persists peer ephemeral key in HandshakeDao as in production
        assertTrue(bobManager.verifyIncomingInit(init1))
        seedConversation(id = convId, handshakeStatus = "WAITING", identityState = "UNPINNED", currentRequestId = reqId)
        seedHandshake(
            requestId = reqId,
            conversationId = convId,
            isIncoming = true,
            status = "WAITING",
            peerEphemeralPublicKey = init1.ephemeralPublicKey
        )

        // Second valid INIT signed by Alice for the same requestId but with a different ephemeral key
        val ekPair2 = Curve25519Engine.generateX25519KeyPair()
        val init2 = HandshakeManager(aliceIdentity).createInitRequest(
            existingRequestId = reqId,
            persistedEphemeralKeyPair = ekPair2
        ).packet

        // 1. In-memory cache on active Bob HandshakeManager rejects key substitution
        assertFalse(
            "verifyIncomingInit must reject different ephemeral key for cached requestId",
            bobManager.verifyIncomingInit(init2)
        )
        try {
            bobManager.registerPendingPeerEphemeralKey(reqId, ekPair2.publicKey)
            fail("registerPendingPeerEphemeralKey must throw SecurityException on conflicting key")
        } catch (_: SecurityException) {
            // Expected
        }
        assertArrayEquals(init1.ephemeralPublicKey, bobManager.getPendingPeerEphemeralKey(reqId))

        // 2. After app/process restart: new HandshakeManager restores pinned key from HandshakeDao
        val restartedBobManager = HandshakeManager(bobIdentity)
        val storedReq = handshakeDao.getByRequestId(reqId)!!
        val persistedPeerEk = Base64.decode(storedReq.peerEphemeralPublicKeyBase64, Base64.NO_WRAP)

        assertFalse(
            "Recreated HandshakeManager must reject substituted key against DB-persisted peer ephemeral key",
            restartedBobManager.verifyIncomingInit(init2, expectedPeerEphemeralKey = persistedPeerEk)
        )
        assertTrue(
            "Recreated HandshakeManager must accept identical INIT matching DB-persisted peer ephemeral key",
            restartedBobManager.verifyIncomingInit(init1, expectedPeerEphemeralKey = persistedPeerEk)
        )
    }

    @Test
    fun test_acceptInitRequest_rejects_persisted_or_incoming_ephemeral_conflict() = runBlocking {
        val init1 = aliceManager.createInitRequest().packet
        val reqId = init1.requestId
        val convId = "conv_pin_02"

        assertTrue(bobManager.verifyIncomingInit(init1))
        val firstResponse = bobManager.acceptInitRequest(reqId, init1.identityPublicKey)
        val bobEphPair = bobManager.getEphemeralKeyPair(reqId)!!

        seedConversation(id = convId, handshakeStatus = "WAITING", identityState = "PINNED_TOFU", currentRequestId = reqId)
        seedHandshake(
            requestId = reqId,
            conversationId = convId,
            isIncoming = true,
            status = "ACCEPTED",
            ourEphemeralPrivateKey = bobEphPair.privateKey,
            peerEphemeralPublicKey = init1.ephemeralPublicKey
        )

        val conflictingEk = Curve25519Engine.generateX25519KeyPair().publicKey

        // Conflict against in-memory pinned peer ephemeral key
        try {
            bobManager.acceptInitRequest(
                requestId = reqId,
                peerIdentityKey = init1.identityPublicKey,
                persistedPeerEphemeralKey = conflictingEk
            )
            fail("acceptInitRequest must throw SecurityException when persistedPeerEphemeralKey conflicts with cache")
        } catch (_: SecurityException) {
            // Expected
        }

        // Recreate HandshakeManager and restore keys from HandshakeDao as in production
        val restartedBobManager = HandshakeManager(bobIdentity)
        val storedReq = handshakeDao.getByRequestId(reqId)!!
        val persistedPeerEk = Base64.decode(storedReq.peerEphemeralPublicKeyBase64, Base64.NO_WRAP)
        val restoredOurPair = restoreKeyPairFromDb(storedReq)

        try {
            restartedBobManager.acceptInitRequest(
                requestId = reqId,
                peerIdentityKey = init1.identityPublicKey,
                persistedPeerEphemeralKey = persistedPeerEk,
                persistedOurEphemeralKeyPair = restoredOurPair,
                incomingPeerEphemeralKey = conflictingEk
            )
            fail("acceptInitRequest must throw SecurityException when incomingPeerEphemeralKey conflicts with DB key")
        } catch (_: SecurityException) {
            // Expected
        }

        // Consistent DB-restored keys succeed identically
        val retryResponse = restartedBobManager.acceptInitRequest(
            requestId = reqId,
            peerIdentityKey = init1.identityPublicKey,
            persistedPeerEphemeralKey = persistedPeerEk,
            persistedOurEphemeralKeyPair = restoredOurPair,
            incomingPeerEphemeralKey = init1.ephemeralPublicKey
        )
        assertArrayEquals(firstResponse.sessionKeys.outboundKey, retryResponse.sessionKeys.outboundKey)
    }

    // =========================================================================
    // المحور 2: بقاء طلبات المصافحة المعلقة دون انتهاء تلقائي بعد 24 ساعة
    // =========================================================================

    @Test
    fun test_waiting_request_disallows_expired_transition_and_stays_active_beyond_24_hours() = runBlocking {
        // 1. State machine must block WAITING -> EXPIRED
        assertFalse(HandshakeStateMachine.canTransition(HandshakeStatus.WAITING, HandshakeStatus.EXPIRED))

        // Sequential initiator path through PENDING_CONFIRM_SEND -> READY & valid WAITING transitions
        assertTrue(HandshakeStateMachine.canTransition(HandshakeStatus.WAITING, HandshakeStatus.PENDING_CONFIRM_SEND))
        assertTrue(HandshakeStateMachine.canTransition(HandshakeStatus.PENDING_CONFIRM_SEND, HandshakeStatus.READY))
        assertTrue(HandshakeStateMachine.canTransition(HandshakeStatus.WAITING, HandshakeStatus.REJECTED))
        assertTrue(HandshakeStateMachine.canTransition(HandshakeStatus.WAITING, HandshakeStatus.KEY_CHANGED_ALERT))
        assertTrue(HandshakeStateMachine.canTransition(HandshakeStatus.WAITING, HandshakeStatus.FAILED))
        assertTrue(HandshakeStateMachine.canTransition(HandshakeStatus.WAITING, HandshakeStatus.RESPONSE_RECEIVED))
        assertTrue(HandshakeStateMachine.canTransition(HandshakeStatus.WAITING, HandshakeStatus.ESTABLISHING))
        assertTrue(HandshakeStateMachine.canTransition(HandshakeStatus.WAITING, HandshakeStatus.READY))

        val now = System.currentTimeMillis()
        val olderThan24h = now - 48L * 60L * 60L * 1000L

        // Initiator cannot jump straight from WAITING to READY via markReadyIfPendingConfirm
        seedConversation(id = "conv_out_48h", phone = "+967770000021", handshakeStatus = "WAITING", currentRequestId = "W48OUT")
        assertEquals(0, conversationDao.markReadyIfPendingConfirm("conv_out_48h", "ready", now))

        // 2. Requests created 48 hours ago with expiredAt = 0L stay WAITING and queryable in HandshakeDao
        seedHandshake(
            requestId = "W48OUT",
            conversationId = "conv_out_48h",
            phone = "+967770000021",
            isIncoming = false,
            status = "WAITING",
            createdAt = olderThan24h,
            expiredAt = 0L
        )
        seedHandshake(
            requestId = "W48IN",
            conversationId = "conv_in_48h",
            phone = "+967770000022",
            isIncoming = true,
            status = "WAITING",
            createdAt = olderThan24h,
            expiredAt = 0L
        )

        assertEquals("WAITING", handshakeDao.getByRequestId("W48OUT")?.status)
        assertEquals("W48OUT", handshakeDao.getActiveWaitingRequest("+967770000021")?.requestId)
        assertEquals("W48OUT", handshakeDao.getActiveOutgoingWaitingRequest("conv_out_48h")?.requestId)
        assertEquals("W48IN", handshakeDao.getActiveIncomingWaitingRequest("conv_in_48h")?.requestId)
    }

    @Test
    fun test_pending_request_older_than_24_hours_resends_via_createInitRequest_and_preserves_signature_checks() = runBlocking {
        val init1 = aliceManager.createInitRequest().packet
        val reqId = init1.requestId
        val convId = "conv_resend_48h"
        val olderThan24h = System.currentTimeMillis() - 48L * 60L * 60L * 1000L

        seedConversation(id = convId, handshakeStatus = "WAITING", currentRequestId = reqId)
        seedHandshake(
            requestId = reqId,
            conversationId = convId,
            isIncoming = false,
            status = "WAITING",
            createdAt = olderThan24h,
            expiredAt = 0L,
            ourEphemeralPrivateKey = aliceManager.getEphemeralKeyPair(reqId)!!.privateKey
        )

        // Recreate Initiator HandshakeManager after >24h and restore persisted key pair from DB
        val restartedAliceManager = HandshakeManager(aliceIdentity)
        val restoredPair = restoreKeyPairFromDb(handshakeDao.getByRequestId(reqId)!!)

        val resentInit = restartedAliceManager.createInitRequest(
            existingRequestId = reqId,
            persistedEphemeralKeyPair = restoredPair
        )
        assertEquals(reqId, resentInit.packet.requestId)
        assertArrayEquals(init1.ephemeralPublicKey, resentInit.packet.ephemeralPublicKey)

        // Ensure timestamp signature verification remains enforced
        val tamperedTimestampInit = resentInit.packet.copy(timestamp = resentInit.packet.timestamp + 1L)
        assertFalse(
            "Tampering with INIT timestamp without re-signing must still fail verification",
            bobManager.verifyIncomingInit(tamperedTimestampInit)
        )

        // Authentic resent INIT completes full handshake cleanly
        assertTrue(bobManager.verifyIncomingInit(resentInit.packet))
        val respResult = bobManager.acceptInitRequest(reqId, resentInit.packet.identityPublicKey)
        val confirmResult = restartedAliceManager.processResponse(respResult.packet)
        assertTrue(bobManager.verifyConfirm(confirmResult.packet, respResult.sessionKeys.confirmationKey))
        assertArrayEquals(confirmResult.sessionKeys.outboundKey, respResult.sessionKeys.inboundKey)
    }

    // =========================================================================
    // المحور 3: تطبيق مهلة الثلاث دقائق على المبادر فقط بعد الرفض الموثوق
    // =========================================================================

    @Test
    fun test_authentic_reject_applies_3_minute_cooldown_to_initiator_while_untrusted_reject_fails_verification() = runBlocking {
        val receiver = WaslSmsReceiver()
        val testApp = createAppForReceiverTest(aliceManager)
        val bobPubKeyB64 = Base64.encodeToString(bobIdentity.getPublicIdentityKey(), Base64.NO_WRAP)

        // 1. UNPINNED conversation: even signed REJECT must be ignored without cooldown
        val unpinnedPhone = "+967770000051"
        val unpinnedConvId = "conv_cd_unpinned"
        val reqUnpinned = "WREJ05U"
        seedConversation(
            id = unpinnedConvId,
            phone = unpinnedPhone,
            handshakeStatus = "WAITING",
            identityState = "UNPINNED",
            currentRequestId = reqUnpinned,
            peerIdentityKeyBase64 = null
        )
        seedHandshake(
            requestId = reqUnpinned,
            conversationId = unpinnedConvId,
            phone = unpinnedPhone,
            isIncoming = false,
            status = "WAITING"
        )
        val (_, bobRejectUnpinnedSms) = bobManager.createRejectPacket(reqUnpinned)
        invokeReceiverHandshake(receiver, testApp, bobRejectUnpinnedSms, unpinnedPhone)

        val unpinnedConvAfter = conversationDao.getConversationById(unpinnedConvId)!!
        assertEquals("WAITING", unpinnedConvAfter.handshakeStatus)
        assertNull(unpinnedConvAfter.rejectedAt)
        assertNull(handshakeDao.getByRequestId(reqUnpinned)!!.rejectedAt)

        // 2. PINNED_TOFU conversation: untrusted (forged/stale) REJECT must NOT trigger cooldown
        val pinnedPhone = "+967770000052"
        val pinnedConvId = "conv_cd_pinned"
        val reqPinned = "WREJ05P"
        seedConversation(
            id = pinnedConvId,
            phone = pinnedPhone,
            handshakeStatus = "WAITING",
            identityState = "PINNED_TOFU",
            currentRequestId = reqPinned,
            peerIdentityKeyBase64 = bobPubKeyB64
        )
        seedHandshake(
            requestId = reqPinned,
            conversationId = pinnedConvId,
            phone = pinnedPhone,
            isIncoming = false,
            status = "WAITING"
        )

        val (_, forgedRejectSms) = HandshakeManager(eveIdentity).createRejectPacket(reqPinned)
        invokeReceiverHandshake(receiver, testApp, forgedRejectSms, pinnedPhone)

        var convAfter = conversationDao.getConversationById(pinnedConvId)!!
        assertEquals("WAITING", convAfter.handshakeStatus)
        assertNull(convAfter.rejectedAt)
        assertEquals("WAITING", handshakeDao.getByRequestId(reqPinned)!!.status)
        assertNull(handshakeDao.getByRequestId(reqPinned)!!.rejectedAt)

        val bobPubKey = bobIdentity.getPublicIdentityKey()
        val staleTimestamp = System.currentTimeMillis() - 11L * 60L * 1000L
        val domainBytes = "WASL1:REJ:v1:".toByteArray(Charsets.UTF_8)
        val reqBytes = reqPinned.toByteArray(Charsets.UTF_8)
        val staleSignData = ByteBuffer.allocate(domainBytes.size + 2 + reqBytes.size + 32 + 8)
            .put(domainBytes)
            .putShort(reqBytes.size.toShort())
            .put(reqBytes)
            .put(bobPubKey)
            .putLong(staleTimestamp)
            .array()
        val staleRejectPacket = HandshakePacket.Reject(
            requestId = reqPinned,
            timestamp = staleTimestamp,
            identityPublicKey = bobPubKey,
            signature = bobIdentity.sign(staleSignData)
        )
        assertTrue(
            "Stale REJECT packet must carry a valid signature for its old timestamp",
            aliceIdentity.verifyPeerSignature(bobPubKey, staleSignData, staleRejectPacket.signature)
        )
        val staleRejectSms = HandshakePacketCodec.encode(staleRejectPacket)
        invokeReceiverHandshake(receiver, testApp, staleRejectSms, pinnedPhone)

        convAfter = conversationDao.getConversationById(pinnedConvId)!!
        assertEquals("WAITING", convAfter.handshakeStatus)
        assertNull(convAfter.rejectedAt)

        // 3. Authentic REJECT from pinned Bob triggers WaslSmsReceiver to persist REJECTED + rejectedAt
        val (_, bobRejectSms) = bobManager.createRejectPacket(reqPinned)
        invokeReceiverHandshake(receiver, testApp, bobRejectSms, pinnedPhone)

        val persistedConv = conversationDao.getConversationById(pinnedConvId)!!
        val persistedReq = handshakeDao.getByRequestId(reqPinned)!!
        val savedRejectedAt = requireNotNull(persistedConv.rejectedAt) {
            "Authentic REJECT must persist rejectedAt in DB"
        }

        assertEquals("REJECTED", persistedConv.handshakeStatus)
        assertEquals("REJECTED", persistedReq.status)
        assertEquals(savedRejectedAt, persistedReq.rejectedAt)

        // Initiator is blocked by the DB-persisted rejectedAt
        assertTrue(HandshakeStateMachine.checkRejectionCooldown(savedRejectedAt) > 0L)
        try {
            aliceManager.createInitRequest(rejectedAt = savedRejectedAt)
            fail("Initiator must be blocked during 3-minute cooldown persisted by receiver")
        } catch (_: IllegalStateException) {
            // Expected
        }

        // After 3 minutes elapse relative to savedRejectedAt, cooldown lifts and allows new INIT
        val afterCooldownTime = savedRejectedAt + HandshakeStateMachine.REJECTION_COOLDOWN_MS + 1_000L
        assertEquals(0L, HandshakeStateMachine.checkRejectionCooldown(savedRejectedAt, afterCooldownTime))

        val expiredSavedRejectedAt = savedRejectedAt - (HandshakeStateMachine.REJECTION_COOLDOWN_MS + 1_000L)
        val nextInit = aliceManager.createInitRequest(rejectedAt = expiredSavedRejectedAt)
        assertNotEquals(reqPinned, nextInit.packet.requestId)
    }

    @Test
    fun test_responder_after_sending_reject_keeps_null_rejectedAt_and_can_initiate_immediately() = runBlocking {
        val reqId = "WREJ06"
        val convId = "conv_resp_rej"
        val conv = seedConversation(
            id = convId,
            handshakeStatus = "WAITING",
            identityState = "PINNED_TOFU",
            currentRequestId = reqId
        )
        seedHandshake(
            requestId = reqId,
            conversationId = convId,
            isIncoming = true,
            status = "WAITING"
        )

        // Responder sends authentic signed REJECT and records rejectedAt = null locally (matching MainActivity)
        val (rejectPacket, _) = bobManager.createRejectPacket(reqId)
        assertTrue(aliceManager.verifyReject(rejectPacket, bobIdentity.getPublicIdentityKey()))

        handshakeDao.updateStatusAndRejectedAt(reqId, "REJECTED", null)
        conversationDao.update(conv.copy(handshakeStatus = "REJECTED", rejectedAt = null))

        val reloadedConv = conversationDao.getConversationById(convId)!!
        val reloadedReq = handshakeDao.getByRequestId(reqId)!!

        assertEquals("REJECTED", reloadedConv.handshakeStatus)
        assertNull(reloadedConv.rejectedAt)
        assertEquals("REJECTED", reloadedReq.status)
        assertNull(reloadedReq.rejectedAt)

        assertEquals(0L, HandshakeStateMachine.checkRejectionCooldown(reloadedConv.rejectedAt))
        val domainConv = Conversation(
            id = convId,
            contactName = reloadedConv.contactName,
            phoneNumber = reloadedConv.phoneNumber,
            lastMessage = null,
            lastMessageTimestamp = reloadedConv.lastMessageTimestamp,
            handshakeStatus = HandshakeStatus.REJECTED,
            rejectedAt = reloadedConv.rejectedAt,
            currentRequestId = reqId
        )
        assertEquals(0L, domainConv.remainingCooldownSeconds())

        val immediateInit = bobManager.createInitRequest(rejectedAt = reloadedConv.rejectedAt)
        assertNotEquals(reqId, immediateInit.packet.requestId)
    }

    // =========================================================================
    // المحور 4: رفض الردود المتأخرة للطلبات المرفوضة أو المستبدلة
    // =========================================================================

    @Test
    fun test_rejected_request_blocks_late_response_by_db_status_and_state_guards_not_just_missing_key() = runBlocking {
        val init1 = aliceManager.createInitRequest().packet
        val req1 = init1.requestId
        val convId = "conv_late_rej"

        val conv = seedConversation(
            id = convId,
            handshakeStatus = "WAITING",
            identityState = "PINNED_TOFU",
            currentRequestId = req1,
            peerIdentityKeyBase64 = Base64.encodeToString(bobIdentity.getPublicIdentityKey(), Base64.NO_WRAP)
        )
        seedHandshake(
            requestId = req1,
            conversationId = convId,
            isIncoming = false,
            status = "WAITING",
            ourEphemeralPrivateKey = aliceManager.getEphemeralKeyPair(req1)!!.privateKey
        )

        // Responder generates RESPONSE before rejection reaches or completes (delayed in SMS transit)
        assertTrue(bobManager.verifyIncomingInit(init1))
        val lateResp = bobManager.acceptInitRequest(req1, init1.identityPublicKey).packet

        // Request req1 transitions to REJECTED in DB, intentionally leaving ephemeralPrivateKeyBase64 intact in DB
        val rejectedAt = System.currentTimeMillis()
        handshakeDao.updateStatusAndRejectedAt(req1, "REJECTED", rejectedAt)
        conversationDao.update(conv.copy(handshakeStatus = "REJECTED", rejectedAt = rejectedAt))

        // Layer 1: Rejection enforced by DB status/state guards even though persisted key still exists in DB row
        assertNotNull(handshakeDao.getByRequestId(req1)?.ephemeralPrivateKeyBase64)
        assertNull(
            "Rejected request must NOT be returned as active outgoing WAITING request",
            handshakeDao.getActiveOutgoingWaitingRequest(convId)
        )
        assertEquals("REJECTED", handshakeDao.getByRequestId(req1)?.status)
        assertEquals("REJECTED", conversationDao.getConversationById(convId)?.handshakeStatus)
        assertFalse(HandshakeStateMachine.canTransition(HandshakeStatus.REJECTED, HandshakeStatus.PENDING_CONFIRM_SEND))
        assertEquals(0, conversationDao.initPendingConfirmAttempt(convId, "cm_late", 1))
        assertEquals(0, conversationDao.markReadyIfPendingConfirm(convId, "ready", System.currentTimeMillis()))
        assertNull(conversationDao.recordConfirmSentPartAtomic(convId, "cm_late", 1, 1, true, System.currentTimeMillis()))

        // Layer 2: Separate HandshakeManager check once keys for rejected request are cleared/not loaded
        aliceManager.clearEphemeralKeys(req1)
        try {
            aliceManager.processResponse(lateResp)
            fail("processResponse must throw IllegalStateException when no active ephemeral key is loaded for req1")
        } catch (_: IllegalStateException) {
            // Expected
        }
    }

    @Test
    fun test_superseded_request_blocks_late_response_by_currentRequestId_and_cryptographic_binding() = runBlocking {
        // 1. Old request req1 -> Responder generates delayed resp1
        val init1 = aliceManager.createInitRequest().packet
        val req1 = init1.requestId
        val convId = "conv_late_superseded"
        assertTrue(bobManager.verifyIncomingInit(init1))
        val lateResp1 = bobManager.acceptInitRequest(req1, init1.identityPublicKey).packet

        // 2. req1 is superseded by a new request req2 with a new ephemeral key ekA2
        aliceManager.clearEphemeralKeys(req1)
        val init2 = aliceManager.createInitRequest().packet
        val req2 = init2.requestId
        assertNotEquals(req1, req2)

        seedConversation(
            id = convId,
            handshakeStatus = "WAITING",
            identityState = "PINNED_TOFU",
            currentRequestId = req2,
            peerIdentityKeyBase64 = Base64.encodeToString(bobIdentity.getPublicIdentityKey(), Base64.NO_WRAP)
        )
        seedHandshake(requestId = req1, conversationId = convId, isIncoming = false, status = "REJECTED")
        seedHandshake(
            requestId = req2,
            conversationId = convId,
            isIncoming = false,
            status = "WAITING",
            ourEphemeralPrivateKey = aliceManager.getEphemeralKeyPair(req2)!!.privateKey
        )

        // Layer 1: DB currentRequestId & active WAITING guards drop resp1
        val currentConv = conversationDao.getConversationById(convId)!!
        assertEquals(req2, currentConv.currentRequestId)
        assertNotEquals(lateResp1.requestId, currentConv.currentRequestId)
        assertEquals(req2, handshakeDao.getActiveOutgoingWaitingRequest(convId)?.requestId)

        // Layer 2a: HandshakeManager rejects unmodified lateResp1 for inactive req1
        try {
            aliceManager.processResponse(lateResp1)
            fail("processResponse must throw IllegalStateException for superseded req1")
        } catch (_: IllegalStateException) {
            // Expected
        }

        // Layer 2b: Even with active non-null ekA2 present for req2, rewriting requestId to req2 fails signature check
        try {
            aliceManager.processResponse(lateResp1.copy(requestId = req2))
            fail("processResponse must throw GeneralSecurityException because signature binds RESP to req1 and ekA1")
        } catch (_: GeneralSecurityException) {
            // Expected cryptographic rejection
        }

        // Authentic resp2 for req2 completes without interference
        assertTrue(bobManager.verifyIncomingInit(init2))
        val validResp2 = bobManager.acceptInitRequest(req2, init2.identityPublicKey)
        val confirmResult2 = aliceManager.processResponse(validResp2.packet)
        assertTrue(bobManager.verifyConfirm(confirmResult2.packet, validResp2.sessionKeys.confirmationKey))
        assertArrayEquals(confirmResult2.sessionKeys.outboundKey, validResp2.sessionKeys.inboundKey)
    }

    // =========================================================================
    // المحور 5: بقاء KEY_CHANGED_ALERT حاجزاً أمنياً لا يمكن تجاوزه تلقائياً
    // =========================================================================

    @Test
    fun test_key_changed_alert_blocks_state_machine_and_all_dao_ready_transitions() = runBlocking {
        // 1. State machine must forbid every automatic transition out of KEY_CHANGED_ALERT
        for (target in HandshakeStatus.entries) {
            assertFalse(
                "KEY_CHANGED_ALERT must forbid automatic transition to $target",
                HandshakeStateMachine.canTransition(HandshakeStatus.KEY_CHANGED_ALERT, target)
            )
        }

        val now = System.currentTimeMillis()

        // 2. DB SQL guards - Case A: identityState = KEY_CHANGED_ALERT while handshakeStatus = PENDING_CONFIRM_SEND
        val convIdA = "conv_kca_identity"
        seedConversation(
            id = convIdA,
            phone = "+967770000091",
            handshakeStatus = "PENDING_CONFIRM_SEND",
            identityState = "KEY_CHANGED_ALERT",
            currentRequestId = "WKCA1",
            pendingConfirmMessageId = "cm-alert-a",
            pendingConfirmTotalParts = 1
        )
        assertEquals(0, conversationDao.initPendingConfirmAttempt(convIdA, "cm-new-a", 1))
        assertEquals(0, conversationDao.markReadyIfPendingConfirm(convIdA, "ready", now))
        assertNull(conversationDao.recordConfirmSentPartAtomic(convIdA, "cm-alert-a", 1, 1, true, now))
        assertEquals(0, conversationDao.markResponderReady(convIdA, "ready", now))

        val afterA = conversationDao.getConversationById(convIdA)!!
        assertNotEquals("READY", afterA.handshakeStatus)
        assertEquals("KEY_CHANGED_ALERT", afterA.identityState)

        // 3. DB SQL guards - Case B: handshakeStatus = KEY_CHANGED_ALERT while identityState = PINNED_TOFU
        val convIdB = "conv_kca_status"
        seedConversation(
            id = convIdB,
            phone = "+967770000092",
            handshakeStatus = "KEY_CHANGED_ALERT",
            identityState = "PINNED_TOFU",
            currentRequestId = "WKCA2",
            pendingConfirmMessageId = "cm-alert-b",
            pendingConfirmTotalParts = 1
        )
        assertEquals(0, conversationDao.initPendingConfirmAttempt(convIdB, "cm-new-b", 1))
        assertEquals(0, conversationDao.markReadyIfPendingConfirm(convIdB, "ready", now))
        assertNull(conversationDao.recordConfirmSentPartAtomic(convIdB, "cm-alert-b", 1, 1, true, now))
        assertEquals(0, conversationDao.markResponderReady(convIdB, "ready", now))

        val afterB = conversationDao.getConversationById(convIdB)!!
        assertEquals("KEY_CHANGED_ALERT", afterB.handshakeStatus)
    }

    @Test
    fun test_waslSmsSender_blocks_message_sending_when_in_key_changed_alert() = runBlocking {
        val dummySessionKeyB64 = Base64.encodeToString(ByteArray(32) { 0x2A.toByte() }, Base64.NO_WRAP)

        val convIdIdentityLock = "conv_send_block_1"
        seedConversation(
            id = convIdIdentityLock,
            phone = "+967770000101",
            handshakeStatus = "READY",
            identityState = "KEY_CHANGED_ALERT",
            sessionKeyBase64 = dummySessionKeyB64
        )

        val convIdStatusLock = "conv_send_block_2"
        seedConversation(
            id = convIdStatusLock,
            phone = "+967770000102",
            handshakeStatus = "KEY_CHANGED_ALERT",
            identityState = "PINNED_TOFU",
            sessionKeyBase64 = dummySessionKeyB64
        )

        val smsSender = WaslSmsSender(RuntimeEnvironment.getApplication(), database)

        val res1 = smsSender.sendEncryptedMessage(convIdIdentityLock, "رسالة محظورة", "+967770000101", null)
        assertTrue("Sending must fail when identityState is KEY_CHANGED_ALERT", res1.isFailure)
        assertTrue(res1.exceptionOrNull() is IllegalStateException)
        assertEquals(1L, conversationDao.getNextOutboundCounter(convIdIdentityLock))

        val res2 = smsSender.sendEncryptedMessage(convIdStatusLock, "رسالة محظورة", "+967770000102", null)
        assertTrue("Sending must fail when handshakeStatus is KEY_CHANGED_ALERT", res2.isFailure)
        assertTrue(res2.exceptionOrNull() is IllegalStateException)
        assertEquals(1L, conversationDao.getNextOutboundCounter(convIdStatusLock))
    }
}
