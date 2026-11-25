package com.wasl.secure

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.ContactsContract
import android.telephony.SmsManager
import android.util.Base64
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import androidx.room.withTransaction
import com.wasl.secure.core.theme.LocalWaslColors
import com.wasl.secure.core.theme.ThmanyahBlack
import com.wasl.secure.core.theme.WaslTheme
import com.wasl.secure.core.crypto.Curve25519Engine
import com.wasl.secure.core.util.YemenPhoneUtils
import com.wasl.secure.data.local.entity.ConversationEntity
import com.wasl.secure.data.local.entity.HandshakeEntity
import com.wasl.secure.domain.model.Conversation
import com.wasl.secure.domain.model.HandshakeStatus
import com.wasl.secure.domain.model.Message
import com.wasl.secure.domain.model.MessageDirection
import com.wasl.secure.domain.model.MessageStatus
import com.wasl.secure.domain.model.SimInfo
import com.wasl.secure.domain.usecase.RetrySendMessageUseCase
import com.wasl.secure.domain.usecase.SendMessageUseCase
import com.wasl.secure.presentation.chats.ChatsListScreen
import com.wasl.secure.presentation.chats.components.NewChatDialog
import com.wasl.secure.presentation.conversation.ConversationScreen
import com.wasl.secure.presentation.navigation.Screen
import com.wasl.secure.telephony.NotificationHelper
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID

class MainActivity : ComponentActivity() {

    private val notificationConversationId = mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        notificationConversationId.value = intent?.getStringExtra("conversationId")

        setContent {
            var isDarkTheme by remember { mutableStateOf(true) }

            WaslTheme(darkTheme = isDarkTheme) {
                WaslAppNavigation(
                    isDarkTheme = isDarkTheme,
                    onToggleTheme = { isDarkTheme = !isDarkTheme },
                    pendingNotificationConvId = notificationConversationId.value,
                    onNotificationConvHandled = { notificationConversationId.value = null }
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        notificationConversationId.value = intent.getStringExtra("conversationId")
    }
}

@Composable
fun WaslAppNavigation(
    isDarkTheme: Boolean,
    onToggleTheme: () -> Unit,
    pendingNotificationConvId: String? = null,
    onNotificationConvHandled: () -> Unit = {}
) {
    val context = LocalContext.current
    val app = context.applicationContext as WaslApplication
    val scope = rememberCoroutineScope()
    val navController = rememberNavController()
    val customColors = LocalWaslColors.current

    // Check runtime permissions
    var hasPermissions by remember {
        mutableStateOf(checkRequiredPermissions(context))
    }

    val permissionsToRequest = remember {
        val list = mutableListOf(
            Manifest.permission.SEND_SMS,
            Manifest.permission.RECEIVE_SMS,
            Manifest.permission.READ_PHONE_STATE,
            Manifest.permission.READ_CONTACTS
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            list.add(Manifest.permission.POST_NOTIFICATIONS)
        }
        list.toTypedArray()
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestMultiplePermissions()
    ) { results ->
        val smsGranted = results[Manifest.permission.SEND_SMS] == true &&
                results[Manifest.permission.RECEIVE_SMS] == true
        hasPermissions = smsGranted
    }

    if (app.isSecurityLockdown) {
        // Critical Security Lockdown Screen (Identity Key Lost / Inaccessible)
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(MaterialTheme.colorScheme.background)
                .padding(24.dp),
            contentAlignment = Alignment.Center
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {
                Box(
                    modifier = Modifier
                        .size(80.dp)
                        .clip(RoundedCornerShape(24.dp))
                        .background(MaterialTheme.colorScheme.error.copy(alpha = 0.12f)),
                    contentAlignment = Alignment.Center
                ) {
                    Text(text = "⚠️", fontSize = 36.sp)
                }

                Spacer(modifier = Modifier.height(24.dp))

                Text(
                    text = "إغلاق أمني: تعذر الوصول لمفتاح الهوية",
                    fontFamily = ThmanyahBlack,
                    fontSize = 20.sp,
                    color = MaterialTheme.colorScheme.error,
                    textAlign = TextAlign.Center
                )

                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    text = "تعذر الوصول إلى مفتاح الهوية المحمي في عتاد الجهاز (Android Keystore).\n\nلحمايتك من انتحال الهوية وتزوير التوقيعات الرقمية، تم إيقاف التطبيق أمنياً. يُمنع توليد مفاتيح جديدة بصمت.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = customColors.textSecondary,
                    textAlign = TextAlign.Center,
                    lineHeight = 22.sp
                )
            }
        }
        return
    }

    if (!hasPermissions) {
        // Permissions Onboarding Screen
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(MaterialTheme.colorScheme.background)
                .padding(24.dp),
            contentAlignment = Alignment.Center
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {
                Box(
                    modifier = Modifier
                        .size(80.dp)
                        .clip(RoundedCornerShape(24.dp))
                        .background(customColors.sentBubble.copy(alpha = 0.12f)),
                    contentAlignment = Alignment.Center
                ) {
                    Text(text = "🔒", fontSize = 36.sp)
                }

                Spacer(modifier = Modifier.height(24.dp))

                Text(
                    text = "مرحباً بك في وَصْل",
                    fontFamily = ThmanyahBlack,
                    fontSize = 22.sp,
                    color = customColors.textPrimary
                )

                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    text = "نظام المراسلة الآمن والمشفر المخصص لليمن.\nيعمل التطبيق بدون أي اتصال بالإنترنت عبر شبكة الرسائل الخلوية (SMS).\n\nلتأمين تشفير الرسائل واكتشاف الشرائح، يرجى منح أذونات الرسائل والهاتف.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = customColors.textSecondary,
                    textAlign = TextAlign.Center,
                    lineHeight = 22.sp
                )

                Spacer(modifier = Modifier.height(32.dp))

                Button(
                    onClick = { permissionLauncher.launch(permissionsToRequest) },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = customColors.sentBubble)
                ) {
                    Text(
                        text = "منح الأذونات والبدء",
                        style = MaterialTheme.typography.labelLarge,
                        modifier = Modifier.padding(vertical = 4.dp)
                    )
                }
            }
        }
        return
    }

    // Active SIM cards discovery
    val activeSims = remember(hasPermissions) {
        app.simCardManager.getActiveSimCards()
    }

    // Observe real Room Database conversations
    val conversationEntities by app.database.conversationDao().getAllConversations()
        .collectAsState(initial = emptyList())

    val sendMessageUseCase = remember(app) {
        SendMessageUseCase(app.smsSender, app.simCardManager, app.database)
    }
    val retrySendMessageUseCase = remember(app) {
        RetrySendMessageUseCase(app.smsSender, app.database)
    }

    LaunchedEffect(pendingNotificationConvId, conversationEntities) {
        val targetId = pendingNotificationConvId
        if (!targetId.isNullOrBlank() && conversationEntities.any { it.id == targetId }) {
            val currentOpenConvId = navController.currentBackStackEntry?.arguments?.getString("conversationId")
            if (currentOpenConvId != targetId) {
                navController.navigate(Screen.Conversation.createRoute(targetId)) {
                    popUpTo(Screen.ChatsList.route)
                }
            }
            onNotificationConvHandled()
        }
    }

    val conversations = remember(conversationEntities) {
        conversationEntities.map { entity ->
            Conversation(
                id = entity.id,
                contactName = entity.contactName,
                phoneNumber = entity.phoneNumber,
                lastMessage = entity.lastMessage,
                lastMessageTimestamp = entity.lastMessageTimestamp,
                unreadCount = entity.unreadCount,
                handshakeStatus = try {
                    HandshakeStatus.valueOf(entity.handshakeStatus)
                } catch (e: Exception) {
                    HandshakeStatus.WAITING
                },
                defaultSubscriptionId = entity.defaultSubscriptionId,
                rejectedAt = entity.rejectedAt,
                currentRequestId = entity.currentRequestId
            )
        }
    }

    var showNewChatDialog by remember { mutableStateOf(false) }

    // Contact Picker
    val contactPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.PickContact()
    ) { contactUri: Uri? ->
        contactUri?.let { uri ->
            try {
                val cursor = context.contentResolver.query(uri, null, null, null, null)
                cursor?.use {
                    if (it.moveToFirst()) {
                        val nameIndex = it.getColumnIndex(ContactsContract.Contacts.DISPLAY_NAME)
                        val idIndex = it.getColumnIndex(ContactsContract.Contacts._ID)
                        val contactName = if (nameIndex >= 0) it.getString(nameIndex) else "جهة اتصال"
                        val contactId = if (idIndex >= 0) it.getString(idIndex) else ""

                        var rawPhone = ""
                        val phonesCursor = context.contentResolver.query(
                            ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
                            null,
                            ContactsContract.CommonDataKinds.Phone.CONTACT_ID + " = ?",
                            arrayOf(contactId),
                            null
                        )
                        phonesCursor?.use { pCursor ->
                            if (pCursor.moveToFirst()) {
                                val pIndex = pCursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER)
                                if (pIndex >= 0) {
                                    rawPhone = pCursor.getString(pIndex)
                                }
                            }
                        }

                        if (rawPhone.isNotBlank()) {
                            val normalizedPhone = YemenPhoneUtils.normalize(rawPhone)
                            scope.launch(Dispatchers.IO) {
                                val comparable = YemenPhoneUtils.extractComparableKey(normalizedPhone)
                                var conv = app.database.conversationDao().getConversationByComparableDigits(comparable)
                                if (conv == null) {
                                    val newId = UUID.randomUUID().toString()
                                    conv = ConversationEntity(
                                        id = newId,
                                        contactName = contactName,
                                        phoneNumber = normalizedPhone,
                                        lastMessage = null,
                                        lastMessageTimestamp = System.currentTimeMillis(),
                                        unreadCount = 0,
                                        handshakeStatus = "NEW",
                                        defaultSubscriptionId = activeSims.firstOrNull()?.subscriptionId,
                                        rejectedAt = null,
                                        currentRequestId = null,
                                        peerIdentityKeyBase64 = null,
                                        sessionKeyBase64 = null,
                                        inboundSessionKeyBase64 = null,
                                        nextOutboundCounter = 1L
                                    )
                                    app.database.conversationDao().insertOrUpdate(conv)
                                }
                                withContext(Dispatchers.Main) {
                                    navController.navigate(Screen.Conversation.createRoute(conv.id))
                                }
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                Toast.makeText(context, "تعذر قراءة جهة الاتصال", Toast.LENGTH_SHORT).show()
            }
        }
    }

    NavHost(
        navController = navController,
        startDestination = Screen.ChatsList.route
    ) {
        composable(Screen.ChatsList.route) {
            ChatsListScreen(
                conversations = conversations,
                isDarkTheme = isDarkTheme,
                onToggleTheme = onToggleTheme,
                onChatClick = { conversationId ->
                    navController.navigate(Screen.Conversation.createRoute(conversationId))
                },
                onNewChatClick = {
                    showNewChatDialog = true
                },
                onDeleteChat = { conversationId ->
                    scope.launch(Dispatchers.IO) {
                        val packetConvId = conversationId.replace("-", "").take(16)
                        app.database.withTransaction {
                            app.database.conversationDao().deleteById(conversationId)
                            app.database.messageDao().deleteAllForConversation(conversationId)
                            app.database.messageChunkDao().deleteChunksForConversation(conversationId, packetConvId)
                            app.database.handshakeDao().deleteForConversation(conversationId)
                        }
                        NotificationHelper(context).cancelConversationNotification(conversationId)
                    }
                }
            )

            if (showNewChatDialog) {
                NewChatDialog(
                    onDismiss = { showNewChatDialog = false },
                    onPickFromContacts = {
                        showNewChatDialog = false
                        contactPickerLauncher.launch(null)
                    },
                    onStartChat = { name, phone ->
                        val normalizedPhone = YemenPhoneUtils.normalize(phone)
                        scope.launch(Dispatchers.IO) {
                            val comparable = YemenPhoneUtils.extractComparableKey(normalizedPhone)
                            var conv = app.database.conversationDao().getConversationByComparableDigits(comparable)
                            if (conv == null) {
                                val newId = UUID.randomUUID().toString()
                                conv = ConversationEntity(
                                    id = newId,
                                    contactName = name,
                                    phoneNumber = normalizedPhone,
                                    lastMessage = null,
                                    lastMessageTimestamp = System.currentTimeMillis(),
                                    unreadCount = 0,
                                    handshakeStatus = "NEW",
                                    defaultSubscriptionId = activeSims.firstOrNull()?.subscriptionId,
                                    rejectedAt = null,
                                    currentRequestId = null,
                                    peerIdentityKeyBase64 = null,
                                    sessionKeyBase64 = null,
                                    inboundSessionKeyBase64 = null,
                                    nextOutboundCounter = 1L
                                )
                                app.database.conversationDao().insertOrUpdate(conv)
                            }
                            withContext(Dispatchers.Main) {
                                navController.navigate(Screen.Conversation.createRoute(conv.id))
                            }
                        }
                    }
                )
            }
        }

        composable(
            route = Screen.Conversation.route,
            arguments = listOf(navArgument("conversationId") { type = NavType.StringType })
        ) { backStackEntry ->
            val conversationId = backStackEntry.arguments?.getString("conversationId") ?: ""
            val convEntity = conversationEntities.find { it.id == conversationId }

            if (convEntity != null) {
                val conversation = remember(convEntity) {
                    Conversation(
                        id = convEntity.id,
                        contactName = convEntity.contactName,
                        phoneNumber = convEntity.phoneNumber,
                        lastMessage = convEntity.lastMessage,
                        lastMessageTimestamp = convEntity.lastMessageTimestamp,
                        unreadCount = convEntity.unreadCount,
                        handshakeStatus = try {
                            HandshakeStatus.valueOf(convEntity.handshakeStatus)
                        } catch (e: Exception) {
                            HandshakeStatus.WAITING
                        },
                        defaultSubscriptionId = convEntity.defaultSubscriptionId,
                        rejectedAt = convEntity.rejectedAt,
                        currentRequestId = convEntity.currentRequestId
                    )
                }

                val messageEntities by app.database.messageDao().getMessagesForConversation(conversationId)
                    .collectAsState(initial = emptyList())

                val messages = remember(messageEntities) {
                    messageEntities.map { m ->
                        Message(
                            id = m.id,
                            conversationId = m.conversationId,
                            direction = if (m.direction == "INCOMING") MessageDirection.INCOMING else MessageDirection.OUTGOING,
                            content = m.content,
                            timestamp = m.timestamp,
                            status = try {
                                MessageStatus.valueOf(m.status)
                            } catch (e: Exception) {
                                MessageStatus.DELIVERED
                            },
                            simSubscriptionId = m.simSubscriptionId,
                            totalParts = m.totalParts,
                            deliveredParts = m.deliveredParts
                        )
                    }
                }

                var activeSubId by remember(conversationId) {
                    mutableStateOf(convEntity.defaultSubscriptionId ?: activeSims.firstOrNull()?.subscriptionId)
                }

                LaunchedEffect(conversationId, activeSims) {
                    activeSubId = app.simCardManager.resolveEffectiveSimForConversation(conversationId)
                }

                LaunchedEffect(conversationId, convEntity.unreadCount) {
                    NotificationHelper(context).cancelConversationNotification(conversationId)
                    if (convEntity.unreadCount > 0) {
                        app.database.conversationDao().markConversationAsRead(conversationId)
                    }
                }

                val ourIdentityKey = remember {
                    app.identityManager.getPublicIdentityKey()
                }

                val currentReqId = convEntity.currentRequestId
                val currentHandshakeReq by remember(currentReqId) {
                    if (currentReqId != null) {
                        app.database.handshakeDao().observeByRequestId(currentReqId)
                    } else {
                        flowOf(null)
                    }
                }.collectAsState(initial = null)

                val isIncomingPendingHandshake =
                    conversation.handshakeStatus == HandshakeStatus.WAITING &&
                    currentHandshakeReq != null &&
                    currentHandshakeReq!!.isIncoming &&
                    currentHandshakeReq!!.status == "WAITING"

                val isIncomingAcceptedHandshake =
                    conversation.handshakeStatus == HandshakeStatus.WAITING &&
                    currentHandshakeReq != null &&
                    currentHandshakeReq!!.isIncoming &&
                    currentHandshakeReq!!.status == "ACCEPTED"

                ConversationScreen(
                    conversation = conversation,
                    messages = messages,
                    availableSims = activeSims,
                    currentSubId = activeSubId,
                    ourIdentityKey = ourIdentityKey,
                    peerIdentityKeyBase64 = convEntity.peerIdentityKeyBase64,
                    isIncomingPendingHandshake = isIncomingPendingHandshake,
                    isIncomingAcceptedHandshake = isIncomingAcceptedHandshake,
                    onBackClick = { navController.popBackStack() },
                    onSendMessage = { text, subId ->
                        scope.launch(Dispatchers.IO) {
                            val res = sendMessageUseCase(
                                conversationId = conversation.id,
                                plainText = text,
                                targetPhone = conversation.phoneNumber,
                                requestedSubId = subId
                            )
                            if (res.isFailure) {
                                withContext(Dispatchers.Main) {
                                    Toast.makeText(context, "فشل الإرسال: ${res.exceptionOrNull()?.message}", Toast.LENGTH_SHORT).show()
                                }
                            }
                        }
                    },
                    onSelectSim = { newSubId ->
                        activeSubId = newSubId
                        scope.launch(Dispatchers.IO) {
                            app.simCardManager.setConversationSimPreference(conversationId, newSubId)
                        }
                    },
                    onDeleteMessage = { messageId ->
                        scope.launch(Dispatchers.IO) {
                            app.database.messageDao().deleteMessageAndRefreshConversation(conversationId, messageId)
                        }
                    },
                    onInitiateHandshake = {
                        scope.launch(Dispatchers.IO) {
                            try {
                                val latestConv = app.database.conversationDao().getConversationById(conversation.id)
                                    ?: return@launch

                                if (latestConv.handshakeStatus == "KEY_CHANGED_ALERT" || latestConv.identityState == "KEY_CHANGED_ALERT") {
                                    withContext(Dispatchers.Main) {
                                        Toast.makeText(
                                            context,
                                            "⚠️ تم إيقاف المحادثة بسبب تغير الهوية الرقمية للطرف الآخر",
                                            Toast.LENGTH_SHORT
                                        ).show()
                                    }
                                    return@launch
                                }

                                // Strictly bind active request inspection to currentRequestId
                                val activeReq = latestConv.currentRequestId?.let {
                                    app.database.handshakeDao().getByRequestId(it)
                                }
                                if (latestConv.handshakeStatus == "WAITING" && activeReq != null && activeReq.isIncoming) {
                                    withContext(Dispatchers.Main) {
                                        Toast.makeText(
                                            context,
                                            "يوجد طلب تأسيس وارد بانتظار القبول أو الرفض",
                                            Toast.LENGTH_SHORT
                                        ).show()
                                    }
                                    return@launch
                                }

                                val existingReqId = if (
                                    latestConv.handshakeStatus == "WAITING" &&
                                    activeReq != null &&
                                    !activeReq.isIncoming &&
                                    activeReq.status == "WAITING"
                                ) {
                                    activeReq.requestId
                                } else {
                                    null
                                }

                                // Retrieve persisted ephemeral key from HandshakeEntity if retrying an outgoing request after restart
                                val persistedKeyPair = if (existingReqId != null) {
                                    val privB64 = activeReq?.ephemeralPrivateKeyBase64
                                    if (privB64 != null) {
                                        val privBytes = Base64.decode(privB64, Base64.NO_WRAP)
                                        val pubBytes = Curve25519Engine.getX25519PublicKeyFromPrivateKey(privBytes)
                                        Curve25519Engine.KeyPairBytes(privBytes, pubBytes)
                                    } else {
                                        // Strictly abort retry if original ephemeral key cannot be found; do not generate a new key for existing requestId
                                        withContext(Dispatchers.Main) {
                                            Toast.makeText(
                                                context,
                                                "تعذر العثور على المفتاح المؤقت للطلب السابق ($existingReqId). يرجى بدء طلب جديد.",
                                                Toast.LENGTH_LONG
                                            ).show()
                                        }
                                        return@launch
                                    }
                                } else {
                                    null
                                }

                                val initResult = app.handshakeManager.createInitRequest(
                                    existingRequestId = existingReqId,
                                    rejectedAt = latestConv.rejectedAt,
                                    persistedEphemeralKeyPair = persistedKeyPair
                                )
                                val ephKeyPair = app.handshakeManager.getEphemeralKeyPair(initResult.packet.requestId)
                                val privB64 = ephKeyPair?.let { Base64.encodeToString(it.privateKey, Base64.NO_WRAP) }
                                val now = System.currentTimeMillis()

                                var persistedToDb = false
                                app.database.withTransaction {
                                    val convTx = app.database.conversationDao().getConversationById(conversation.id)
                                        ?: return@withTransaction
                                    if (convTx.handshakeStatus == "KEY_CHANGED_ALERT" || convTx.identityState == "KEY_CHANGED_ALERT") {
                                        return@withTransaction
                                    }

                                    val handshakeReq = HandshakeEntity(
                                        requestId = initResult.packet.requestId,
                                        conversationId = conversation.id,
                                        phoneNumber = convTx.phoneNumber,
                                        isIncoming = false,
                                        status = "WAITING",
                                        createdAt = if (existingReqId != null) activeReq!!.createdAt else now,
                                        expiredAt = 0L,
                                        rejectedAt = null,
                                        ephemeralPrivateKeyBase64 = privB64,
                                        peerEphemeralPublicKeyBase64 = null
                                    )
                                    app.database.handshakeDao().insertOrUpdate(handshakeReq)

                                    app.database.conversationDao().update(
                                        convTx.copy(
                                            currentRequestId = initResult.packet.requestId,
                                            handshakeStatus = "WAITING",
                                            rejectedAt = null,
                                            lastMessage = "🔒 تم إرسال طلب تأسيس اتصال مشفر",
                                            lastMessageTimestamp = now
                                        )
                                    )
                                    persistedToDb = true
                                }
                                if (!persistedToDb) return@launch

                                val effectiveSubId = activeSubId ?: app.simCardManager.resolveEffectiveSimForConversation(conversation.id)
                                val smsManager = if (effectiveSubId != null && effectiveSubId != -1) {
                                    SmsManager.getSmsManagerForSubscriptionId(effectiveSubId)
                                } else {
                                    SmsManager.getDefault()
                                }
                                smsManager.sendTextMessage(conversation.phoneNumber, null, initResult.smsPayload, null, null)

                                withContext(Dispatchers.Main) {
                                    Toast.makeText(context, "تم إرسال طلب المصافحة عبر SMS", Toast.LENGTH_SHORT).show()
                                }
                            } catch (e: Exception) {
                                withContext(Dispatchers.Main) {
                                    Toast.makeText(context, e.message ?: "فشل إرسال طلب المصافحة", Toast.LENGTH_SHORT).show()
                                }
                            }
                        }
                    },
                    onAcceptHandshake = {
                        scope.launch(Dispatchers.IO) {
                            try {
                                val latestConv = app.database.conversationDao().getConversationById(conversation.id)
                                    ?: return@launch

                                if (latestConv.handshakeStatus == "KEY_CHANGED_ALERT" || latestConv.identityState == "KEY_CHANGED_ALERT") {
                                    withContext(Dispatchers.Main) {
                                        Toast.makeText(
                                            context,
                                            "⚠️ لا يمكن قبول المصافحة مع وجود تحذير تغير الهوية الرقمية",
                                            Toast.LENGTH_SHORT
                                        ).show()
                                    }
                                    return@launch
                                }

                                val reqId = latestConv.currentRequestId
                                val peerIdentityKeyB64 = latestConv.peerIdentityKeyBase64
                                val storedReq = reqId?.let { app.database.handshakeDao().getByRequestId(it) }
                                if (
                                    reqId == null ||
                                    peerIdentityKeyB64 == null ||
                                    storedReq == null ||
                                    !storedReq.isIncoming ||
                                    (storedReq.status != "WAITING" && storedReq.status != "ACCEPTED")
                                ) {
                                    withContext(Dispatchers.Main) {
                                        Toast.makeText(context, "لا يوجد طلب تأسيس وارد صالح للقبول", Toast.LENGTH_SHORT).show()
                                    }
                                    return@launch
                                }

                                val peerIdentityKey = Base64.decode(peerIdentityKeyB64, Base64.NO_WRAP)
                                val peerEphKey = storedReq.peerEphemeralPublicKeyBase64?.let {
                                    Base64.decode(it, Base64.NO_WRAP)
                                }
                                val ourPersistedEphKeyPair = storedReq.ephemeralPrivateKeyBase64?.let {
                                    val priv = Base64.decode(it, Base64.NO_WRAP)
                                    val pub = Curve25519Engine.getX25519PublicKeyFromPrivateKey(priv)
                                    Curve25519Engine.KeyPairBytes(priv, pub)
                                }
                                if (storedReq.status == "ACCEPTED" && ourPersistedEphKeyPair == null && app.handshakeManager.getEphemeralKeyPair(reqId) == null) {
                                    withContext(Dispatchers.Main) {
                                        Toast.makeText(
                                            context,
                                            "تعذر استعادة المفتاح المؤقت لهذا الطلب ($reqId)",
                                            Toast.LENGTH_LONG
                                        ).show()
                                    }
                                    return@launch
                                }

                                val respResult = app.handshakeManager.acceptInitRequest(
                                    requestId = reqId,
                                    peerIdentityKey = peerIdentityKey,
                                    persistedPeerEphemeralKey = peerEphKey,
                                    persistedOurEphemeralKeyPair = ourPersistedEphKeyPair
                                )

                                val ourEphKeyPair = app.handshakeManager.getEphemeralKeyPair(reqId)
                                val ourPrivB64 = ourEphKeyPair?.let { Base64.encodeToString(it.privateKey, Base64.NO_WRAP) }
                                val outKeyB64 = Base64.encodeToString(respResult.sessionKeys.outboundKey, Base64.NO_WRAP)
                                val inKeyB64 = Base64.encodeToString(respResult.sessionKeys.inboundKey, Base64.NO_WRAP)
                                val confirmationKeyB64 = Base64.encodeToString(respResult.sessionKeys.confirmationKey, Base64.NO_WRAP)

                                var committedAccept = false
                                app.database.withTransaction {
                                    val convTx = app.database.conversationDao().getConversationById(conversation.id)
                                        ?: return@withTransaction
                                    if (
                                        convTx.currentRequestId != reqId ||
                                        convTx.handshakeStatus == "KEY_CHANGED_ALERT" ||
                                        convTx.identityState == "KEY_CHANGED_ALERT"
                                    ) {
                                        return@withTransaction
                                    }

                                    app.database.handshakeDao().insertOrUpdate(
                                        storedReq.copy(
                                            status = "ACCEPTED",
                                            rejectedAt = null,
                                            ephemeralPrivateKeyBase64 = ourPrivB64 ?: storedReq.ephemeralPrivateKeyBase64
                                        )
                                    )

                                    app.database.conversationDao().update(
                                        convTx.copy(
                                            handshakeStatus = "WAITING",
                                            rejectedAt = null,
                                            peerIdentityKeyBase64 = peerIdentityKeyB64,
                                            sessionKeyBase64 = outKeyB64,
                                            inboundSessionKeyBase64 = inKeyB64,
                                            pendingConfirmationKeyBase64 = confirmationKeyB64,
                                            identityState = "PINNED_TOFU",
                                            lastMessage = "🔒 تم إرسال الرد، بانتظار تأكيد التشفير...",
                                            lastMessageTimestamp = System.currentTimeMillis()
                                        )
                                    )
                                    committedAccept = true
                                }
                                if (!committedAccept) return@launch

                                val effectiveSubId = activeSubId ?: app.simCardManager.resolveEffectiveSimForConversation(conversation.id)
                                val smsManager = if (effectiveSubId != null && effectiveSubId != -1) {
                                    SmsManager.getSmsManagerForSubscriptionId(effectiveSubId)
                                } else {
                                    SmsManager.getDefault()
                                }
                                smsManager.sendTextMessage(conversation.phoneNumber, null, respResult.smsPayload, null, null)

                                withContext(Dispatchers.Main) {
                                    Toast.makeText(context, "تم قبول المصافحة وإرسال الرد، بانتظار التأكيد", Toast.LENGTH_SHORT).show()
                                }
                            } catch (e: Exception) {
                                withContext(Dispatchers.Main) {
                                    Toast.makeText(context, e.message ?: "فشل قبول المصافحة", Toast.LENGTH_SHORT).show()
                                }
                            }
                        }
                    },
                    onRejectHandshake = {
                        scope.launch(Dispatchers.IO) {
                            try {
                                val latestConv = app.database.conversationDao().getConversationById(conversation.id)
                                    ?: return@launch

                                if (latestConv.handshakeStatus == "KEY_CHANGED_ALERT" || latestConv.identityState == "KEY_CHANGED_ALERT") {
                                    withContext(Dispatchers.Main) {
                                        Toast.makeText(
                                            context,
                                            "⚠️ المحادثة متوقفة بسبب تغير الهوية الرقمية",
                                            Toast.LENGTH_SHORT
                                        ).show()
                                    }
                                    return@launch
                                }

                                val reqId = latestConv.currentRequestId
                                val storedReq = reqId?.let { app.database.handshakeDao().getByRequestId(it) }
                                if (
                                    reqId == null ||
                                    storedReq == null ||
                                    !storedReq.isIncoming ||
                                    storedReq.status != "WAITING" ||
                                    latestConv.handshakeStatus != "WAITING"
                                ) {
                                    withContext(Dispatchers.Main) {
                                        Toast.makeText(context, "لا يوجد طلب وارد معلق لرفضه", Toast.LENGTH_SHORT).show()
                                    }
                                    return@launch
                                }

                                val (_, rejectPayload) = app.handshakeManager.createRejectPacket(reqId)
                                val effectiveSubId = activeSubId ?: app.simCardManager.resolveEffectiveSimForConversation(conversation.id)
                                val smsManager = if (effectiveSubId != null && effectiveSubId != -1) {
                                    SmsManager.getSmsManagerForSubscriptionId(effectiveSubId)
                                } else {
                                    SmsManager.getDefault()
                                }
                                smsManager.sendTextMessage(conversation.phoneNumber, null, rejectPayload, null, null)

                                val now = System.currentTimeMillis()
                                app.database.withTransaction {
                                    val convTx = app.database.conversationDao().getConversationById(conversation.id)
                                        ?: return@withTransaction
                                    if (
                                        convTx.currentRequestId != reqId ||
                                        convTx.handshakeStatus == "KEY_CHANGED_ALERT" ||
                                        convTx.identityState == "KEY_CHANGED_ALERT"
                                    ) {
                                        return@withTransaction
                                    }

                                    app.database.handshakeDao().updateStatusAndRejectedAt(
                                        requestId = reqId,
                                        status = "REJECTED",
                                        rejectedAt = null
                                    )
                                    // Responder NEVER has 3-minute cooldown applied to them
                                    app.database.conversationDao().update(
                                        convTx.copy(
                                            handshakeStatus = "REJECTED",
                                            rejectedAt = null,
                                            lastMessage = "تم رفض طلب الاتصال المشفر",
                                            lastMessageTimestamp = now
                                        )
                                    )
                                }
                                withContext(Dispatchers.Main) {
                                    Toast.makeText(context, "تم رفض الطلب وإشعار الطرف الآخر", Toast.LENGTH_SHORT).show()
                                }
                            } catch (e: Exception) {
                                withContext(Dispatchers.Main) {
                                    Toast.makeText(context, "فشل إرسال الرفض: ${e.message}", Toast.LENGTH_SHORT).show()
                                }
                            }
                        }
                    },
                    onResendConfirm = {
                        scope.launch(Dispatchers.IO) {
                            try {
                                val latestConv = app.database.conversationDao().getConversationById(conversation.id)
                                    ?: return@launch
                                if (
                                    latestConv.handshakeStatus != "PENDING_CONFIRM_SEND" ||
                                    latestConv.identityState == "KEY_CHANGED_ALERT"
                                ) {
                                    return@launch
                                }

                                val reqId = latestConv.currentRequestId
                                val confKeyB64 = latestConv.pendingConfirmationKeyBase64
                                if (reqId == null || confKeyB64 == null) {
                                    withContext(Dispatchers.Main) {
                                        Toast.makeText(context, "لا توجد بيانات تأكيد معلقة", Toast.LENGTH_SHORT).show()
                                    }
                                    return@launch
                                }
                                val confKey = Base64.decode(confKeyB64, Base64.NO_WRAP)
                                val (_, confirmPayload) = app.handshakeManager.createConfirmPacket(reqId, confKey)
                                val confirmMsgId = UUID.randomUUID().toString()
                                val effectiveSubId = activeSubId ?: app.simCardManager.resolveEffectiveSimForConversation(conversation.id)
                                app.smsSender.sendConfirmPacket(
                                    conversationId = conversation.id,
                                    targetPhone = conversation.phoneNumber,
                                    confirmPayload = confirmPayload,
                                    confirmMessageId = confirmMsgId,
                                    subscriptionId = effectiveSubId
                                )
                                withContext(Dispatchers.Main) {
                                    Toast.makeText(context, "جاري إعادة إرسال التأكيد...", Toast.LENGTH_SHORT).show()
                                }
                            } catch (e: Exception) {
                                withContext(Dispatchers.Main) {
                                    Toast.makeText(context, "فشل إعادة الإرسال: ${e.message}", Toast.LENGTH_SHORT).show()
                                }
                            }
                        }
                    },
                    onResendMessage = { messageId ->
                        scope.launch(Dispatchers.IO) {
                            val res = retrySendMessageUseCase(
                                conversationId = conversation.id,
                                messageId = messageId,
                                targetPhone = conversation.phoneNumber
                            )
                            if (res.isFailure) {
                                withContext(Dispatchers.Main) {
                                    Toast.makeText(
                                        context,
                                        "فشلت إعادة الإرسال: ${res.exceptionOrNull()?.message}",
                                        Toast.LENGTH_SHORT
                                    ).show()
                                }
                            }
                        }
                    }
                )
            }
        }
    }
}

private fun checkRequiredPermissions(context: Context): Boolean {
    val hasSendSms = ContextCompat.checkSelfPermission(context, Manifest.permission.SEND_SMS) == PackageManager.PERMISSION_GRANTED
    val hasReceiveSms = ContextCompat.checkSelfPermission(context, Manifest.permission.RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED
    return hasSendSms && hasReceiveSms
}
