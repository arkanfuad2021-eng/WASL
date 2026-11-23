package com.wasl.secure

import android.Manifest
import android.content.Context
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
import com.wasl.secure.core.theme.LocalWaslColors
import com.wasl.secure.core.theme.ThmanyahBlack
import com.wasl.secure.core.theme.WaslTheme
import com.wasl.secure.core.util.YemenPhoneUtils
import com.wasl.secure.data.local.entity.ConversationEntity
import com.wasl.secure.domain.model.Conversation
import com.wasl.secure.domain.model.HandshakeStatus
import com.wasl.secure.domain.model.Message
import com.wasl.secure.domain.model.MessageDirection
import com.wasl.secure.domain.model.MessageStatus
import com.wasl.secure.domain.model.SimInfo
import com.wasl.secure.presentation.chats.ChatsListScreen
import com.wasl.secure.presentation.chats.components.NewChatDialog
import com.wasl.secure.presentation.conversation.ConversationScreen
import com.wasl.secure.presentation.navigation.Screen
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            var isDarkTheme by remember { mutableStateOf(true) }

            WaslTheme(darkTheme = isDarkTheme) {
                WaslAppNavigation(
                    isDarkTheme = isDarkTheme,
                    onToggleTheme = { isDarkTheme = !isDarkTheme }
                )
            }
        }
    }
}

@Composable
fun WaslAppNavigation(
    isDarkTheme: Boolean,
    onToggleTheme: () -> Unit
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
                                        handshakeStatus = "WAITING",
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
                        app.database.conversationDao().deleteById(conversationId)
                        app.database.messageDao().deleteAllForConversation(conversationId)
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
                                    handshakeStatus = "WAITING",
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

                var activeSubId by remember {
                    mutableStateOf(convEntity.defaultSubscriptionId ?: activeSims.firstOrNull()?.subscriptionId)
                }

                val ourIdentityKey = remember {
                    app.identityManager.getPublicIdentityKey()
                }

                ConversationScreen(
                    conversation = conversation,
                    messages = messages,
                    availableSims = activeSims,
                    currentSubId = activeSubId,
                    ourIdentityKey = ourIdentityKey,
                    peerIdentityKeyBase64 = convEntity.peerIdentityKeyBase64,
                    onBackClick = { navController.popBackStack() },
                    onSendMessage = { text, subId ->
                        scope.launch(Dispatchers.IO) {
                            val res = app.smsSender.sendEncryptedMessage(
                                conversationId = conversation.id,
                                plainText = text,
                                targetPhone = conversation.phoneNumber,
                                subscriptionId = subId
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
                            app.database.conversationDao().updateDefaultSim(conversation.id, newSubId)
                        }
                    },
                    onDeleteMessage = { messageId ->
                        scope.launch(Dispatchers.IO) {
                            app.database.messageDao().deleteById(messageId)
                        }
                    },
                    onInitiateHandshake = {
                        scope.launch(Dispatchers.IO) {
                            try {
                                val initResult = app.handshakeManager.createInitRequest(
                                    existingRequestId = convEntity.currentRequestId,
                                    rejectedAt = convEntity.rejectedAt
                                )
                                app.database.conversationDao().update(
                                    convEntity.copy(
                                        currentRequestId = initResult.packet.requestId,
                                        handshakeStatus = "WAITING",
                                        lastMessage = "🔒 تم إرسال طلب تأسيس اتصال مشفر",
                                        lastMessageTimestamp = System.currentTimeMillis()
                                    )
                                )

                                val smsManager = if (activeSubId != null && activeSubId != -1) {
                                    SmsManager.getSmsManagerForSubscriptionId(activeSubId!!)
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
                                val reqId = convEntity.currentRequestId
                                if (reqId == null) {
                                    withContext(Dispatchers.Main) {
                                        Toast.makeText(context, "لا يوجد طلب تأسيس معلق", Toast.LENGTH_SHORT).show()
                                    }
                                    return@launch
                                }
                                val respResult = app.handshakeManager.acceptInitRequest(reqId)
                                val outKeyB64 = Base64.encodeToString(respResult.sessionKeys.outboundKey, Base64.NO_WRAP)
                                val inKeyB64 = Base64.encodeToString(respResult.sessionKeys.inboundKey, Base64.NO_WRAP)
                                val peerIdentityB64 = Base64.encodeToString(respResult.packet.identityPublicKey, Base64.NO_WRAP)

                                app.database.conversationDao().update(
                                    convEntity.copy(
                                        handshakeStatus = "READY",
                                        peerIdentityKeyBase64 = peerIdentityB64,
                                        sessionKeyBase64 = outKeyB64,
                                        inboundSessionKeyBase64 = inKeyB64,
                                        lastMessage = "✅ تم تأسيس التشفير والمفاتيح بنجاح",
                                        lastMessageTimestamp = System.currentTimeMillis()
                                    )
                                )

                                val smsManager = if (activeSubId != null && activeSubId != -1) {
                                    SmsManager.getSmsManagerForSubscriptionId(activeSubId!!)
                                } else {
                                    SmsManager.getDefault()
                                }
                                smsManager.sendTextMessage(conversation.phoneNumber, null, respResult.smsPayload, null, null)

                                withContext(Dispatchers.Main) {
                                    Toast.makeText(context, "تم قبول المصافحة وتفعيل التشفير بنجاح", Toast.LENGTH_SHORT).show()
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
                                val reqId = convEntity.currentRequestId
                                if (reqId != null) {
                                    val rejectPayload = app.handshakeManager.createRejectPacket(reqId)
                                    val smsManager = if (activeSubId != null && activeSubId != -1) {
                                        SmsManager.getSmsManagerForSubscriptionId(activeSubId!!)
                                    } else {
                                        SmsManager.getDefault()
                                    }
                                    smsManager.sendTextMessage(conversation.phoneNumber, null, rejectPayload, null, null)
                                }
                                app.database.conversationDao().update(
                                    convEntity.copy(
                                        handshakeStatus = "REJECTED",
                                        rejectedAt = System.currentTimeMillis(),
                                        lastMessage = "تم رفض طلب الاتصال المشفر",
                                        lastMessageTimestamp = System.currentTimeMillis()
                                    )
                                )
                            } catch (e: Exception) {
                                // Suppressed
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
