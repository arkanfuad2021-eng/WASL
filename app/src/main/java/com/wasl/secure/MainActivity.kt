package com.wasl.secure

import android.net.Uri
import android.os.Bundle
import android.provider.ContactsContract
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.wasl.secure.core.theme.WaslTheme
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
    val navController = rememberNavController()
    var showNewChatDialog by remember { mutableStateOf(false) }

    // SIM cards discovery
    val sampleSims = remember {
        listOf(
            SimInfo(subscriptionId = 1, slotIndex = 0, displayName = "SIM 1 (الأساسية)", carrierName = "STC", isDefaultSms = true),
            SimInfo(subscriptionId = 2, slotIndex = 1, displayName = "SIM 2 (الثانوية)", carrierName = "Mobily", isDefaultSms = false)
        )
    }

    val conversations = remember {
        mutableStateListOf(
            Conversation(
                id = "conv-1",
                contactName = "محمد القحطاني",
                phoneNumber = "+966501234567",
                lastMessage = "أهلاً يا محمد، هل وصلتك الرسالة الأخيرة؟",
                lastMessageTimestamp = System.currentTimeMillis() - 1000 * 60 * 5,
                handshakeStatus = HandshakeStatus.READY,
                defaultSubscriptionId = 1
            ),
            Conversation(
                id = "conv-2",
                contactName = "أحمد السعيد",
                phoneNumber = "+966559876543",
                lastMessage = null,
                lastMessageTimestamp = System.currentTimeMillis() - 1000 * 60 * 30,
                handshakeStatus = HandshakeStatus.WAITING,
                defaultSubscriptionId = 1
            ),
            Conversation(
                id = "conv-3",
                contactName = "خالد العتيبي",
                phoneNumber = "+966540001122",
                lastMessage = "تم الاتفاق، سأرسل لك التفاصيل غداً بإذن الله",
                lastMessageTimestamp = System.currentTimeMillis() - 1000 * 60 * 60 * 24,
                handshakeStatus = HandshakeStatus.READY,
                defaultSubscriptionId = 2
            ),
            Conversation(
                id = "conv-4",
                contactName = "سالم الدوسري",
                phoneNumber = "+966567778899",
                lastMessage = null,
                lastMessageTimestamp = System.currentTimeMillis() - 1000 * 60,
                handshakeStatus = HandshakeStatus.REJECTED,
                rejectedAt = System.currentTimeMillis() - 1000 * 45 // 45 seconds ago (has remaining cooldown)
            )
        )
    }

    val sampleMessages = remember {
        mutableStateListOf(
            Message(
                id = "msg-1",
                conversationId = "conv-1",
                direction = MessageDirection.INCOMING,
                content = "السلام عليكم أحمد، تم تفعيل المحادثة بنجاح، هل تسمعني؟",
                timestamp = System.currentTimeMillis() - 1000 * 60 * 8,
                status = MessageStatus.DECRYPTED
            ),
            Message(
                id = "msg-2",
                conversationId = "conv-1",
                direction = MessageDirection.OUTGOING,
                content = "وعليكم السلام ورحمة الله! نعم، الرسائل تصل مفكوكة ومشفرة تماماً عبر SMS وبدون إنترنت 🎉",
                timestamp = System.currentTimeMillis() - 1000 * 60 * 6,
                status = MessageStatus.DELIVERED
            ),
            Message(
                id = "msg-3",
                conversationId = "conv-1",
                direction = MessageDirection.OUTGOING,
                content = "لاحظ كيف أن النص الأصلي يظهر هنا فقط، بينما في تطبيق رسائل النظام يظهر نص مشفر غير مفهوم.",
                timestamp = System.currentTimeMillis() - 1000 * 60 * 5,
                status = MessageStatus.DELIVERED
            )
        )
    }

    // Official Android Contact Picker launcher
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

                        // Query phone number
                        var phoneNumber = ""
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
                                    phoneNumber = pCursor.getString(pIndex)
                                }
                            }
                        }

                        if (phoneNumber.isNotBlank()) {
                            // Check existing conversation
                            val existing = conversations.find { c -> c.phoneNumber.replace(" ", "") == phoneNumber.replace(" ", "") }
                            if (existing != null) {
                                navController.navigate(Screen.Conversation.createRoute(existing.id))
                            } else {
                                val newConv = Conversation(
                                    id = UUID.randomUUID().toString(),
                                    contactName = contactName,
                                    phoneNumber = phoneNumber,
                                    lastMessage = null,
                                    lastMessageTimestamp = System.currentTimeMillis(),
                                    handshakeStatus = HandshakeStatus.WAITING,
                                    defaultSubscriptionId = 1
                                )
                                conversations.add(0, newConv)
                                navController.navigate(Screen.Conversation.createRoute(newConv.id))
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                // Handled gracefully
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
                    conversations.removeAll { it.id == conversationId }
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
                        val existing = conversations.find { c -> c.phoneNumber.replace(" ", "") == phone.replace(" ", "") }
                        if (existing != null) {
                            navController.navigate(Screen.Conversation.createRoute(existing.id))
                        } else {
                            val newConv = Conversation(
                                id = UUID.randomUUID().toString(),
                                contactName = name,
                                phoneNumber = phone,
                                lastMessage = null,
                                lastMessageTimestamp = System.currentTimeMillis(),
                                handshakeStatus = HandshakeStatus.WAITING,
                                defaultSubscriptionId = 1
                            )
                            conversations.add(0, newConv)
                            navController.navigate(Screen.Conversation.createRoute(newConv.id))
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
            val conversation = conversations.find { it.id == conversationId } ?: conversations.first()

            var activeSubId by remember { mutableStateOf(conversation.defaultSubscriptionId ?: 1) }

            ConversationScreen(
                conversation = conversation,
                messages = sampleMessages.filter { it.conversationId == conversation.id },
                availableSims = sampleSims,
                currentSubId = activeSubId,
                onBackClick = { navController.popBackStack() },
                onSendMessage = { text, subId ->
                    sampleMessages.add(
                        Message(
                            id = UUID.randomUUID().toString(),
                            conversationId = conversation.id,
                            direction = MessageDirection.OUTGOING,
                            content = text,
                            timestamp = System.currentTimeMillis(),
                            status = MessageStatus.DELIVERED,
                            simSubscriptionId = subId
                        )
                    )
                },
                onSelectSim = { newSubId ->
                    activeSubId = newSubId
                    val index = conversations.indexOfFirst { it.id == conversation.id }
                    if (index != -1) {
                        conversations[index] = conversations[index].copy(defaultSubscriptionId = newSubId)
                    }
                },
                onDeleteMessage = { messageId ->
                    sampleMessages.removeAll { it.id == messageId }
                }
            )
        }
    }
}
