package com.wasl.secure.presentation.conversation

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.ime
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.wasl.secure.R
import com.wasl.secure.core.theme.LocalWaslColors
import com.wasl.secure.core.theme.ThmanyahBlack
import com.wasl.secure.core.theme.WaslAmberPending
import com.wasl.secure.core.theme.WaslEmeraldActive
import com.wasl.secure.core.theme.WaslRoseReject
import com.wasl.secure.domain.model.Conversation
import com.wasl.secure.domain.model.HandshakeStatus
import com.wasl.secure.domain.model.Message
import com.wasl.secure.domain.model.MessageDirection
import com.wasl.secure.domain.model.MessageStatus
import com.wasl.secure.domain.model.SimInfo
import com.wasl.secure.telephony.MessageChunkManager
import com.wasl.secure.presentation.conversation.components.MessageBubble
import com.wasl.secure.presentation.conversation.components.MessageInputBar
import com.wasl.secure.presentation.conversation.components.SimSelectionDialog
import com.wasl.secure.presentation.handshake.HandshakeRejectionConfirmationDialog
import kotlinx.coroutines.delay
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConversationScreen(
    conversation: Conversation,
    messages: List<Message>,
    availableSims: List<SimInfo>,
    currentSubId: Int?,
    warnHighSmsParts: Boolean = true,
    isIncomingPendingHandshake: Boolean = false,
    isIncomingAcceptedHandshake: Boolean = false,
    onBackClick: () -> Unit,
    onOpenDetails: () -> Unit = {},
    onSendMessage: (String, Int?) -> Unit,
    onSelectSim: (Int) -> Unit,
    onDeleteMessage: (String) -> Unit,
    onInitiateHandshake: () -> Unit,
    onAcceptHandshake: () -> Unit,
    onRejectHandshake: () -> Unit,
    onResendConfirm: () -> Unit = {},
    onResendMessage: (String) -> Unit = {}
) {
    val context = LocalContext.current
    val customColors = LocalWaslColors.current
    var inputText by remember { mutableStateOf("") }
    var showSimDialog by remember { mutableStateOf(false) }
    var showRejectConfirmDialog by remember { mutableStateOf(false) }
    var selectedMessageForAction by remember { mutableStateOf<Message?>(null) }
    var showHighCostSmsWarning by remember { mutableStateOf(false) }

    var remainingCooldown by remember(conversation.rejectedAt, conversation.handshakeStatus) {
        mutableStateOf(conversation.remainingCooldownSeconds())
    }

    LaunchedEffect(conversation.rejectedAt, conversation.handshakeStatus) {
        remainingCooldown = conversation.remainingCooldownSeconds()
        if (conversation.handshakeStatus == HandshakeStatus.REJECTED) {
            while (remainingCooldown > 0) {
                delay(1000L)
                remainingCooldown = conversation.remainingCooldownSeconds()
            }
        }
    }

    val listState = rememberLazyListState()

    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) {
            listState.animateScrollToItem(messages.size - 1)
        }
    }

    Scaffold(
        contentWindowInsets = WindowInsets.statusBars,
        topBar = {
            TopAppBar(
                title = {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .clip(RoundedCornerShape(10.dp))
                            .clickable(onClick = onOpenDetails)
                            .padding(end = 6.dp)
                    ) {
                        // Contact Avatar
                        Box(
                            modifier = Modifier
                                .size(38.dp)
                                .clip(RoundedCornerShape(12.dp))
                                .background(customColors.sentBubble.copy(alpha = 0.15f)),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = conversation.contactName.firstOrNull()?.toString() ?: "و",
                                fontFamily = ThmanyahBlack,
                                fontSize = 16.sp,
                                color = customColors.sentBubble
                            )
                        }

                        Spacer(modifier = Modifier.width(10.dp))

                        // Contact Name & Discrete Security Pill
                        Column {
                            Text(
                                text = conversation.contactName,
                                fontFamily = ThmanyahBlack,
                                fontSize = 15.sp,
                                color = customColors.textPrimary
                            )
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                val (statusText, statusDotColor) = when (conversation.handshakeStatus) {
                                    HandshakeStatus.READY -> "مشفر عبر SMS" to WaslEmeraldActive
                                    HandshakeStatus.KEY_CHANGED_ALERT -> "⚠️ تغيرت الهوية الرقمية" to MaterialTheme.colorScheme.error
                                    HandshakeStatus.REJECTED -> "تم رفض طلب المصافحة" to WaslRoseReject
                                    HandshakeStatus.PENDING_CONFIRM_SEND -> "جاري تأكيد التشفير..." to WaslAmberPending
                                    else -> "في انتظار تأسيس المفاتيح" to WaslAmberPending
                                }
                                Box(
                                    modifier = Modifier
                                        .size(6.dp)
                                        .clip(RoundedCornerShape(3.dp))
                                        .background(statusDotColor)
                                )
                                Spacer(modifier = Modifier.width(4.dp))
                                Text(
                                    text = statusText,
                                    style = MaterialTheme.typography.labelSmall,
                                    color = statusDotColor,
                                    fontSize = 10.sp
                                )
                            }
                        }
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBackClick) {
                        Icon(
                            imageVector = Icons.Default.ArrowBack,
                            contentDescription = "Back",
                            tint = customColors.textPrimary
                        )
                    }
                },
                actions = {
                    // Conversation & Security Details screen button
                    IconButton(onClick = onOpenDetails) {
                        Icon(
                            imageVector = Icons.Default.Info,
                            contentDescription = "Security Info",
                            tint = customColors.textSecondary
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            )
        },
        bottomBar = {
            if (conversation.handshakeStatus == HandshakeStatus.READY) {
                MessageInputBar(
                    text = inputText,
                    onTextChanged = { inputText = it },
                    onSendClick = {
                        val estimatedParts = MessageChunkManager.estimateEncryptedSmsParts(inputText)

                        if (warnHighSmsParts && estimatedParts > 10) {
                            showHighCostSmsWarning = true
                        } else {
                            onSendMessage(inputText, currentSubId)
                            inputText = ""
                        }
                    },
                    onSendLongClick = {
                        if (availableSims.size > 1) {
                            showSimDialog = true
                        } else {
                            val activeSim = availableSims.firstOrNull()
                            val simDesc = if (activeSim != null) "${activeSim.displayName} (${activeSim.carrierName})" else "SIM 1"
                            Toast.makeText(context, "الشريحة الوحيدة: $simDesc", Toast.LENGTH_SHORT).show()
                        }
                    },
                    simDisplayName = availableSims.find { it.subscriptionId == currentSubId }?.displayName
                )
            } else {
                // Handshake Action Bar
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .navigationBarsPadding()
                        .imePadding()
                        .background(MaterialTheme.colorScheme.surfaceVariant)
                        .padding(16.dp),
                    contentAlignment = Alignment.Center
                ) {
                    when (conversation.handshakeStatus) {
                        HandshakeStatus.WAITING -> {
                            if (isIncomingPendingHandshake) {
                                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                    Text(
                                        text = "📩 طلب تأسيس محادثة مشفرة وارد من ${conversation.contactName}",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = customColors.textSecondary
                                    )
                                    Spacer(modifier = Modifier.height(10.dp))
                                    Row {
                                        Button(
                                            onClick = onAcceptHandshake,
                                            colors = ButtonDefaults.buttonColors(containerColor = customColors.sentBubble),
                                            shape = RoundedCornerShape(10.dp)
                                        ) {
                                            Text("قبول وتبادل المفاتيح")
                                        }
                                        Spacer(modifier = Modifier.width(8.dp))
                                        OutlinedButton(
                                            onClick = { showRejectConfirmDialog = true },
                                            shape = RoundedCornerShape(10.dp)
                                        ) {
                                            Text("رفض الطلب", color = MaterialTheme.colorScheme.error)
                                        }
                                    }
                                }
                            } else if (isIncomingAcceptedHandshake) {
                                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                    Text(
                                        text = "⏳ تم قبول الطلب وإرسال الرد، بانتظار تأكيد الطرف الآخر...",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = customColors.textSecondary
                                    )
                                    Spacer(modifier = Modifier.height(8.dp))
                                    OutlinedButton(
                                        onClick = onAcceptHandshake,
                                        shape = RoundedCornerShape(10.dp)
                                    ) {
                                        Text("إعادة إرسال الرد", color = customColors.textPrimary)
                                    }
                                }
                            } else if (conversation.currentRequestId == null) {
                                // Handle legacy NEW conversations previously stored as WAITING without an active requestId
                                Button(
                                    onClick = onInitiateHandshake,
                                    colors = ButtonDefaults.buttonColors(containerColor = customColors.sentBubble),
                                    shape = RoundedCornerShape(12.dp),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(18.dp))
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("إرسال طلب مصافحة مشفرة (Handshake SMS)")
                                }
                            } else {
                                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                    Text(
                                        text = "⏳ تم إرسال طلب المصافحة، بانتظار موافقة الطرف الآخر...",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = customColors.textSecondary
                                    )
                                    Spacer(modifier = Modifier.height(8.dp))
                                    OutlinedButton(
                                        onClick = onInitiateHandshake,
                                        shape = RoundedCornerShape(10.dp)
                                    ) {
                                        Text("إعادة إرسال الطلب", color = customColors.textPrimary)
                                    }
                                }
                            }
                        }
                        HandshakeStatus.PENDING_CONFIRM_SEND -> {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Text(
                                    text = "⏳ جاري إرسال تأكيد المصافحة (CONFIRM)...",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = customColors.textSecondary
                                )
                                Spacer(modifier = Modifier.height(8.dp))
                                Button(
                                    onClick = onResendConfirm,
                                    colors = ButtonDefaults.buttonColors(containerColor = customColors.sentBubble),
                                    shape = RoundedCornerShape(10.dp)
                                ) {
                                    Text("إعادة إرسال التأكيد")
                                }
                            }
                        }
                        HandshakeStatus.KEY_CHANGED_ALERT -> {
                            Column(
                                horizontalAlignment = Alignment.CenterHorizontally,
                                modifier = Modifier.padding(8.dp)
                            ) {
                                Text(
                                    text = "⚠️ تحذير أمني خطير: تغيرت الهوية الرقمية للطرف الآخر!\nتم إيقاف وحظر إرسال الرسائل لحمايتك من التجسس.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.error,
                                    textAlign = androidx.compose.ui.text.style.TextAlign.Center
                                )
                            }
                        }
                        HandshakeStatus.REJECTED -> {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                val rejectInfoText = if (remainingCooldown > 0) {
                                    val minutes = remainingCooldown / 60
                                    val seconds = remainingCooldown % 60
                                    String.format(
                                        Locale.getDefault(),
                                        "تم رفض الطلب. يمكنك إرسال طلب جديد بعد %02d:%02d",
                                        minutes,
                                        seconds
                                    )
                                } else {
                                    "تم رفض طلب الاتصال المشفر سابقاً. يمكنك إرسال طلب جديد الآن."
                                }
                                Text(
                                    text = rejectInfoText,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.error
                                )
                                Spacer(modifier = Modifier.height(8.dp))
                                Button(
                                    onClick = onInitiateHandshake,
                                    enabled = remainingCooldown == 0L,
                                    colors = ButtonDefaults.buttonColors(containerColor = customColors.sentBubble),
                                    shape = RoundedCornerShape(10.dp)
                                ) {
                                    Text("محاولة التأسيس مجدداً")
                                }
                            }
                        }
                        else -> {
                            Button(
                                onClick = onInitiateHandshake,
                                colors = ButtonDefaults.buttonColors(containerColor = customColors.sentBubble),
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("إرسال طلب مصافحة مشفرة (Handshake SMS)")
                            }
                        }
                    }
                }
            }
        },
        containerColor = MaterialTheme.colorScheme.background
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
        ) {
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(vertical = 8.dp)
            ) {
                // Discrete System Security Bubble in center
                item {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 12.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(12.dp))
                                .background(customColors.securityBadgeBackground)
                                .padding(horizontal = 14.dp, vertical = 6.dp)
                        ) {
                            Text(
                                text = if (conversation.handshakeStatus == HandshakeStatus.READY)
                                    "🔒 " + stringResource(R.string.handshake_completed)
                                else
                                    "🔒 محادثة عبر شبكة الرسائل الخلوية - بدون إنترنت",
                                style = MaterialTheme.typography.labelSmall,
                                color = customColors.securityBadgeText,
                                fontSize = 11.sp
                            )
                        }
                    }
                }

                // Chat Messages Stream
                items(messages, key = { it.id }) { message ->
                    MessageBubble(
                        message = message,
                        onLongClick = { selectedMessageForAction = message }
                    )
                }
            }
        }
    }

    // Handshake Rejection Confirmation Dialog (Incoming requests only)
    if (showRejectConfirmDialog && isIncomingPendingHandshake) {
        HandshakeRejectionConfirmationDialog(
            contactName = conversation.contactName,
            onConfirmReject = {
                showRejectConfirmDialog = false
                onRejectHandshake()
            },
            onDismiss = { showRejectConfirmDialog = false }
        )
    }

    // High SMS parts confirmation dialog (> 10 SMS parts)
    if (showHighCostSmsWarning) {
        AlertDialog(
            onDismissRequest = { showHighCostSmsWarning = false },
            title = {
                Text(
                    text = "تنبيه استهلاك رسائل SMS",
                    fontFamily = ThmanyahBlack,
                    color = customColors.textPrimary
                )
            },
            text = {
                Text(
                    text = "هذه الرسالة طويلة وستُرسل كأكثر من 10 رسائل SMS مجزأة عبر شبكة الاتصالات. هل تود المتابعة وخصم الرصيد الخلوي؟",
                    style = MaterialTheme.typography.bodyMedium,
                    color = customColors.textSecondary
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        onSendMessage(inputText, currentSubId)
                        inputText = ""
                        showHighCostSmsWarning = false
                    }
                ) {
                    Text(
                        text = "متابعة الإرسال",
                        color = customColors.sentBubble,
                        style = MaterialTheme.typography.labelLarge
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { showHighCostSmsWarning = false }) {
                    Text(
                        text = "إلغاء",
                        color = customColors.textPrimary,
                        style = MaterialTheme.typography.labelLarge
                    )
                }
            },
            containerColor = MaterialTheme.colorScheme.surface
        )
    }

    // Long-press Message Action Dialog (Copy / Delete)
    selectedMessageForAction?.let { message ->
        AlertDialog(
            onDismissRequest = { selectedMessageForAction = null },
            title = {
                Text(
                    text = "خيارات الرسالة المشفرة",
                    fontFamily = ThmanyahBlack,
                    color = customColors.textPrimary
                )
            },
            text = {
                Column {
                    Text(
                        text = "المحتوى المفكوك: \"${message.content.take(30)}...\"",
                        style = MaterialTheme.typography.bodySmall,
                        color = customColors.textSecondary
                    )
                }
            },
            confirmButton = {
                val canResend = message.direction == MessageDirection.OUTGOING &&
                        message.status == MessageStatus.FAILED &&
                        conversation.handshakeStatus == HandshakeStatus.READY
                Column(horizontalAlignment = Alignment.End) {
                    if (canResend) {
                        TextButton(
                            onClick = {
                                onResendMessage(message.id)
                                selectedMessageForAction = null
                            }
                        ) {
                            Text(
                                text = "إعادة الإرسال",
                                color = customColors.sentBubble,
                                style = MaterialTheme.typography.labelLarge
                            )
                        }
                    }
                    Row {
                        TextButton(
                            onClick = {
                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                val clip = ClipData.newPlainText("Decrypted WASL Message", message.content)
                                clipboard.setPrimaryClip(clip)
                                Toast.makeText(context, "تم نسخ النص المفكوك", Toast.LENGTH_SHORT).show()
                                selectedMessageForAction = null
                            }
                        ) {
                            Text(
                                text = "نسخ النص",
                                color = customColors.sentBubble,
                                style = MaterialTheme.typography.labelLarge
                            )
                        }

                        TextButton(
                            onClick = {
                                onDeleteMessage(message.id)
                                selectedMessageForAction = null
                            }
                        ) {
                            Text(
                                text = "مسح محلياً",
                                color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.labelLarge
                            )
                        }
                    }
                }
            },
            dismissButton = {
                TextButton(onClick = { selectedMessageForAction = null }) {
                    Text(
                        text = stringResource(R.string.return_button),
                        color = customColors.textPrimary,
                        style = MaterialTheme.typography.labelLarge
                    )
                }
            },
            containerColor = MaterialTheme.colorScheme.surface
        )
    }

    // SIM Selection Bottom Sheet / Dialog
    if (showSimDialog) {
        SimSelectionDialog(
            availableSims = availableSims,
            selectedSubId = currentSubId,
            onSimSelected = { subId ->
                onSelectSim(subId)
                showSimDialog = false
            },
            onDismiss = { showSimDialog = false }
        )
    }
}
