package com.wasl.secure.presentation.details

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.util.Base64
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Divider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.wasl.secure.R
import com.wasl.secure.core.crypto.Curve25519Engine
import com.wasl.secure.core.crypto.SafetyNumberGenerator
import com.wasl.secure.core.theme.LocalWaslColors
import com.wasl.secure.core.theme.ThmanyahBlack
import com.wasl.secure.core.theme.WaslAmberPending
import com.wasl.secure.core.theme.WaslRoseReject
import com.wasl.secure.domain.model.Conversation
import com.wasl.secure.domain.model.HandshakeStatus
import com.wasl.secure.domain.model.SimInfo
import com.wasl.secure.presentation.conversation.components.SimSelectionDialog

/**
 * Full-screen conversation security details, 12-digit safety number verification,
 * SIM card routing management, and local chat deletion.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConversationDetailsScreen(
    conversation: Conversation,
    availableSims: List<SimInfo>,
    currentSubId: Int?,
    ourIdentityKey: ByteArray,
    peerIdentityKeyBase64: String?,
    onBackClick: () -> Unit,
    onSelectSim: (Int) -> Unit,
    onDeleteChat: () -> Unit
) {
    val context = LocalContext.current
    val customColors = LocalWaslColors.current
    var showSimDialog by remember { mutableStateOf(false) }
    var showDeleteConfirm by remember { mutableStateOf(false) }

    val safetyNumber = remember(ourIdentityKey, peerIdentityKeyBase64) {
        if (peerIdentityKeyBase64.isNullOrBlank()) {
            null
        } else {
            try {
                val peerKey = Base64.decode(peerIdentityKeyBase64, Base64.NO_WRAP)
                if (peerKey.size == Curve25519Engine.KEY_SIZE && ourIdentityKey.size == Curve25519Engine.KEY_SIZE) {
                    SafetyNumberGenerator.generateSafetyNumber(ourIdentityKey, peerKey)
                } else {
                    null
                }
            } catch (_: Exception) {
                null
            }
        }
    }

    val activeSim = remember(availableSims, currentSubId) {
        availableSims.find { it.subscriptionId == currentSubId } ?: availableSims.firstOrNull()
    }
    val simLabel = if (activeSim != null) {
        "${activeSim.displayName} (${activeSim.carrierName})"
    } else {
        "الشريحة الافتراضية"
    }

    Scaffold(
        contentWindowInsets = WindowInsets.statusBars,
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "تفاصيل المحادثة والأمان",
                        fontFamily = ThmanyahBlack,
                        fontSize = 18.sp,
                        color = customColors.textPrimary
                    )
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
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            )
        },
        containerColor = MaterialTheme.colorScheme.background
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .navigationBarsPadding()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // 1. Contact Profile & Handshake Status Pill
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                color = MaterialTheme.colorScheme.surface,
                border = BorderStroke(1.dp, customColors.divider)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Box(
                        modifier = Modifier
                            .size(56.dp)
                            .clip(RoundedCornerShape(18.dp))
                            .background(customColors.sentBubble.copy(alpha = 0.15f)),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = conversation.contactName.firstOrNull()?.toString() ?: "و",
                            fontFamily = ThmanyahBlack,
                            fontSize = 22.sp,
                            color = customColors.sentBubble
                        )
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    Text(
                        text = conversation.contactName,
                        fontFamily = ThmanyahBlack,
                        fontSize = 17.sp,
                        color = customColors.textPrimary
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                        Text(
                            text = conversation.phoneNumber,
                            style = MaterialTheme.typography.bodyMedium,
                            color = customColors.textSecondary
                        )
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    StatusBadgePill(status = conversation.handshakeStatus)
                }
            }

            // 2. Safety Number Verification Card (No QR)
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                color = MaterialTheme.colorScheme.surface,
                border = BorderStroke(1.dp, customColors.divider)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp)
                ) {
                    Text(
                        text = "رقم الأمان والتحقق المشفر",
                        fontFamily = ThmanyahBlack,
                        fontSize = 15.sp,
                        color = customColors.textPrimary
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    if (safetyNumber != null) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(12.dp))
                                .background(customColors.sentBubble.copy(alpha = 0.12f))
                                .border(
                                    width = 1.dp,
                                    color = customColors.sentBubble.copy(alpha = 0.3f),
                                    shape = RoundedCornerShape(12.dp)
                                )
                                .padding(vertical = 12.dp, horizontal = 10.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                                Text(
                                    text = safetyNumber,
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 19.sp,
                                    color = customColors.textPrimary,
                                    letterSpacing = 1.sp
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(10.dp))

                        Text(
                            text = "قارن هذا الرقم المكون من 12 رقماً مع الرقم الظاهر على هاتف ${conversation.contactName} للتحقق من عدم وجود أي وسيط.",
                            style = MaterialTheme.typography.bodySmall,
                            color = customColors.textSecondary,
                            lineHeight = 18.sp
                        )

                        Spacer(modifier = Modifier.height(12.dp))

                        OutlinedButton(
                            onClick = {
                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                clipboard.setPrimaryClip(ClipData.newPlainText("WASL Safety Number", safetyNumber))
                                Toast.makeText(context, "تم نسخ رقم الأمان", Toast.LENGTH_SHORT).show()
                            },
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            border = BorderStroke(1.dp, customColors.divider),
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = customColors.sentBubble
                            )
                        ) {
                            Icon(
                                imageVector = Icons.Default.ContentCopy,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "نسخ رقم الأمان",
                                fontFamily = ThmanyahBlack,
                                fontSize = 13.sp
                            )
                        }
                    } else {
                        Text(
                            text = "سيتم توليد رقم الأمان المكون من 12 رقماً فور إتمام المصافحة وتبادل المفاتيح مع الطرف الآخر.",
                            style = MaterialTheme.typography.bodySmall,
                            color = customColors.textSecondary,
                            lineHeight = 18.sp
                        )
                    }
                }
            }

            // 3. Encryption & SIM Routing Info Card
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                color = MaterialTheme.colorScheme.surface,
                border = BorderStroke(1.dp, customColors.divider)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Text(
                        text = "معلومات التشفير والشريحة",
                        fontFamily = ThmanyahBlack,
                        fontSize = 15.sp,
                        color = customColors.textPrimary
                    )

                    Divider(color = customColors.divider, thickness = 0.75.dp)

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "التشفير المعتمد",
                            style = MaterialTheme.typography.bodySmall,
                            color = customColors.textSecondary
                        )
                        CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                            Text(
                                text = "X25519 + Ed25519 + AES-256",
                                style = MaterialTheme.typography.bodySmall,
                                color = customColors.textPrimary
                            )
                        }
                    }

                    Divider(color = customColors.divider, thickness = 0.75.dp)

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                if (availableSims.size > 1) {
                                    showSimDialog = true
                                } else {
                                    Toast.makeText(context, "الشريحة الوحيدة: $simLabel", Toast.LENGTH_SHORT).show()
                                }
                            }
                            .padding(vertical = 2.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "شريحة الإرسال",
                            style = MaterialTheme.typography.bodySmall,
                            color = customColors.textSecondary
                        )
                        Text(
                            text = if (availableSims.size > 1) "$simLabel • تغيير" else simLabel,
                            fontFamily = ThmanyahBlack,
                            fontSize = 12.sp,
                            color = customColors.sentBubble
                        )
                    }
                }
            }

            // 4. Local Chat Deletion Button
            OutlinedButton(
                onClick = { showDeleteConfirm = true },
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                border = BorderStroke(1.dp, WaslRoseReject.copy(alpha = 0.45f)),
                colors = ButtonDefaults.outlinedButtonColors(
                    containerColor = WaslRoseReject.copy(alpha = 0.1f),
                    contentColor = WaslRoseReject
                )
            ) {
                Text(
                    text = "مسح المحادثة محلياً",
                    fontFamily = ThmanyahBlack,
                    fontSize = 13.sp,
                    modifier = Modifier.padding(vertical = 4.dp)
                )
            }
        }
    }

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

    if (showDeleteConfirm) {
        AlertDialog(
            onDismissRequest = { showDeleteConfirm = false },
            title = {
                Text(
                    text = "مسح المحادثة محلياً",
                    fontFamily = ThmanyahBlack,
                    color = customColors.textPrimary
                )
            },
            text = {
                Text(
                    text = "هل أنت متأكد من مسح هذه المحادثة وجميع رسائلها من هذا الجهاز؟",
                    style = MaterialTheme.typography.bodyMedium,
                    color = customColors.textSecondary,
                    textAlign = TextAlign.Start
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showDeleteConfirm = false
                        onDeleteChat()
                    }
                ) {
                    Text(
                        text = "مسح محلياً",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.labelLarge
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteConfirm = false }) {
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
}

@Composable
private fun StatusBadgePill(status: HandshakeStatus) {
    val customColors = LocalWaslColors.current
    val (label, bgColor, borderColor, textColor) = when (status) {
        HandshakeStatus.READY -> Quadruple(
            "🔒 محادثة مشفرة جاهزة (READY)",
            customColors.securityBadgeBackground,
            customColors.securityBadgeBorder,
            customColors.securityBadgeText
        )
        HandshakeStatus.KEY_CHANGED_ALERT -> Quadruple(
            "⚠️ تحذير أمني: تغيّرت الهوية الرقمية",
            WaslRoseReject.copy(alpha = 0.12f),
            WaslRoseReject.copy(alpha = 0.45f),
            WaslRoseReject
        )
        HandshakeStatus.REJECTED -> Quadruple(
            "✕ تم رفض طلب التأسيس",
            WaslRoseReject.copy(alpha = 0.12f),
            WaslRoseReject.copy(alpha = 0.45f),
            WaslRoseReject
        )
        else -> Quadruple(
            "⏳ بانتظار إتمام التأسيس المشفر",
            WaslAmberPending.copy(alpha = 0.12f),
            WaslAmberPending.copy(alpha = 0.45f),
            WaslAmberPending
        )
    }

    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(bgColor)
            .border(1.dp, borderColor, RoundedCornerShape(50))
            .padding(horizontal = 12.dp, vertical = 5.dp)
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = textColor
        )
    }
}

private data class Quadruple<A, B, C, D>(
    val first: A,
    val second: B,
    val third: C,
    val fourth: D
)
