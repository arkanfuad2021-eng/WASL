package com.wasl.secure.presentation.conversation.components

import android.util.Base64
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.wasl.secure.core.crypto.SafetyNumberGenerator
import com.wasl.secure.core.theme.LocalWaslColors
import com.wasl.secure.core.theme.ThmanyahBlack

@Composable
fun SafetyNumberDialog(
    contactName: String,
    ourIdentityKey: ByteArray,
    peerIdentityKeyBase64: String?,
    onDismiss: () -> Unit
) {
    val customColors = LocalWaslColors.current

    val safetyNumber = remember(peerIdentityKeyBase64) {
        if (peerIdentityKeyBase64 != null) {
            try {
                val peerKey = Base64.decode(peerIdentityKeyBase64, Base64.NO_WRAP)
                SafetyNumberGenerator.generateSafetyNumber(ourIdentityKey, peerKey)
            } catch (e: Exception) {
                "غير متاح حتى اكتمال المصافحة"
            }
        } else {
            "غير متاح حتى اكتمال المصافحة"
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "رقم الأمان والتحقق المشفر",
                fontFamily = ThmanyahBlack,
                color = customColors.textPrimary
            )
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    text = "قارن هذا الرقم المكون من 12 رقماً مع الرقم الظاهر على هاتف ($contactName). إذا تطابقت الأرقام، فهذا يثبت 100% أن المحادثة مشفرة ولا يمكن لأي شبكة اعتراضها (Zero-MITM):",
                    style = MaterialTheme.typography.bodySmall,
                    color = customColors.textSecondary,
                    textAlign = TextAlign.Center
                )

                Spacer(modifier = Modifier.height(16.dp))

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(customColors.sentBubble.copy(alpha = 0.08f))
                        .padding(16.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = safetyNumber,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp,
                        color = customColors.textPrimary,
                        lineHeight = 22.sp,
                        textAlign = TextAlign.Center
                    )
                }

                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    text = "🔒 التشفير: X25519 + Ed25519 + AES-256-GCM\nعزل تام بدون إنترنت",
                    style = MaterialTheme.typography.labelSmall,
                    color = customColors.textTertiary,
                    textAlign = TextAlign.Center
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text(
                    text = "إغلاق",
                    color = customColors.sentBubble
                )
            }
        },
        containerColor = MaterialTheme.colorScheme.surface
    )
}
