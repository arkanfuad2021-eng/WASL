package com.wasl.secure.presentation.conversation.components

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Send
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.wasl.secure.R
import com.wasl.secure.core.theme.LocalWaslColors
import com.wasl.secure.telephony.MessageChunkManager

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun MessageInputBar(
    text: String,
    onTextChanged: (String) -> Unit,
    onSendClick: () -> Unit,
    onSendLongClick: () -> Unit,
    simDisplayName: String?,
    modifier: Modifier = Modifier
) {
    val customColors = LocalWaslColors.current

    // Real-time calculation of estimated SMS segments matching MessageChunkManager (63 bytes/part)
    val estimatedSmsParts = remember(text) {
        MessageChunkManager.estimateEncryptedSmsParts(text)
    }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .navigationBarsPadding()
            .imePadding()
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .border(width = 0.5.dp, color = customColors.divider)
            .padding(horizontal = 12.dp, vertical = 8.dp)
    ) {
        // SMS Parts & Encryption Status Bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 4.dp, vertical = 2.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "🔒 مشفر محلياً بـ AES-256-GCM",
                style = MaterialTheme.typography.labelSmall,
                color = customColors.sentBubble
            )

            Spacer(modifier = Modifier.weight(1f))

            // Post-encryption SMS part counter
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .background(customColors.sentBubble.copy(alpha = 0.12f))
                .padding(horizontal = 8.dp, vertical = 2.dp)
            ) {
                Text(
                    text = "$estimatedSmsParts SMS (مشفر)",
                    style = MaterialTheme.typography.labelSmall,
                    color = if (estimatedSmsParts > 10) MaterialTheme.colorScheme.error else customColors.sentBubble,
                    fontSize = 10.sp
                )
            }
        }

        // Input Field & Send Button Row
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Text input container
            Box(
                modifier = Modifier
                    .weight(1f)
                    .clip(RoundedCornerShape(20.dp))
                    .background(customColors.inputBackground)
                    .border(width = 1.dp, color = customColors.inputBorder, shape = RoundedCornerShape(20.dp))
                    .padding(horizontal = 16.dp, vertical = 10.dp)
            ) {
                if (text.isEmpty()) {
                    Text(
                        text = stringResource(R.string.type_encrypted_message),
                        style = MaterialTheme.typography.bodyMedium,
                        color = customColors.textTertiary
                    )
                }
                BasicTextField(
                    value = text,
                    onValueChange = onTextChanged,
                    textStyle = MaterialTheme.typography.bodyMedium.copy(
                        color = customColors.textPrimary
                    ),
                    cursorBrush = SolidColor(customColors.sentBubble),
                    modifier = Modifier.fillMaxWidth()
                )
            }

            Spacer(modifier = Modifier.width(8.dp))

            // Dual-Action Send Button (Click: Send, Long-Click: Choose SIM)
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .clip(RoundedCornerShape(16.dp))
                    .background(if (text.isNotBlank()) customColors.sentBubble else customColors.sentBubble.copy(alpha = 0.4f))
                    .combinedClickable(
                        onClick = { if (text.isNotBlank()) onSendClick() },
                        onLongClick = onSendLongClick
                    ),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Default.Send,
                    contentDescription = "Send",
                    tint = Color.White,
                    modifier = Modifier.size(20.dp)
                )
            }
        }
    }
}
