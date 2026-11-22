package com.wasl.secure.presentation.conversation.components

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.wasl.secure.core.theme.LocalWaslColors
import com.wasl.secure.core.theme.WaslRoseReject
import com.wasl.secure.domain.model.Message
import com.wasl.secure.domain.model.MessageDirection
import com.wasl.secure.domain.model.MessageStatus
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun MessageBubble(
    message: Message,
    onLongClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val customColors = LocalWaslColors.current
    val isOutgoing = message.direction == MessageDirection.OUTGOING
    val timeFormat = remember { SimpleDateFormat("h:mm a", Locale.getDefault()) }

    Box(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 14.dp, vertical = 4.dp),
        contentAlignment = if (isOutgoing) Alignment.CenterEnd else Alignment.CenterStart
    ) {
        Column(
            modifier = Modifier
                .widthIn(max = 280.dp)
                .clip(
                    RoundedCornerShape(
                        topStart = 18.dp,
                        topEnd = 18.dp,
                        bottomStart = if (isOutgoing) 18.dp else 4.dp,
                        bottomEnd = if (isOutgoing) 4.dp else 18.dp
                    )
                )
                .background(
                    if (isOutgoing) customColors.sentBubble else customColors.receivedBubble
                )
                .combinedClickable(
                    onClick = { /* Message Details */ },
                    onLongClick = onLongClick
                )
                .padding(horizontal = 14.dp, vertical = 9.dp)
        ) {
            // Decrypted plain text content
            Text(
                text = message.content,
                style = MaterialTheme.typography.bodyMedium,
                color = if (isOutgoing) customColors.sentBubbleText else customColors.receivedBubbleText,
                lineHeight = 20.sp
            )

            // Status, Timestamp & Delivery Checkmarks
            Row(
                modifier = Modifier
                    .align(if (isOutgoing) Alignment.End else Alignment.Start)
                    .padding(top = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = timeFormat.format(Date(message.timestamp)),
                    style = MaterialTheme.typography.labelSmall,
                    color = if (isOutgoing) customColors.sentBubbleText.copy(alpha = 0.7f)
                    else customColors.textTertiary
                )

                if (isOutgoing) {
                    Spacer(modifier = Modifier.width(4.dp))
                    when (message.status) {
                        MessageStatus.DELIVERED -> {
                            Text(
                                text = "✓✓",
                                style = MaterialTheme.typography.labelSmall,
                                color = customColors.sentBubbleText
                            )
                        }
                        MessageStatus.SENT -> {
                            Text(
                                text = "✓",
                                style = MaterialTheme.typography.labelSmall,
                                color = customColors.sentBubbleText.copy(alpha = 0.8f)
                            )
                        }
                        MessageStatus.FAILED -> {
                            Text(
                                text = "⚠️ فشل",
                                style = MaterialTheme.typography.labelSmall,
                                color = WaslRoseReject
                            )
                        }
                        MessageStatus.SENDING, MessageStatus.QUEUED -> {
                            Text(
                                text = "⏳",
                                style = MaterialTheme.typography.labelSmall,
                                color = customColors.sentBubbleText.copy(alpha = 0.6f)
                            )
                        }
                        else -> {}
                    }
                }
            }
        }
    }
}
