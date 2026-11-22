package com.wasl.secure.presentation.chats.components

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.wasl.secure.core.theme.LocalWaslColors
import com.wasl.secure.core.theme.ThmanyahBlack
import com.wasl.secure.core.theme.WaslAmberPending
import com.wasl.secure.core.theme.WaslEmeraldActive
import com.wasl.secure.core.theme.WaslRoseReject
import com.wasl.secure.domain.model.Conversation
import com.wasl.secure.domain.model.HandshakeStatus
import kotlinx.coroutines.delay
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun ChatItemRow(
    conversation: Conversation,
    onClick: () -> Unit,
    onLongClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val customColors = LocalWaslColors.current

    // Reactive Countdown Timer for the 3-minute post-rejection cooldown
    var remainingCooldown by remember(conversation.rejectedAt) {
        mutableStateOf(conversation.remainingCooldownSeconds())
    }

    LaunchedEffect(conversation.rejectedAt, conversation.handshakeStatus) {
        if (conversation.handshakeStatus == HandshakeStatus.REJECTED) {
            while (remainingCooldown > 0) {
                delay(1000L)
                remainingCooldown = conversation.remainingCooldownSeconds()
            }
        }
    }

    Row(
        modifier = modifier
            .fillMaxWidth()
            .combinedClickable(
                onClick = onClick,
                onLongClick = onLongClick
            )
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        // Avatar with cryptographic status badge
        Box(contentAlignment = Alignment.BottomStart) {
            val firstLetter = conversation.contactName.firstOrNull()?.toString() ?: "و"
            Box(
                modifier = Modifier
                    .size(50.dp)
                    .clip(RoundedCornerShape(16.dp))
                    .background(customColors.sentBubble.copy(alpha = 0.15f)),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = firstLetter,
                    fontFamily = ThmanyahBlack,
                    fontSize = 18.sp,
                    color = customColors.sentBubble
                )
            }

            // Lock / Pending / Cooldown indicator badge
            val badgeColor = when (conversation.handshakeStatus) {
                HandshakeStatus.READY -> WaslEmeraldActive
                HandshakeStatus.WAITING, HandshakeStatus.NEW -> WaslAmberPending
                HandshakeStatus.REJECTED -> WaslRoseReject
                else -> Color.Gray
            }
            val badgeIcon = when (conversation.handshakeStatus) {
                HandshakeStatus.READY -> "🔒"
                HandshakeStatus.WAITING, HandshakeStatus.NEW -> "⏳"
                HandshakeStatus.REJECTED -> "✕"
                else -> "•"
            }

            Box(
                modifier = Modifier
                    .size(16.dp)
                    .clip(CircleShape)
                    .background(badgeColor),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = badgeIcon,
                    fontSize = 8.sp,
                    color = Color.White
                )
            }
        }

        Spacer(modifier = Modifier.width(14.dp))

        // Contact info & last message snippet
        Column(modifier = Modifier.weight(1f)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = conversation.contactName,
                    style = MaterialTheme.typography.titleMedium,
                    color = customColors.textPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )

                // Timestamp or Cooldown status
                if (conversation.handshakeStatus == HandshakeStatus.REJECTED && remainingCooldown > 0) {
                    val minutes = remainingCooldown / 60
                    val seconds = remainingCooldown % 60
                    Text(
                        text = String.format(Locale.getDefault(), "%02d:%02d", minutes, seconds),
                        style = MaterialTheme.typography.labelSmall,
                        color = WaslRoseReject
                    )
                } else if (conversation.lastMessageTimestamp > 0) {
                    val timeFormat = remember { SimpleDateFormat("h:mm a", Locale.getDefault()) }
                    Text(
                        text = timeFormat.format(Date(conversation.lastMessageTimestamp)),
                        style = MaterialTheme.typography.labelSmall,
                        color = customColors.textTertiary
                    )
                }
            }

            Spacer(modifier = Modifier.height(4.dp))

            // Subtitle / Snippet
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                val snippetText = when (conversation.handshakeStatus) {
                    HandshakeStatus.READY -> conversation.lastMessage ?: "محادثة مشفرة جديدة"
                    HandshakeStatus.WAITING -> "طلب تأسيس محادثة مشفرة عبر SMS (بانتظار الرد)..."
                    HandshakeStatus.REJECTED -> {
                        if (remainingCooldown > 0) "تم رفض الطلب. انتظر انقضاء المهلة لإعادة الإرسال"
                        else "تم رفض الطلب. يمكنك الآن إرسال طلب جديد"
                    }
                    HandshakeStatus.EXPIRED -> "انتهت مهلة الطلب (24 ساعة). اضغط لإعادة الإرسال"
                    else -> "محادثة مشفرة"
                }

                Text(
                    text = snippetText,
                    style = MaterialTheme.typography.bodySmall,
                    color = when (conversation.handshakeStatus) {
                        HandshakeStatus.WAITING -> WaslAmberPending
                        HandshakeStatus.REJECTED -> WaslRoseReject.copy(alpha = 0.8f)
                        else -> customColors.textSecondary
                    },
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )

                if (conversation.handshakeStatus == HandshakeStatus.READY) {
                    Text(
                        text = "✓✓",
                        style = MaterialTheme.typography.labelSmall,
                        color = customColors.sentBubble,
                        modifier = Modifier.padding(start = 6.dp)
                    )
                }
            }
        }
    }
}
