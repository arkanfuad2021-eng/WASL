package com.wasl.secure.telephony

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.wasl.secure.MainActivity
import com.wasl.secure.R

class NotificationHelper(private val context: Context) {

    companion object {
        const val CHANNEL_ID = "wasl_encrypted_messages_channel"
        const val CHANNEL_NAME = "رسائل WASL المشفرة"
    }

    private val notificationManager =
        context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    init {
        createNotificationChannel()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "إشعارات الرسائل المشفرة المستلمة عبر SMS"
                enableLights(true)
                enableVibration(true)
            }
            notificationManager.createNotificationChannel(channel)
        }
    }

    /**
     * Posts a notification for an incoming decrypted message.
     * @param hideContent If true, masks the message preview for lock screen privacy.
     */
    fun showIncomingMessageNotification(
        conversationId: String,
        senderName: String,
        decryptedContent: String,
        hideContent: Boolean = false
    ) {
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            putExtra("conversationId", conversationId)
        }

        val pendingIntent = PendingIntent.getActivity(
            context,
            conversationId.hashCode(),
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val displayText = if (hideContent) {
            "رسالة مشفرة جديدة"
        } else {
            decryptedContent
        }

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification_wasl)
            .setContentTitle(senderName)
            .setContentText(displayText)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        notificationManager.notify(conversationId.hashCode(), notification)
    }

    /**
     * Dismisses any active notification for a conversation once the user opens it.
     */
    fun cancelConversationNotification(conversationId: String) {
        notificationManager.cancel(conversationId.hashCode())
    }
}
