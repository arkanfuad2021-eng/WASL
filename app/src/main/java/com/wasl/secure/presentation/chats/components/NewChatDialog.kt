package com.wasl.secure.presentation.chats.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.wasl.secure.core.theme.LocalWaslColors
import com.wasl.secure.core.theme.ThmanyahBlack
import com.wasl.secure.core.util.YemenPhoneUtils

@Composable
fun NewChatDialog(
    onDismiss: () -> Unit,
    onPickFromContacts: () -> Unit,
    onStartChat: (name: String, phone: String) -> Unit
) {
    val customColors = LocalWaslColors.current
    var name by remember { mutableStateOf("") }
    var rawPhone by remember { mutableStateOf("+967") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "بدء محادثة مشفرة جديدة",
                fontFamily = ThmanyahBlack,
                color = customColors.textPrimary
            )
        },
        text = {
            Column(modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = "اختر جهة اتصال من هاتفك أو أدخل الرقم المباشر بالصيغة اليمنية (+967xxxxxxxxx):",
                    style = MaterialTheme.typography.bodySmall,
                    color = customColors.textSecondary
                )

                Spacer(modifier = Modifier.height(14.dp))

                OutlinedButton(
                    onClick = onPickFromContacts,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Text(
                        text = "📖 اختيار من جهات الاتصال",
                        style = MaterialTheme.typography.labelLarge,
                        color = customColors.sentBubble
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = "أو أدخل البيانات يدوياً:",
                    style = MaterialTheme.typography.labelSmall,
                    color = customColors.textTertiary
                )

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("اسم جهة الاتصال (اختياري)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                )

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = rawPhone,
                    onValueChange = { input ->
                        // Only allow digits and leading plus
                        val filtered = input.filter { it.isDigit() || it == '+' }
                        rawPhone = filtered
                    },
                    label = { Text("رقم الهاتف") },
                    placeholder = { Text("+967xxxxxxxxx") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp)
                )
            }
        },
        confirmButton = {
            val normalizedPhone = YemenPhoneUtils.normalize(rawPhone)
            val isValid = normalizedPhone.length >= 10

            Button(
                onClick = {
                    if (isValid) {
                        val effectiveName = if (name.isNotBlank()) name else normalizedPhone
                        onStartChat(effectiveName, normalizedPhone)
                        onDismiss()
                    }
                },
                enabled = isValid,
                colors = ButtonDefaults.buttonColors(
                    containerColor = customColors.sentBubble
                )
            ) {
                Text("بدء المحادثة")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(
                    text = "إلغاء",
                    color = customColors.textPrimary
                )
            }
        },
        containerColor = MaterialTheme.colorScheme.surface
    )
}
