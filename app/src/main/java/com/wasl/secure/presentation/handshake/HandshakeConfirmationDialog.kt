package com.wasl.secure.presentation.handshake

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.wasl.secure.R
import com.wasl.secure.core.theme.LocalWaslColors
import com.wasl.secure.core.theme.ThmanyahBlack

/**
 * Confirmation dialog shown before executing a handshake rejection,
 * strictly fulfilling the approved decision in Section 5 (Clause 5).
 */
@Composable
fun HandshakeRejectionConfirmationDialog(
    contactName: String,
    onConfirmReject: () -> Unit,
    onDismiss: () -> Unit
) {
    val customColors = LocalWaslColors.current

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = stringResource(R.string.confirm_reject_title),
                fontFamily = ThmanyahBlack,
                color = customColors.textPrimary
            )
        },
        text = {
            Text(
                text = "هل أنت متأكد من رفض طلب تأسيس المحادثة المشفرة من \"$contactName\"؟ سيتم إشعار الطرف الآخر بالرفض ولن يتمكن من إرسال طلب جديد إلا بعد مرور 3 دقائق.",
                style = MaterialTheme.typography.bodyMedium,
                color = customColors.textSecondary
            )
        },
        confirmButton = {
            TextButton(onClick = onConfirmReject) {
                Text(
                    text = stringResource(R.string.reject_button),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.labelLarge
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
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
