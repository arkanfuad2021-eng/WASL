package com.wasl.secure.presentation.conversation.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.RadioButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.wasl.secure.R
import com.wasl.secure.core.theme.LocalWaslColors
import com.wasl.secure.core.theme.ThmanyahBlack
import com.wasl.secure.domain.model.SimInfo

@Composable
fun SimSelectionDialog(
    availableSims: List<SimInfo>,
    selectedSubId: Int?,
    onSimSelected: (Int) -> Unit,
    onDismiss: () -> Unit
) {
    val customColors = LocalWaslColors.current

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = stringResource(R.string.select_sim_title),
                fontFamily = ThmanyahBlack,
                color = customColors.textPrimary
            )
        },
        text = {
            Column(modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = stringResource(R.string.select_sim_desc),
                    style = MaterialTheme.typography.bodyMedium,
                    color = customColors.textSecondary
                )
                Spacer(modifier = Modifier.height(14.dp))

                availableSims.forEach { sim ->
                    val isSelected = sim.subscriptionId == selectedSubId

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(12.dp))
                            .background(
                                if (isSelected) customColors.sentBubble.copy(alpha = 0.12f)
                                else MaterialTheme.colorScheme.surface
                            )
                            .clickable {
                                onSimSelected(sim.subscriptionId)
                                onDismiss()
                            }
                            .padding(horizontal = 12.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = isSelected,
                            onClick = {
                                onSimSelected(sim.subscriptionId)
                                onDismiss()
                            },
                            colors = RadioButtonDefaults.colors(
                                selectedColor = customColors.sentBubble
                            )
                        )

                        Spacer(modifier = Modifier.width(8.dp))

                        Column {
                            Text(
                                text = sim.displayName,
                                style = MaterialTheme.typography.titleMedium,
                                color = customColors.textPrimary
                            )
                            Text(
                                text = "${sim.carrierName} (فتحة الشريحة ${sim.slotIndex + 1})",
                                style = MaterialTheme.typography.bodySmall,
                                color = customColors.textTertiary
                            )
                        }
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                }
            }
        },
        confirmButton = {},
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
