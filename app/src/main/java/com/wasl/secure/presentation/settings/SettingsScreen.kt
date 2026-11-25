package com.wasl.secure.presentation.settings

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
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
import androidx.compose.material3.Divider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.wasl.secure.R
import com.wasl.secure.core.theme.LocalWaslColors
import com.wasl.secure.core.theme.ThmanyahBlack
import com.wasl.secure.core.theme.WaslAmberPending
import com.wasl.secure.core.theme.WaslEmeraldActive
import com.wasl.secure.domain.model.SimInfo
import com.wasl.secure.presentation.conversation.components.SimSelectionDialog

/**
 * Application settings screen covering theme mode, default SMS SIM routing,
 * high-part warning toggle, notification content privacy, permissions, and app info.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    isDarkTheme: Boolean,
    warnHighSmsParts: Boolean,
    hideNotificationContent: Boolean,
    defaultGlobalSubId: Int,
    availableSims: List<SimInfo>,
    allPermissionsGranted: Boolean,
    onBackClick: () -> Unit,
    onDarkThemeChange: (Boolean) -> Unit,
    onWarnHighSmsPartsChange: (Boolean) -> Unit,
    onHideNotificationContentChange: (Boolean) -> Unit,
    onSelectGlobalSim: (Int) -> Unit,
    onRequestPermissionsClick: () -> Unit
) {
    val context = LocalContext.current
    val customColors = LocalWaslColors.current
    var showSimDialog by remember { mutableStateOf(false) }

    val sectionHeaderColor = if (isDarkTheme) Color(0xFF2DD4BF) else customColors.sentBubble
    val activeSim = remember(availableSims, defaultGlobalSubId) {
        availableSims.find { it.subscriptionId == defaultGlobalSubId }
            ?: availableSims.find { it.isDefaultSms }
            ?: availableSims.firstOrNull()
    }
    val simBadgeText = if (activeSim != null) {
        "${activeSim.carrierName} • ${activeSim.displayName}"
    } else {
        "افتراضي النظام"
    }

    Scaffold(
        contentWindowInsets = WindowInsets.statusBars,
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "الإعدادات",
                        fontFamily = ThmanyahBlack,
                        fontSize = 19.sp,
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
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // 1. Appearance Section
            SettingsSection(title = "المظهر", titleColor = sectionHeaderColor) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "ثيم التطبيق",
                            fontFamily = ThmanyahBlack,
                            fontSize = 14.sp,
                            color = customColors.textPrimary
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = "التبديل بين النهاري والليلي",
                            style = MaterialTheme.typography.bodySmall,
                            color = customColors.textSecondary
                        )
                    }
                    Spacer(modifier = Modifier.width(10.dp))
                    ThemeSegmentedToggle(
                        isDarkTheme = isDarkTheme,
                        onSelectTheme = onDarkThemeChange
                    )
                }
            }

            // 2. Multi-SIM & SMS Section
            SettingsSection(title = "تعدد الشرائح ورسائل SMS", titleColor = sectionHeaderColor) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable {
                            if (availableSims.isNotEmpty()) {
                                showSimDialog = true
                            } else {
                                Toast.makeText(context, "لم يتم اكتشاف شرائح SIM نشطة", Toast.LENGTH_SHORT).show()
                            }
                        }
                        .padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "الشريحة الافتراضية",
                            fontFamily = ThmanyahBlack,
                            fontSize = 14.sp,
                            color = customColors.textPrimary
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = "للمحادثات الجديدة قبل التخصيص",
                            style = MaterialTheme.typography.bodySmall,
                            color = customColors.textSecondary
                        )
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(10.dp))
                            .background(customColors.sentBubble.copy(alpha = if (isDarkTheme) 0.25f else 0.1f))
                            .border(
                                width = 1.dp,
                                color = if (isDarkTheme) Color(0xFF134E4A) else Color.Transparent,
                                shape = RoundedCornerShape(10.dp)
                            )
                            .padding(horizontal = 10.dp, vertical = 5.dp)
                    ) {
                        Text(
                            text = simBadgeText,
                            style = MaterialTheme.typography.labelSmall,
                            color = sectionHeaderColor,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }

                Divider(color = customColors.divider, thickness = 0.75.dp)

                SettingsSwitchRow(
                    title = "تنبيه استهلاك الأجزاء",
                    subtitle = "تحذير عند تجاوز 10 أجزاء SMS",
                    checked = warnHighSmsParts,
                    isDarkTheme = isDarkTheme,
                    onCheckedChange = onWarnHighSmsPartsChange
                )
            }

            // 3. Privacy & Notifications Section
            SettingsSection(title = "الخصوصية والإشعارات", titleColor = sectionHeaderColor) {
                SettingsSwitchRow(
                    title = "إخفاء محتوى الإشعارات",
                    subtitle = "عرض \"رسالة مشفرة جديدة\" فقط",
                    checked = hideNotificationContent,
                    isDarkTheme = isDarkTheme,
                    onCheckedChange = onHideNotificationContentChange
                )

                Divider(color = customColors.divider, thickness = 0.75.dp)

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable(onClick = onRequestPermissionsClick)
                        .padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "أذونات التطبيق",
                            fontFamily = ThmanyahBlack,
                            fontSize = 14.sp,
                            color = customColors.textPrimary
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = "SMS + Phone + Contacts (صفر إنترنت)",
                            style = MaterialTheme.typography.bodySmall,
                            color = customColors.textSecondary
                        )
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = if (allPermissionsGranted) "مكتملة" else "تفعيل",
                        fontFamily = ThmanyahBlack,
                        fontSize = 12.sp,
                        color = if (allPermissionsGranted) customColors.securityBadgeText else WaslAmberPending
                    )
                }
            }

            // 4. About Section
            SettingsSection(title = "حول التطبيق", titleColor = sectionHeaderColor) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Preserve high contrast around dark-navy logo strokes across both themes
                    Box(
                        modifier = Modifier
                            .size(68.dp)
                            .clip(RoundedCornerShape(16.dp))
                            .background(if (isDarkTheme) Color(0xFFF1F5F9) else Color(0xFFF8FAFC))
                            .border(1.dp, customColors.divider, RoundedCornerShape(16.dp))
                            .padding(6.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Image(
                            painter = painterResource(id = R.drawable.wasl_logo_mark),
                            contentDescription = "شعار تطبيق وَصْل",
                            modifier = Modifier.fillMaxSize(),
                            contentScale = ContentScale.Fit
                        )
                    }

                    Spacer(modifier = Modifier.width(12.dp))

                    Column(modifier = Modifier.weight(1f)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text(
                                text = "تطبيق وَصْل | WASL",
                                fontFamily = ThmanyahBlack,
                                fontSize = 14.sp,
                                color = customColors.textPrimary
                            )
                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(8.dp))
                                    .background(customColors.sentBubble.copy(alpha = if (isDarkTheme) 0.25f else 0.1f))
                                    .border(
                                        width = 1.dp,
                                        color = if (isDarkTheme) Color(0xFF134E4A) else Color.Transparent,
                                        shape = RoundedCornerShape(8.dp)
                                    )
                                    .padding(horizontal = 8.dp, vertical = 3.dp)
                            ) {
                                Text(
                                    text = "الإصدار 1.0",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = sectionHeaderColor
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(6.dp))

                        Text(
                            text = "مراسلة نصية مشفرة طرفاً لطرف عبر شبكة SMS دون الحاجة للإنترنت.",
                            style = MaterialTheme.typography.bodySmall,
                            color = customColors.textSecondary,
                            lineHeight = 18.sp
                        )
                    }
                }
            }
        }
    }

    if (showSimDialog) {
        SimSelectionDialog(
            availableSims = availableSims,
            selectedSubId = activeSim?.subscriptionId,
            onSimSelected = { subId ->
                onSelectGlobalSim(subId)
                showSimDialog = false
            },
            onDismiss = { showSimDialog = false }
        )
    }
}

@Composable
private fun SettingsSection(
    title: String,
    titleColor: Color,
    content: @Composable ColumnScope.() -> Unit
) {
    val customColors = LocalWaslColors.current
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = title,
            fontFamily = ThmanyahBlack,
            fontSize = 12.sp,
            color = titleColor,
            modifier = Modifier.padding(horizontal = 4.dp, vertical = 6.dp)
        )
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            color = MaterialTheme.colorScheme.surface,
            border = BorderStroke(1.dp, customColors.divider)
        ) {
            Column(modifier = Modifier.fillMaxWidth(), content = content)
        }
    }
}

@Composable
private fun ThemeSegmentedToggle(
    isDarkTheme: Boolean,
    onSelectTheme: (Boolean) -> Unit
) {
    val customColors = LocalWaslColors.current
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(12.dp))
            .background(
                if (isDarkTheme) MaterialTheme.colorScheme.background
                else Color(0xFFF1F5F9)
            )
            .border(1.dp, customColors.divider, RoundedCornerShape(12.dp))
            .padding(3.dp),
        horizontalArrangement = Arrangement.spacedBy(2.dp)
    ) {
        val lightSelected = !isDarkTheme
        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(9.dp))
                .background(if (lightSelected) Color.White else Color.Transparent)
                .clickable { if (isDarkTheme) onSelectTheme(false) }
                .padding(horizontal = 12.dp, vertical = 6.dp),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = "نهاري",
                fontFamily = ThmanyahBlack,
                fontSize = 12.sp,
                color = if (lightSelected) customColors.sentBubble else customColors.textSecondary
            )
        }
        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(9.dp))
                .background(if (isDarkTheme) customColors.sentBubble else Color.Transparent)
                .clickable { if (!isDarkTheme) onSelectTheme(true) }
                .padding(horizontal = 12.dp, vertical = 6.dp),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = "ليلي",
                fontFamily = ThmanyahBlack,
                fontSize = 12.sp,
                color = if (isDarkTheme) Color.White else customColors.textSecondary
            )
        }
    }
}

@Composable
private fun SettingsSwitchRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    isDarkTheme: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    val customColors = LocalWaslColors.current
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onCheckedChange(!checked) }
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                fontFamily = ThmanyahBlack,
                fontSize = 14.sp,
                color = customColors.textPrimary
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = customColors.textSecondary
            )
        }
        Spacer(modifier = Modifier.width(8.dp))
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = Color.White,
                checkedTrackColor = if (isDarkTheme) WaslEmeraldActive else customColors.sentBubble,
                uncheckedThumbColor = customColors.textSecondary,
                uncheckedTrackColor = MaterialTheme.colorScheme.background
            )
        )
    }
}
