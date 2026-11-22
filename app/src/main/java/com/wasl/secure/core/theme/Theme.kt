package com.wasl.secure.core.theme

import android.app.Activity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

@Immutable
data class WaslCustomColors(
    val sentBubble: Color,
    val sentBubbleText: Color,
    val receivedBubble: Color,
    val receivedBubbleText: Color,
    val securityBadgeBackground: Color,
    val securityBadgeText: Color,
    val securityBadgeBorder: Color,
    val inputBackground: Color,
    val inputBorder: Color,
    val textPrimary: Color,
    val textSecondary: Color,
    val textTertiary: Color,
    val divider: Color
)

val LocalWaslColors = staticCompositionLocalOf {
    WaslCustomColors(
        sentBubble = WaslTealDark,
        sentBubbleText = Color.White,
        receivedBubble = DarkBubbleReceived,
        receivedBubbleText = DarkBubbleReceivedText,
        securityBadgeBackground = Color(0xFF162529),
        securityBadgeText = WaslEmeraldActive,
        securityBadgeBorder = Color(0xFF134E4A),
        inputBackground = DarkInputBackground,
        inputBorder = DarkInputBorder,
        textPrimary = DarkTextPrimary,
        textSecondary = DarkTextSecondary,
        textTertiary = DarkTextTertiary,
        divider = DarkDivider
    )
}

private val DarkColorScheme = darkColorScheme(
    primary = WaslTealPrimary,
    onPrimary = Color.White,
    background = DarkScreenBackground,
    onBackground = DarkTextPrimary,
    surface = DarkSurfaceCard,
    onSurface = DarkTextPrimary,
    surfaceVariant = DarkAppBar,
    onSurfaceVariant = DarkTextSecondary,
    outline = DarkDivider
)

private val LightColorScheme = lightColorScheme(
    primary = WaslTealPrimary,
    onPrimary = Color.White,
    background = LightScreenBackground,
    onBackground = LightTextPrimary,
    surface = LightSurfaceCard,
    onSurface = LightTextPrimary,
    surfaceVariant = LightAppBar,
    onSurfaceVariant = LightTextSecondary,
    outline = LightDivider
)

@Composable
fun WaslTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme

    val customColors = if (darkTheme) {
        WaslCustomColors(
            sentBubble = WaslTealDark,
            sentBubbleText = Color.White,
            receivedBubble = DarkBubbleReceived,
            receivedBubbleText = DarkBubbleReceivedText,
            securityBadgeBackground = Color(0xFF162529),
            securityBadgeText = Color(0xFF34D399),
            securityBadgeBorder = Color(0xFF134E4A),
            inputBackground = DarkInputBackground,
            inputBorder = DarkInputBorder,
            textPrimary = DarkTextPrimary,
            textSecondary = DarkTextSecondary,
            textTertiary = DarkTextTertiary,
            divider = DarkDivider
        )
    } else {
        WaslCustomColors(
            sentBubble = WaslTealLight,
            sentBubbleText = Color.White,
            receivedBubble = LightBubbleReceived,
            receivedBubbleText = LightBubbleReceivedText,
            securityBadgeBackground = Color(0xFFF0FDF4),
            securityBadgeText = Color(0xFF059669),
            securityBadgeBorder = Color(0xFFA7F3D0),
            inputBackground = LightInputBackground,
            inputBorder = LightInputBorder,
            textPrimary = LightTextPrimary,
            textSecondary = LightTextSecondary,
            textTertiary = LightTextTertiary,
            divider = LightDivider
        )
    }

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = colorScheme.background.toArgb()
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = !darkTheme
        }
    }

    CompositionLocalProvider(LocalWaslColors provides customColors) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = WaslTypography,
            content = content
        )
    }
}
