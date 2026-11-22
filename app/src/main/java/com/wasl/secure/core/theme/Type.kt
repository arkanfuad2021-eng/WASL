package com.wasl.secure.core.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.wasl.secure.R

// Font families configured strictly according to the WASL specification document
val ThmanyahBlack = FontFamily(
    Font(R.font.thmanyah_black, FontWeight.Black)
)

val ThmanyahMedium = FontFamily(
    Font(R.font.thmanyah_medium, FontWeight.Medium)
)

val WaslTypography = Typography(
    displayLarge = TextStyle(
        fontFamily = ThmanyahBlack,
        fontWeight = FontWeight.Black,
        fontSize = 30.sp,
        lineHeight = 38.sp
    ),
    displayMedium = TextStyle(
        fontFamily = ThmanyahBlack,
        fontWeight = FontWeight.Black,
        fontSize = 24.sp,
        lineHeight = 32.sp
    ),
    headlineMedium = TextStyle(
        fontFamily = ThmanyahBlack,
        fontWeight = FontWeight.Black,
        fontSize = 20.sp,
        lineHeight = 28.sp
    ),
    titleLarge = TextStyle(
        fontFamily = ThmanyahBlack,
        fontWeight = FontWeight.Black,
        fontSize = 18.sp,
        lineHeight = 24.sp
    ),
    titleMedium = TextStyle(
        fontFamily = ThmanyahBlack,
        fontWeight = FontWeight.Black,
        fontSize = 16.sp,
        lineHeight = 22.sp
    ),
    bodyLarge = TextStyle(
        fontFamily = ThmanyahMedium,
        fontWeight = FontWeight.Medium,
        fontSize = 15.sp,
        lineHeight = 22.sp
    ),
    bodyMedium = TextStyle(
        fontFamily = ThmanyahMedium,
        fontWeight = FontWeight.Medium,
        fontSize = 14.sp,
        lineHeight = 20.sp
    ),
    bodySmall = TextStyle(
        fontFamily = ThmanyahMedium,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 16.sp
    ),
    labelLarge = TextStyle(
        fontFamily = ThmanyahMedium,
        fontWeight = FontWeight.Medium,
        fontSize = 13.sp,
        lineHeight = 18.sp
    ),
    labelSmall = TextStyle(
        fontFamily = ThmanyahMedium,
        fontWeight = FontWeight.Normal,
        fontSize = 11.sp,
        lineHeight = 14.sp
    )
)
