package com.wasl.secure.core.preferences

import android.content.Context
import android.content.SharedPreferences

/**
 * Persists user-facing UI, theme, SIM default, and notification privacy preferences locally.
 * Intentionally stored separately from cryptographic key vaults and excluded from device backups.
 */
class WaslPreferences(context: Context) {

    companion object {
        const val PREFS_NAME = "wasl_ui_settings_prefs"

        private const val KEY_IS_DARK_THEME = "is_dark_theme"
        private const val KEY_WARN_HIGH_SMS_PARTS = "warn_high_sms_parts"
        private const val KEY_HIDE_NOTIFICATION_CONTENT = "hide_notification_content"
        private const val KEY_DEFAULT_GLOBAL_SUB_ID = "default_global_sub_id"

        const val DEFAULT_IS_DARK_THEME = true
        const val DEFAULT_WARN_HIGH_SMS_PARTS = true
        const val DEFAULT_HIDE_NOTIFICATION_CONTENT = false
        const val DEFAULT_GLOBAL_SUB_ID = -1
    }

    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun isDarkTheme(): Boolean =
        prefs.getBoolean(KEY_IS_DARK_THEME, DEFAULT_IS_DARK_THEME)

    fun setDarkTheme(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_IS_DARK_THEME, enabled).apply()
    }

    fun isWarnHighSmsPartsEnabled(): Boolean =
        prefs.getBoolean(KEY_WARN_HIGH_SMS_PARTS, DEFAULT_WARN_HIGH_SMS_PARTS)

    fun setWarnHighSmsPartsEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_WARN_HIGH_SMS_PARTS, enabled).apply()
    }

    fun isHideNotificationContentEnabled(): Boolean =
        prefs.getBoolean(KEY_HIDE_NOTIFICATION_CONTENT, DEFAULT_HIDE_NOTIFICATION_CONTENT)

    fun setHideNotificationContentEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_HIDE_NOTIFICATION_CONTENT, enabled).apply()
    }

    fun getDefaultGlobalSubId(): Int =
        prefs.getInt(KEY_DEFAULT_GLOBAL_SUB_ID, DEFAULT_GLOBAL_SUB_ID)

    fun setDefaultGlobalSubId(subscriptionId: Int) {
        prefs.edit().putInt(KEY_DEFAULT_GLOBAL_SUB_ID, subscriptionId).apply()
    }
}
