package com.wasl.secure.core.util

/**
 * Utility functions for handling, normalizing, and formatting Yemeni phone numbers.
 * Enforces the strict +967xxxxxxxxx format.
 */
object YemenPhoneUtils {

    const val COUNTRY_CODE = "+967"
    private const val PREFIX_WITH_PLUS = "+967"
    private const val PREFIX_WITH_ZEROS = "00967"

    /**
     * Normalizes an input phone number string into the strict Yemeni format: +967xxxxxxxxx
     */
    fun normalize(input: String): String {
        val trimmed = input.trim().replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
        if (trimmed.isEmpty()) return ""

        val digitsOnly = trimmed.replace("+", "")

        return when {
            // Already starts with +967
            trimmed.startsWith(PREFIX_WITH_PLUS) -> {
                val sub = digitsOnly.substring(3)
                PREFIX_WITH_PLUS + sub.take(9)
            }
            // Starts with 00967
            trimmed.startsWith(PREFIX_WITH_ZEROS) -> {
                val sub = digitsOnly.substring(5)
                PREFIX_WITH_PLUS + sub.take(9)
            }
            // Starts with 07xxxxxxx (10 digits)
            digitsOnly.startsWith("07") && digitsOnly.length >= 10 -> {
                PREFIX_WITH_PLUS + digitsOnly.substring(1).take(9)
            }
            // Starts with 7xxxxxxx (9 digits)
            digitsOnly.startsWith("7") && digitsOnly.length >= 9 -> {
                PREFIX_WITH_PLUS + digitsOnly.take(9)
            }
            // Fallback: if already starts with +, keep it; otherwise prepend +967
            trimmed.startsWith("+") -> trimmed
            else -> PREFIX_WITH_PLUS + digitsOnly.take(9)
        }
    }

    /**
     * Extracts the last 9 digits to ensure matching incoming SMS numbers from any carrier.
     */
    fun extractComparableKey(phone: String): String {
        val digits = phone.filter { it.isDigit() }
        return if (digits.length >= 9) {
            digits.takeLast(9)
        } else {
            digits
        }
    }

    /**
     * Checks if the number is a valid 9-digit Yemeni mobile number (+967xxxxxxxxx).
     */
    fun isValidYemenMobile(phone: String): Boolean {
        val norm = normalize(phone)
        val regex = Regex("""^\+967[7][0-9]{8}$""")
        return regex.matches(norm)
    }
}
