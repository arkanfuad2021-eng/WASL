package com.wasl.secure.telephony

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.telephony.SubscriptionInfo
import android.telephony.SubscriptionManager
import androidx.core.content.ContextCompat
import com.wasl.secure.data.local.WaslDatabase
import com.wasl.secure.domain.model.SimInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Manages dual-SIM discovery, system defaults, and per-conversation SIM routing.
 * Conforms to Section 9 of the Master Specification.
 */
class SimCardManager(
    private val context: Context,
    private val database: WaslDatabase
) {
    private val subscriptionManager: SubscriptionManager? by lazy {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            context.getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE) as? SubscriptionManager
        } else {
            null
        }
    }

    /**
     * Checks if the app currently has permission to read cellular SIM state.
     */
    fun hasPhoneStatePermission(): Boolean {
        return ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.READ_PHONE_STATE
        ) == PackageManager.PERMISSION_GRANTED
    }

    /**
     * Queries Android SubscriptionManager to retrieve all active cellular SIMs.
     * Returns empty list if no permission or no active SIMs found.
     */
    @SuppressLint("MissingPermission")
    fun getActiveSimCards(): List<SimInfo> {
        if (!hasPhoneStatePermission() || subscriptionManager == null) {
            return emptyList()
        }

        return try {
            val subInfoList = subscriptionManager?.activeSubscriptionInfoList ?: return emptyList()
            val defaultSmsSubId = getDefaultSmsSubscriptionId()

            subInfoList.map { info ->
                mapSubscriptionInfoToSimInfo(info, defaultSmsSubId)
            }
        } catch (e: Exception) {
            emptyList()
        }
    }

    /**
     * Returns true if the phone has 2 or more active cellular SIM cards.
     */
    fun isMultiSimDevice(): Boolean {
        return getActiveSimCards().size > 1
    }

    /**
     * Gets the system-wide default SMS subscription ID configured in Android settings.
     */
    fun getDefaultSmsSubscriptionId(): Int {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            val subId = SubscriptionManager.getDefaultSmsSubscriptionId()
            if (subId != SubscriptionManager.INVALID_SUBSCRIPTION_ID) {
                return subId
            }
        }
        return -1
    }

    /**
     * Resolves which SIM to use for a conversation following the agreed robust hierarchy:
     * 1. Saved conversation default SIM.
     * 2. System default SMS SIM.
     * 3. First available active SIM.
     */
    suspend fun resolveEffectiveSimForConversation(conversationId: String): Int = withContext(Dispatchers.IO) {
        // 1. Check saved conversation SIM in database
        val conv = database.conversationDao().getConversationById(conversationId)
        val savedSubId = conv?.defaultSubscriptionId

        val activeSims = getActiveSimCards()
        if (activeSims.isEmpty()) {
            return@withContext -1 // Fallback to default SmsManager
        }

        // If saved SIM is still active, use it
        if (savedSubId != null && activeSims.any { it.subscriptionId == savedSubId }) {
            return@withContext savedSubId
        }

        // 2. Check system default SMS SIM
        val systemDefaultSubId = getDefaultSmsSubscriptionId()
        if (systemDefaultSubId != -1 && activeSims.any { it.subscriptionId == systemDefaultSubId }) {
            // Persist as default for this thread
            database.conversationDao().updateDefaultSim(conversationId, systemDefaultSubId)
            return@withContext systemDefaultSubId
        }

        // 3. Fallback to first available active SIM
        val firstActiveSubId = activeSims.first().subscriptionId
        database.conversationDao().updateDefaultSim(conversationId, firstActiveSubId)
        return@withContext firstActiveSubId
    }

    /**
     * Updates and pins the selected SIM card for a conversation.
     * Rule: Changes ONLY transmission routing; NEVER alters cryptographic keys.
     */
    suspend fun setConversationSimPreference(conversationId: String, subscriptionId: Int) = withContext(Dispatchers.IO) {
        database.conversationDao().updateDefaultSim(conversationId, subscriptionId)
    }

    private fun mapSubscriptionInfoToSimInfo(info: SubscriptionInfo, defaultSmsSubId: Int): SimInfo {
        val slotIdx = info.simSlotIndex
        val subId = info.subscriptionId

        val defaultDisplayName = "SIM ${slotIdx + 1}"
        val displayName = info.displayName?.toString()?.takeIf { it.isNotBlank() } ?: defaultDisplayName
        val carrierName = info.carrierName?.toString()?.takeIf { it.isNotBlank() } ?: "شبكة خلوية"

        return SimInfo(
            subscriptionId = subId,
            slotIndex = slotIdx,
            displayName = displayName,
            carrierName = carrierName,
            isDefaultSms = (subId == defaultSmsSubId)
        )
    }
}
