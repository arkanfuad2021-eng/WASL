package com.wasl.secure

import android.app.Application
import com.wasl.secure.core.crypto.IdentityManager
import com.wasl.secure.core.crypto.KeystoreManager
import com.wasl.secure.core.protocol.HandshakeManager
import com.wasl.secure.data.local.DatabaseSecurityManager
import com.wasl.secure.data.local.WaslDatabase
import com.wasl.secure.telephony.MessageChunkManager
import com.wasl.secure.telephony.SimCardManager
import com.wasl.secure.telephony.WaslSmsSender
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import net.sqlcipher.database.SQLiteDatabase

class WaslApplication : Application() {

    lateinit var database: WaslDatabase
        private set

    lateinit var keystoreManager: KeystoreManager
        private set

    lateinit var identityManager: IdentityManager
        private set

    lateinit var databaseSecurityManager: DatabaseSecurityManager
        private set

    lateinit var handshakeManager: HandshakeManager
        private set

    lateinit var simCardManager: SimCardManager
        private set

    lateinit var smsSender: WaslSmsSender
        private set

    var isSecurityLockdown: Boolean = false
        private set

    override fun onCreate() {
        super.onCreate()

        // 1. Initialize SQLCipher native cryptographic binaries
        SQLiteDatabase.loadLibs(this)

        // 2. Initialize Android Keystore master envelope manager
        keystoreManager = KeystoreManager()

        // 3. Initialize identity manager and verify key integrity
        identityManager = IdentityManager(this, keystoreManager)
        if (!identityManager.isHealthy()) {
            isSecurityLockdown = true
        }

        handshakeManager = HandshakeManager(identityManager)

        // 4. Initialize secure database using Keystore-wrapped DEK (No hardcoded passphrases)
        databaseSecurityManager = DatabaseSecurityManager(this, keystoreManager)
        val dek = databaseSecurityManager.getOrResolveDatabaseKey()
        database = WaslDatabase.getInstance(this, dek)

        // 5. Initialize SIM and Telephony SMS services
        simCardManager = SimCardManager(this, database)
        smsSender = WaslSmsSender(this, database)

        // 6. Purge abandoned message chunks older than 24 hours on startup
        CoroutineScope(Dispatchers.IO).launch {
            try {
                database.messageChunkDao().deleteExpiredChunks(
                    System.currentTimeMillis() - MessageChunkManager.CHUNK_EXPIRY_MS
                )
            } catch (_: Exception) {
            }
        }
    }
}
