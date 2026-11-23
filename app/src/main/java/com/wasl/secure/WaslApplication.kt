package com.wasl.secure

import android.app.Application
import com.wasl.secure.core.crypto.IdentityManager
import com.wasl.secure.core.crypto.KeystoreManager
import com.wasl.secure.core.protocol.HandshakeManager
import com.wasl.secure.data.local.WaslDatabase
import com.wasl.secure.telephony.SimCardManager
import com.wasl.secure.telephony.WaslSmsSender
import net.sqlcipher.database.SQLiteDatabase

class WaslApplication : Application() {

    lateinit var database: WaslDatabase
        private set

    lateinit var keystoreManager: KeystoreManager
        private set

    lateinit var identityManager: IdentityManager
        private set

    lateinit var handshakeManager: HandshakeManager
        private set

    lateinit var simCardManager: SimCardManager
        private set

    lateinit var smsSender: WaslSmsSender
        private set

    override fun onCreate() {
        super.onCreate()

        // 1. Initialize SQLCipher native cryptographic libraries
        SQLiteDatabase.loadLibs(this)

        // 2. Initialize Android Keystore master envelope manager
        keystoreManager = KeystoreManager()

        // 3. Initialize identity and handshake protocol engines
        identityManager = IdentityManager(this, keystoreManager)
        handshakeManager = HandshakeManager(identityManager)

        // 4. Initialize secure database with encrypted passphrase
        val rawDbKey = "WASL_DATABASE_SQLCIPHER_SECURE_PASSPHRASE_V1".toByteArray(Charsets.UTF_8)
        database = WaslDatabase.getInstance(this, rawDbKey)

        // 5. Initialize SIM and Telephony SMS services
        simCardManager = SimCardManager(this, database)
        smsSender = WaslSmsSender(this, database)
    }
}
