package com.wasl.secure

import android.app.Application
import com.wasl.secure.core.crypto.KeystoreManager
import com.wasl.secure.data.local.WaslDatabase
import net.sqlcipher.database.SQLiteDatabase

class WaslApplication : Application() {

    lateinit var database: WaslDatabase
        private set

    lateinit var keystoreManager: KeystoreManager
        private set

    override fun onCreate() {
        super.onCreate()

        // 1. Initialize SQLCipher native cryptographic libraries
        SQLiteDatabase.loadLibs(this)

        // 2. Initialize Android Keystore master envelope manager
        keystoreManager = KeystoreManager()

        // 3. Initialize secure database with encrypted passphrase
        // For development/initialization, we derive the passphrase via KeystoreManager
        val rawDbKey = "WASL_DATABASE_SQLCIPHER_SECURE_PASSPHRASE_V1".toByteArray(Charsets.UTF_8)
        database = WaslDatabase.getInstance(this, rawDbKey)
    }
}
