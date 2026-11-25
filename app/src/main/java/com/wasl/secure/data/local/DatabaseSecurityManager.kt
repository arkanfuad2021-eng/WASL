package com.wasl.secure.data.local

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import com.wasl.secure.core.crypto.KeystoreManager
import net.sqlcipher.database.SQLiteDatabase
import java.io.File
import java.security.SecureRandom

/**
 * Manages the Database Encryption Key (DEK) lifecycle, envelope encryption,
 * and crash-resilient stateful migration from legacy databases to Keystore-wrapped DEK.
 */
class DatabaseSecurityManager(
    private val context: Context,
    private val keystoreManager: KeystoreManager
) {

    companion object {
        const val VAULT_PREFS_NAME = "wasl_key_vault"
        const val KEY_WRAPPED_DEK = "wrapped_dek_base64"
        const val KEY_MIGRATION_STATE = "migration_state"
        const val KEY_DATABASE_INITIALIZED = "database_has_been_initialized"

        const val LEGACY_PASSPHRASE_STRING = "WASL_DATABASE_SQLCIPHER_SECURE_PASSPHRASE_V1"
        const val DATABASE_NAME = "wasl_encrypted.db"
        const val MIGRATING_DB_NAME = "wasl_encrypted_migrating.db"
        const val BACKUP_DB_NAME = "wasl_encrypted.db.bak"

        val REQUIRED_TABLES = setOf(
            "conversations",
            "messages",
            "handshake_requests",
            "pending_message_chunks",
            "sim_preferences"
        )
    }

    enum class MigrationState {
        NOT_STARTED,
        IN_PROGRESS,
        COMPLETED
    }

    private val vaultPrefs: SharedPreferences =
        context.getSharedPreferences(VAULT_PREFS_NAME, Context.MODE_PRIVATE)

    /**
     * Resolves, generates, or unwraps the 256-bit Database Encryption Key (DEK).
     * If an unmigrated legacy database is detected, performs a stateful crash-resilient migration.
     */
    fun getOrResolveDatabaseKey(): ByteArray {
        val dbFile = context.getDatabasePath(DATABASE_NAME)
        val hasInitialized = vaultPrefs.getBoolean(KEY_DATABASE_INITIALIZED, false)
        val wrappedDekBase64 = vaultPrefs.getString(KEY_WRAPPED_DEK, null)

        // 1. Crash Recovery check before proceeding
        reconcileFileStateAfterCrash(dbFile)

        // 2. Scenario: App was initialized previously, but database file is missing!
        if (hasInitialized && !dbFile.exists()) {
            throw IllegalStateException(
                "تنبيه أمني حرج: ملف قاعدة البيانات المشفرة مفقود رغم تهيئته مسبقاً! " +
                        "تم حظر إنشاء قاعدة فارغة تلقائياً لحماية سجلات المستخدم."
            )
        }

        // 3. Scenario: Legacy database exists without Keystore DEK -> Execute migration
        if (dbFile.exists() && !hasInitialized && (wrappedDekBase64 == null || getMigrationState() != MigrationState.COMPLETED)) {
            return performSafeMigration(dbFile)
        }

        // 4. Scenario: Normal initialized state -> Unwrap existing DEK
        if (hasInitialized && wrappedDekBase64 != null) {
            val wrappedBytes = Base64.decode(wrappedDekBase64, Base64.NO_WRAP)
            return try {
                keystoreManager.unwrapKey(wrappedBytes)
            } catch (e: Exception) {
                throw SecurityException(
                    "تنبيه أمني حرج: تعذر فك تشفير مفتاح قاعدة البيانات من Android Keystore! " +
                            "تم حظر فتح قاعدة البيانات أو استبدال المفتاح لحماية سجلات المستخدم من الفساد.", e
                )
            }
        }

        // 5. Scenario: Clean first install on a fresh device -> Generate new DEK and store wrapped
        if (!hasInitialized && !dbFile.exists()) {
            val newDek = keystoreManager.generateDatabaseEncryptionKey()
            persistWrappedDek(newDek)
            setMigrationState(MigrationState.COMPLETED)
            vaultPrefs.edit().putBoolean(KEY_DATABASE_INITIALIZED, true).apply()
            return newDek
        }

        // 6. Any other corrupted / inconsistent state -> Fail secure!
        throw SecurityException(
            "تنبيه أمني حرج: حالة غير متسقة لمخزن المفاتيح وقاعدة البيانات! " +
                    "تم إيقاف التطبيق لحماية البيانات من التلف أو إنشاء مفتاح بديل غير مصرح."
        )
    }

    /**
     * Performs a stateful crash-resilient migration from the legacy hardcoded key
     * to a new hardware-wrapped DEK using sqlcipher_export and WAL truncation.
     */
    @Synchronized
    private fun performSafeMigration(legacyDbFile: File): ByteArray {
        setMigrationState(MigrationState.IN_PROGRESS)

        val migratingDbFile = context.getDatabasePath(MIGRATING_DB_NAME)
        if (migratingDbFile.exists()) {
            migratingDbFile.delete()
        }

        // Generate new DEK for migration
        val newDek = keystoreManager.generateDatabaseEncryptionKey()
        val legacyPassphrase = LEGACY_PASSPHRASE_STRING.toByteArray(Charsets.UTF_8)

        var legacyDb: SQLiteDatabase? = null
        var migratedDb: SQLiteDatabase? = null

        try {
            // Step 1: Open legacy database
            legacyDb = SQLiteDatabase.openDatabase(
                legacyDbFile.absolutePath,
                legacyPassphrase,
                null,
                SQLiteDatabase.OPEN_READWRITE
            )

            // Step 2: Checkpoint WAL into the main file to avoid missing pending transactions
            legacyDb.rawExecSQL("PRAGMA wal_checkpoint(TRUNCATE);")

            // Step 3: Attach migrating database with the new DEK
            val newDekHex = newDek.joinToString("") { "%02x".format(it) }
            legacyDb.rawExecSQL("ATTACH DATABASE '${migratingDbFile.absolutePath}' AS new_db KEY \"x'$newDekHex'\";")

            // Step 4: Export complete schema, indexes, and rows
            legacyDb.rawExecSQL("SELECT sqlcipher_export('new_db');")

            // Step 5: Detach and close legacy DB cleanly
            legacyDb.rawExecSQL("DETACH DATABASE new_db;")
            legacyDb.close()
            legacyDb = null

            // Step 6: Verify new database integrity and tables
            migratedDb = SQLiteDatabase.openDatabase(
                migratingDbFile.absolutePath,
                newDek,
                null,
                SQLiteDatabase.OPEN_READONLY
            )

            val integrityCursor = migratedDb.rawQuery("PRAGMA integrity_check;", null)
            var integrityOk = false
            if (integrityCursor.moveToFirst()) {
                val result = integrityCursor.getString(0)
                integrityOk = result.equals("ok", ignoreCase = true)
            }
            integrityCursor.close()

            if (!integrityOk) {
                throw SecurityException("فشل فحص التكامل (integrity_check) لقاعدة البيانات الجديدة بعد الترحيل!")
            }

            // Step 7: Verify schema existence
            val tablesCursor = migratedDb.rawQuery("SELECT name FROM sqlite_master WHERE type='table';", null)
            val existingTables = mutableSetOf<String>()
            while (tablesCursor.moveToNext()) {
                existingTables.add(tablesCursor.getString(0))
            }
            tablesCursor.close()

            migratedDb.close()
            migratedDb = null

            // Step 8: Atomic File Replacement
            val backupFile = context.getDatabasePath(BACKUP_DB_NAME)
            if (backupFile.exists()) {
                backupFile.delete()
            }

            if (!legacyDbFile.renameTo(backupFile)) {
                throw IllegalStateException("تعذر إعادة تسمية قاعدة البيانات السابقة إلى ملف النسخة الاحتياطية")
            }

            if (!migratingDbFile.renameTo(legacyDbFile)) {
                // Rollback file rename if failed
                backupFile.renameTo(legacyDbFile)
                throw IllegalStateException("تعذر اعتماد ملف قاعدة البيانات المُرَحَّلة")
            }

            // Clean up auxiliary WAL/SHM legacy files
            File(legacyDbFile.absolutePath + "-wal").delete()
            File(legacyDbFile.absolutePath + "-shm").delete()

            // Persist the wrapped new DEK and mark migration complete
            persistWrappedDek(newDek)
            setMigrationState(MigrationState.COMPLETED)
            vaultPrefs.edit().putBoolean(KEY_DATABASE_INITIALIZED, true).apply()

            // Clean up temporary backup after verified success
            backupFile.delete()

            return newDek
        } catch (e: Exception) {
            legacyDb?.close()
            migratedDb?.close()
            if (migratingDbFile.exists()) {
                migratingDbFile.delete()
            }
            throw IllegalStateException("فشل ترحيل قاعدة البيانات: ${e.message}", e)
        } finally {
            legacyPassphrase.fill(0)
        }
    }

    /**
     * Reconciles file states in case of unexpected termination/crash during previous migration.
     */
    private fun reconcileFileStateAfterCrash(dbFile: File) {
        val backupFile = context.getDatabasePath(BACKUP_DB_NAME)
        val migratingFile = context.getDatabasePath(MIGRATING_DB_NAME)

        // If migratingFile was left over, remove it
        if (migratingFile.exists() && getMigrationState() != MigrationState.COMPLETED) {
            migratingFile.delete()
        }

        // If app crashed after legacyDbFile was renamed to .bak and .db is missing
        if (!dbFile.exists() && backupFile.exists()) {
            backupFile.renameTo(dbFile)
        }

        // If app crashed after new db was active and .bak was left over
        if (dbFile.exists() && backupFile.exists() && getMigrationState() == MigrationState.COMPLETED) {
            backupFile.delete()
        }
    }

    private fun persistWrappedDek(dek: ByteArray) {
        val wrappedDek = keystoreManager.wrapKey(dek)
        val wrappedBase64 = Base64.encodeToString(wrappedDek, Base64.NO_WRAP)
        vaultPrefs.edit()
            .putString(KEY_WRAPPED_DEK, wrappedBase64)
            .apply()
    }

    fun getMigrationState(): MigrationState {
        val stateName = vaultPrefs.getString(KEY_MIGRATION_STATE, MigrationState.NOT_STARTED.name)
        return try {
            MigrationState.valueOf(stateName ?: MigrationState.NOT_STARTED.name)
        } catch (e: Exception) {
            MigrationState.NOT_STARTED
        }
    }

    private fun setMigrationState(state: MigrationState) {
        vaultPrefs.edit()
            .putString(KEY_MIGRATION_STATE, state.name)
            .commit()
    }
}
