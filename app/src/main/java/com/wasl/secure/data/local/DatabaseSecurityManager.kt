package com.wasl.secure.data.local

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import com.wasl.secure.core.crypto.KeystoreManager
import net.sqlcipher.database.SQLiteDatabase
import java.io.File
import java.security.SecureRandom
import java.util.Locale

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
    @Synchronized
    fun getOrResolveDatabaseKey(): ByteArray {
        val dbFile = context.getDatabasePath(DATABASE_NAME)
        val hasInitialized = vaultPrefs.getBoolean(KEY_DATABASE_INITIALIZED, false)
        val wrappedDekBase64 = vaultPrefs.getString(KEY_WRAPPED_DEK, null)

        // 1. Crash Recovery check before proceeding
        reconcileFileStateAfterCrash(dbFile)

        // 2. Scenario: App was initialized and opened previously, but database file is missing!
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

        // 4. Scenario: Existing DB file with valid wrapped DEK & completed state
        // Covers normal initialized launches AND recovery if dbFile was created before KEY_DATABASE_INITIALIZED was saved.
        if (dbFile.exists() && wrappedDekBase64 != null && (hasInitialized || getMigrationState() == MigrationState.COMPLETED)) {
            return unwrapExistingDek(wrappedDekBase64)
        }

        // 5. Scenario: Pre-open crash recovery (first-install DEK generated & wrapped, DB file not yet created)
        if (!hasInitialized && !dbFile.exists() && wrappedDekBase64 != null) {
            return unwrapExistingDek(wrappedDekBase64)
        }

        // 6. Scenario: Clean first install on a fresh device -> Generate & persist wrapped DEK ONLY.
        // KEY_DATABASE_INITIALIZED remains false until Room actually opens/creates the DB file via markDatabaseInitialized().
        if (!hasInitialized && !dbFile.exists() && wrappedDekBase64 == null) {
            val newDek = keystoreManager.generateDatabaseEncryptionKey()
            persistInitialCleanInstallDek(newDek)
            return newDek
        }

        // 7. Any other corrupted / inconsistent state -> Fail secure!
        throw SecurityException(
            "تنبيه أمني حرج: حالة غير متسقة لمخزن المفاتيح وقاعدة البيانات! " +
                    "تم إيقاف التطبيق لحماية البيانات من التلف أو إنشاء مفتاح بديل غير مصرح."
        )
    }

    /**
     * Marks database initialization as complete once Room has actually opened or created
     * the encrypted database file on disk.
     */
    @Synchronized
    fun markDatabaseInitialized() {
        val dbFile = context.getDatabasePath(DATABASE_NAME)
        if (!dbFile.exists()) {
            throw IllegalStateException(
                "لا يمكن تأكيد تهيئة قاعدة البيانات قبل إنشاء ملف القاعدة فعلياً على القرص."
            )
        }
        if (!vaultPrefs.getBoolean(KEY_DATABASE_INITIALIZED, false)) {
            val committed = vaultPrefs.edit()
                .putBoolean(KEY_DATABASE_INITIALIZED, true)
                .commit()
            if (!committed) {
                throw IllegalStateException("تعذر تثبيت حالة تهيئة قاعدة البيانات على القرص.")
            }
        }
    }

    private fun unwrapExistingDek(wrappedDekBase64: String): ByteArray {
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
            val openedLegacyDb = SQLiteDatabase.openDatabase(
                legacyDbFile.absolutePath,
                legacyPassphrase,
                null,
                SQLiteDatabase.OPEN_READWRITE,
                null,
                null
            )
            legacyDb = openedLegacyDb

            // Step 2: Checkpoint WAL into the main file to avoid missing pending transactions
            openedLegacyDb.rawExecSQL("PRAGMA wal_checkpoint(TRUNCATE);")

            // Step 3: Attach migrating database with the new 32-byte DEK as a SQLite BLOB literal (X'...')
            // so ATTACH passes the exact same 32 binary bytes into sqlite3_key / PBKDF2 as SupportFactory(newDek).
            val escapedMigratingPath = migratingDbFile.absolutePath.replace("'", "''")
            val newDekHex = newDek.joinToString("") { "%02x".format(Locale.US, it) }
            openedLegacyDb.rawExecSQL("ATTACH DATABASE '$escapedMigratingPath' AS new_db KEY X'$newDekHex';")

            // Step 4: Export complete schema, indexes, and rows
            openedLegacyDb.rawExecSQL("SELECT sqlcipher_export('new_db');")

            // Step 5: Detach and close legacy DB cleanly
            openedLegacyDb.rawExecSQL("DETACH DATABASE new_db;")
            openedLegacyDb.close()
            legacyDb = null

            // Step 6: Verify new database integrity and tables by reopening with raw 32-byte newDek
            val openedMigratedDb = SQLiteDatabase.openDatabase(
                migratingDbFile.absolutePath,
                newDek,
                null,
                SQLiteDatabase.OPEN_READONLY,
                null,
                null
            )
            migratedDb = openedMigratedDb

            val integrityCursor = openedMigratedDb.rawQuery("PRAGMA integrity_check;", null)
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
            val tablesCursor = openedMigratedDb.rawQuery("SELECT name FROM sqlite_master WHERE type='table';", null)
            val existingTables = mutableSetOf<String>()
            while (tablesCursor.moveToNext()) {
                existingTables.add(tablesCursor.getString(0))
            }
            tablesCursor.close()

            openedMigratedDb.close()
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

            // Atomically persist wrapped new DEK, COMPLETED state, and initialized flag BEFORE deleting backup
            persistCompletedMigrationState(newDek)

            // Clean up temporary backup after verified & persisted success
            backupFile.delete()

            return newDek
        } catch (e: Exception) {
            legacyDb?.close()
            migratedDb?.close()
            newDek.fill(0)
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

        // If migratingFile was left over before completion, remove it
        if (migratingFile.exists() && getMigrationState() != MigrationState.COMPLETED) {
            migratingFile.delete()
        }

        // If app crashed after creating .bak and BEFORE atomic commit of COMPLETED state & wrapped key,
        // restore .bak even if dbFile already points to an unrecorded migrated file.
        if (backupFile.exists() && getMigrationState() != MigrationState.COMPLETED) {
            if (dbFile.exists() && !dbFile.delete()) {
                throw IllegalStateException("تعذر حذف الملف غير المثبَّت لاستعادة النسخة الاحتياطية لقاعدة البيانات")
            }
            if (!backupFile.renameTo(dbFile)) {
                throw IllegalStateException("تعذر استعادة النسخة الاحتياطية لقاعدة البيانات بعد الانقطاع")
            }
            File(dbFile.absolutePath + "-wal").delete()
            File(dbFile.absolutePath + "-shm").delete()
        }

        // Extra guard if .db is missing while .bak exists
        if (!dbFile.exists() && backupFile.exists()) {
            backupFile.renameTo(dbFile)
        }

        // If app crashed after atomic commit succeeded and .bak was left over
        if (dbFile.exists() && backupFile.exists() && getMigrationState() == MigrationState.COMPLETED) {
            backupFile.delete()
        }
    }

    private fun encodeWrappedDek(dek: ByteArray): String {
        val wrappedDek = keystoreManager.wrapKey(dek)
        return Base64.encodeToString(wrappedDek, Base64.NO_WRAP)
    }

    private fun persistInitialCleanInstallDek(dek: ByteArray) {
        val committed = vaultPrefs.edit()
            .putString(KEY_WRAPPED_DEK, encodeWrappedDek(dek))
            .putString(KEY_MIGRATION_STATE, MigrationState.COMPLETED.name)
            .commit()
        if (!committed) {
            throw IllegalStateException("تعذر حفظ مفتاح التشفير الأولي لقاعدة البيانات بشكل متزامن")
        }
    }

    private fun persistCompletedMigrationState(dek: ByteArray) {
        val committed = vaultPrefs.edit()
            .putString(KEY_WRAPPED_DEK, encodeWrappedDek(dek))
            .putString(KEY_MIGRATION_STATE, MigrationState.COMPLETED.name)
            .putBoolean(KEY_DATABASE_INITIALIZED, true)
            .commit()
        if (!committed) {
            throw IllegalStateException("تعذر حفظ حالة ومفتاح الترحيل المكتمل بشكل متزامن")
        }
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
