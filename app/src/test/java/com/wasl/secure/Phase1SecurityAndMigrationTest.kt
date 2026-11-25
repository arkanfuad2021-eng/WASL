package com.wasl.secure

import android.content.Context
import android.content.SharedPreferences
import com.wasl.secure.core.crypto.IdentityManager
import com.wasl.secure.core.crypto.KeystoreManager
import com.wasl.secure.data.local.DatabaseSecurityManager
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.util.concurrent.ConcurrentHashMap

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], manifest = Config.NONE)
class Phase1SecurityAndMigrationTest {

    private lateinit var mockContext: TestMockContext
    private lateinit var keystoreManager: KeystoreManager

    @Before
    fun setUp() {
        mockContext = TestMockContext()
        keystoreManager = KeystoreManager(keyStoreType = "TEST_JVM_FALLBACK")
    }

    @Test
    fun test_keystore_envelope_encryption_wrap_unwrap() {
        // 1. Generate 32-byte DEK
        val rawDek = keystoreManager.generateDatabaseEncryptionKey()
        assertEquals(32, rawDek.size)

        // 2. Wrap DEK
        val wrappedDek = keystoreManager.wrapKey(rawDek)
        assertTrue("Wrapped DEK must include IV and GCM tag", wrappedDek.size > 32 + 12 + 16)

        // 3. Unwrap DEK and verify identity
        val unwrappedDek = keystoreManager.unwrapKey(wrappedDek)
        assertArrayEquals("Unwrapped DEK must match original raw DEK", rawDek, unwrappedDek)

        // 4. Test tampering with wrapped envelope -> must fail
        val corruptedEnvelope = wrappedDek.clone()
        corruptedEnvelope[corruptedEnvelope.size - 1] = (corruptedEnvelope[corruptedEnvelope.size - 1] + 1).toByte()
        try {
            keystoreManager.unwrapKey(corruptedEnvelope)
            fail("Corrupted envelope must throw exception upon decryption")
        } catch (e: Exception) {
            // Success: GCM Authentication failed
        }
    }

    @Test
    fun test_identity_manager_no_silent_regeneration_when_identity_lost() {
        // 1. Clean first run -> Should generate identity
        val identityManager1 = IdentityManager(mockContext, keystoreManager)
        assertTrue(identityManager1.isHealthy())
        assertEquals(IdentityManager.IdentityState.ACTIVE, identityManager1.currentState)

        val originalPublicKey = identityManager1.getPublicIdentityKey()
        assertNotNull(originalPublicKey)

        // 2. Simulate Key Loss / Corruption in Keystore or Prefs on existing install
        val prefs = mockContext.getSharedPreferences(IdentityManager.PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().remove(IdentityManager.KEY_ENCRYPTED_PRIVATE_IDENTITY).commit()

        // 3. Re-instantiate IdentityManager on corrupted state
        val identityManager2 = IdentityManager(mockContext, keystoreManager)

        // 4. MUST NOT silently generate a new identity! MUST enter LOCKDOWN
        assertFalse(identityManager2.isHealthy())
        assertEquals(IdentityManager.IdentityState.LOCKDOWN_KEY_LOST, identityManager2.currentState)

        try {
            identityManager2.getPublicIdentityKey()
            fail("Must throw SecurityException when in LOCKDOWN")
        } catch (e: SecurityException) {
            assertTrue(e.message!!.contains("الإغلاق الأمني"))
        }

        try {
            identityManager2.sign("test".toByteArray())
            fail("Must throw SecurityException when in LOCKDOWN")
        } catch (e: SecurityException) {
            assertTrue(e.message!!.contains("الإغلاق الأمني"))
        }
    }

    @Test
    fun test_database_security_manager_blocks_silent_empty_db_when_data_missing() {
        val vaultPrefs = mockContext.getSharedPreferences(
            DatabaseSecurityManager.VAULT_PREFS_NAME,
            Context.MODE_PRIVATE
        )
        // Mark that the database was previously initialized
        vaultPrefs.edit()
            .putBoolean(DatabaseSecurityManager.KEY_DATABASE_INITIALIZED, true)
            .putString(DatabaseSecurityManager.KEY_MIGRATION_STATE, DatabaseSecurityManager.MigrationState.COMPLETED.name)
            .commit()

        val dbSecurityManager = DatabaseSecurityManager(mockContext, keystoreManager)

        // The database file does not exist on disk
        val dbFile = mockContext.getDatabasePath(DatabaseSecurityManager.DATABASE_NAME)
        assertFalse("Database file should not exist in this test scenario", dbFile.exists())

        try {
            dbSecurityManager.getOrResolveDatabaseKey()
            fail("Must throw IllegalStateException when an initialized DB file is missing from disk")
        } catch (e: IllegalStateException) {
            assertTrue("Error message must inform user of missing database without silent recreation",
                e.message!!.contains("ملف قاعدة البيانات المشفرة مفقود"))
        }
    }

    @Test
    fun test_database_security_manager_first_install_generates_and_persists_dek() {
        val dbSecurityManager = DatabaseSecurityManager(mockContext, keystoreManager)
        val dek = dbSecurityManager.getOrResolveDatabaseKey()

        assertNotNull(dek)
        assertEquals(32, dek.size)
        assertEquals(DatabaseSecurityManager.MigrationState.COMPLETED, dbSecurityManager.getMigrationState())

        val vaultPrefs = mockContext.getSharedPreferences(
            DatabaseSecurityManager.VAULT_PREFS_NAME,
            Context.MODE_PRIVATE
        )
        assertTrue(vaultPrefs.getBoolean(DatabaseSecurityManager.KEY_DATABASE_INITIALIZED, false))
        assertTrue(vaultPrefs.contains(DatabaseSecurityManager.KEY_WRAPPED_DEK))

        // Subsequent call returns identical unwrapped DEK
        val dekSecondCall = dbSecurityManager.getOrResolveDatabaseKey()
        assertArrayEquals(dek, dekSecondCall)
    }

    @Test
    fun test_identity_manager_detects_mismatched_keypair_and_enters_lockdown() {
        // 1. Initial clean generation
        val identityManager1 = IdentityManager(mockContext, keystoreManager)
        assertTrue(identityManager1.isHealthy())

        // 2. Tamper with the public key (swap with a different public key)
        val prefs = mockContext.getSharedPreferences(IdentityManager.PREFS_NAME, Context.MODE_PRIVATE)
        val foreignKeyPair = com.wasl.secure.core.crypto.Curve25519Engine.generateEd25519KeyPair()
        val foreignPubKeyB64 = android.util.Base64.encodeToString(foreignKeyPair.publicKey, android.util.Base64.NO_WRAP)
        prefs.edit().putString(IdentityManager.KEY_PUBLIC_IDENTITY, foreignPubKeyB64).commit()

        // 3. Re-instantiate IdentityManager -> Consistency self-test MUST fail
        val identityManager2 = IdentityManager(mockContext, keystoreManager)
        assertFalse("Mismatched public/private key must fail health check", identityManager2.isHealthy())
        assertEquals(IdentityManager.IdentityState.LOCKDOWN_KEY_LOST, identityManager2.currentState)
    }

    @Test
    fun test_database_security_manager_never_generates_replacement_dek_when_key_inaccessible() {
        // Setup an existing database file and initialized vault
        val dbFile = mockContext.getDatabasePath(DatabaseSecurityManager.DATABASE_NAME).apply {
            createNewFile()
        }
        val vaultPrefs = mockContext.getSharedPreferences(
            DatabaseSecurityManager.VAULT_PREFS_NAME,
            Context.MODE_PRIVATE
        )
        // Store an un-decryptable/corrupted wrapped key in vault
        vaultPrefs.edit()
            .putBoolean(DatabaseSecurityManager.KEY_DATABASE_INITIALIZED, true)
            .putString(DatabaseSecurityManager.KEY_MIGRATION_STATE, DatabaseSecurityManager.MigrationState.COMPLETED.name)
            .putString(DatabaseSecurityManager.KEY_WRAPPED_DEK, "CORRUPTED_BASE64_VALUE")
            .commit()

        val dbSecurityManager = DatabaseSecurityManager(mockContext, keystoreManager)

        try {
            dbSecurityManager.getOrResolveDatabaseKey()
            fail("Must throw SecurityException when wrapped DEK cannot be unwrapped, NEVER generate replacement key")
        } catch (e: SecurityException) {
            assertTrue(e.message!!.contains("تعذر فك تشفير مفتاح قاعدة البيانات") || e.message!!.contains("حظر"))
        }

        // Verify that the vault still contains the original state and did not silently overwrite with a new key
        assertEquals("CORRUPTED_BASE64_VALUE", vaultPrefs.getString(DatabaseSecurityManager.KEY_WRAPPED_DEK, null))
    }
}

/**
 * Lightweight mock Context implementation for JVM unit tests of SharedPreferences and File paths.
 */
class TestMockContext : android.content.ContextWrapper(null) {
    private val prefsMap = ConcurrentHashMap<String, SharedPreferences>()
    private val tempDir = File(System.getProperty("java.io.tmpdir"), "wasl_test_${System.currentTimeMillis()}").apply { mkdirs() }

    override fun getSharedPreferences(name: String, mode: Int): SharedPreferences {
        return prefsMap.computeIfAbsent(name) { TestMockSharedPreferences() }
    }

    override fun getDatabasePath(name: String): File {
        return File(tempDir, name)
    }

    override fun getApplicationContext(): Context {
        return this
    }
}

class TestMockSharedPreferences : SharedPreferences {
    private val map = ConcurrentHashMap<String, Any>()

    override fun getAll(): MutableMap<String, *> = map
    override fun getString(key: String?, defValue: String?): String? = map[key] as? String ?: defValue
    override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? = null
    override fun getInt(key: String?, defValue: Int): Int = (map[key] as? Int) ?: defValue
    override fun getLong(key: String?, defValue: Long): Long = (map[key] as? Long) ?: defValue
    override fun getFloat(key: String?, defValue: Float): Float = (map[key] as? Float) ?: defValue
    override fun getBoolean(key: String?, defValue: Boolean): Boolean = (map[key] as? Boolean) ?: defValue
    override fun contains(key: String?): Boolean = map.containsKey(key)
    override fun edit(): SharedPreferences.Editor = EditorImpl(map)
    override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}

    class EditorImpl(private val target: ConcurrentHashMap<String, Any>) : SharedPreferences.Editor {
        private val temp = mutableMapOf<String, Any?>()
        private var clear = false

        override fun putString(key: String?, value: String?): SharedPreferences.Editor { value?.let { temp[key!!] = it }; return this }
        override fun putStringSet(key: String?, values: MutableSet<String>?): SharedPreferences.Editor = this
        override fun putInt(key: String?, value: Int): SharedPreferences.Editor { temp[key!!] = value; return this }
        override fun putLong(key: String?, value: Long): SharedPreferences.Editor { temp[key!!] = value; return this }
        override fun putFloat(key: String?, value: Float): SharedPreferences.Editor { temp[key!!] = value; return this }
        override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor { temp[key!!] = value; return this }
        override fun remove(key: String?): SharedPreferences.Editor { temp[key!!] = null; return this }
        override fun clear(): SharedPreferences.Editor { clear = true; return this }
        override fun commit(): Boolean { apply(); return true }
        override fun apply() {
            if (clear) target.clear()
            for ((k, v) in temp) {
                if (v == null) target.remove(k) else target[k] = v
            }
        }
    }
}
