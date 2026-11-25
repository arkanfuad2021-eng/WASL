package com.wasl.secure.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.wasl.secure.data.local.dao.ConversationDao
import com.wasl.secure.data.local.dao.HandshakeDao
import com.wasl.secure.data.local.dao.MessageChunkDao
import com.wasl.secure.data.local.dao.MessageDao
import com.wasl.secure.data.local.dao.OutboundAttemptDao
import com.wasl.secure.data.local.entity.ConversationEntity
import com.wasl.secure.data.local.entity.HandshakeEntity
import com.wasl.secure.data.local.entity.MessageChunkEntity
import com.wasl.secure.data.local.entity.MessageEntity
import com.wasl.secure.data.local.entity.OutboundAttemptEntity
import com.wasl.secure.data.local.entity.SimPreferenceEntity
import net.sqlcipher.database.SupportFactory

@Database(
    entities = [
        ConversationEntity::class,
        MessageEntity::class,
        HandshakeEntity::class,
        SimPreferenceEntity::class,
        MessageChunkEntity::class,
        OutboundAttemptEntity::class
    ],
    version = 3,
    exportSchema = false
)
abstract class WaslDatabase : RoomDatabase() {

    abstract fun conversationDao(): ConversationDao
    abstract fun messageDao(): MessageDao
    abstract fun handshakeDao(): HandshakeDao
    abstract fun messageChunkDao(): MessageChunkDao
    abstract fun outboundAttemptDao(): OutboundAttemptDao

    companion object {
        const val DATABASE_NAME = "wasl_encrypted.db"

        @Volatile
        private var INSTANCE: WaslDatabase? = null

        /**
         * Safe migration from Version 1 to Version 2:
         * - Rebuilds pending_message_chunks with composite PK (conversationId, messageId, attemptId, chunkIndex).
         * - Rebuilds messages with composite PK (conversationId, id) and adds attempt tracking + ciphertextBase64.
         * - Creates outbound_attempts table with composite PK (conversationId, messageId, attemptId) and index tracking.
         * - Strictly preserves all existing data without data loss.
         */
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // 1. Rebuild pending_message_chunks with composite PK
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS pending_message_chunks_new (
                        conversationId TEXT NOT NULL,
                        messageId TEXT NOT NULL,
                        attemptId TEXT NOT NULL DEFAULT '0001',
                        chunkIndex INTEGER NOT NULL,
                        totalChunks INTEGER NOT NULL,
                        chunkPayloadBase64 TEXT NOT NULL,
                        nonceBase64 TEXT NOT NULL,
                        sequenceNumber INTEGER NOT NULL,
                        receivedAt INTEGER NOT NULL,
                        PRIMARY KEY(conversationId, messageId, attemptId, chunkIndex)
                    )
                """.trimIndent())

                db.execSQL("""
                    INSERT INTO pending_message_chunks_new (
                        conversationId, messageId, attemptId, chunkIndex, totalChunks,
                        chunkPayloadBase64, nonceBase64, sequenceNumber, receivedAt
                    )
                    SELECT
                        conversationId, messageId, '0001', chunkIndex, totalChunks,
                        chunkPayloadBase64, nonceBase64, sequenceNumber, receivedAt
                    FROM pending_message_chunks
                """.trimIndent())

                db.execSQL("DROP TABLE pending_message_chunks")
                db.execSQL("ALTER TABLE pending_message_chunks_new RENAME TO pending_message_chunks")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_pending_message_chunks_lookup ON pending_message_chunks (conversationId, messageId, attemptId)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_pending_message_chunks_receivedAt ON pending_message_chunks (receivedAt)")

                // 2. Rebuild messages with composite PK (conversationId, id)
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS messages_new (
                        conversationId TEXT NOT NULL,
                        id TEXT NOT NULL,
                        direction TEXT NOT NULL,
                        content TEXT NOT NULL,
                        timestamp INTEGER NOT NULL,
                        status TEXT NOT NULL,
                        simSubscriptionId INTEGER,
                        totalParts INTEGER NOT NULL DEFAULT 1,
                        deliveredParts INTEGER NOT NULL DEFAULT 0,
                        nonceBase64 TEXT,
                        chunkSequence INTEGER NOT NULL DEFAULT 0,
                        attemptCount INTEGER NOT NULL DEFAULT 1,
                        currentAttemptId TEXT NOT NULL DEFAULT '0001',
                        ciphertextBase64 TEXT,
                        PRIMARY KEY(conversationId, id),
                        FOREIGN KEY(conversationId) REFERENCES conversations(id) ON DELETE CASCADE
                    )
                """.trimIndent())

                db.execSQL("""
                    INSERT INTO messages_new (
                        conversationId, id, direction, content, timestamp, status,
                        simSubscriptionId, totalParts, deliveredParts, nonceBase64,
                        chunkSequence, attemptCount, currentAttemptId, ciphertextBase64
                    )
                    SELECT
                        conversationId, id, direction, content, timestamp, status,
                        simSubscriptionId, totalParts, deliveredParts, nonceBase64,
                        chunkSequence, 1, '0001', NULL
                    FROM messages
                """.trimIndent())

                db.execSQL("DROP TABLE messages")
                db.execSQL("ALTER TABLE messages_new RENAME TO messages")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_messages_conversationId ON messages(conversationId)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_messages_timestamp ON messages(timestamp)")

                // 3. Create outbound_attempts table with sentIndices and deliveredIndices
                db.execSQL("""
                    CREATE TABLE IF NOT EXISTS outbound_attempts (
                        conversationId TEXT NOT NULL,
                        messageId TEXT NOT NULL,
                        attemptId TEXT NOT NULL,
                        totalChunks INTEGER NOT NULL,
                        sentChunks INTEGER NOT NULL DEFAULT 0,
                        deliveredChunks INTEGER NOT NULL DEFAULT 0,
                        sentIndices TEXT NOT NULL DEFAULT '',
                        deliveredIndices TEXT NOT NULL DEFAULT '',
                        status TEXT NOT NULL,
                        createdAt INTEGER NOT NULL,
                        PRIMARY KEY(conversationId, messageId, attemptId),
                        FOREIGN KEY(conversationId, messageId) REFERENCES messages(conversationId, id) ON DELETE CASCADE
                    )
                """.trimIndent())
                db.execSQL("CREATE INDEX IF NOT EXISTS index_outbound_attempts_conv_msg ON outbound_attempts (conversationId, messageId)")
            }
        }

        /**
         * Safe migration from Version 2 to Version 3:
         * - Persists CONFIRM send progress columns on conversations across process restarts.
         */
        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE conversations ADD COLUMN pendingConfirmMessageId TEXT")
                db.execSQL("ALTER TABLE conversations ADD COLUMN pendingConfirmTotalParts INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE conversations ADD COLUMN pendingConfirmSentIndices TEXT NOT NULL DEFAULT ''")
            }
        }

        fun getInstance(
            context: Context,
            encryptionPassphrase: ByteArray,
            databaseSecurityManager: DatabaseSecurityManager? = null
        ): WaslDatabase {
            require(encryptionPassphrase.isNotEmpty()) {
                "انتهاك أمني حرج: لا يمكن فتح قاعدة بيانات وصل المشفرة دون مفتاح SQLCipher صالح وغير فارغ!"
            }
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: buildDatabase(
                    context,
                    encryptionPassphrase,
                    databaseSecurityManager
                ).also { INSTANCE = it }
            }
        }

        internal fun createInitializationCallback(
            databaseSecurityManager: DatabaseSecurityManager
        ): Callback {
            return object : Callback() {
                override fun onOpen(db: SupportSQLiteDatabase) {
                    super.onOpen(db)
                    databaseSecurityManager.markDatabaseInitialized()
                }
            }
        }

        private fun buildDatabase(
            context: Context,
            encryptionPassphrase: ByteArray,
            databaseSecurityManager: DatabaseSecurityManager? = null
        ): WaslDatabase {
            require(encryptionPassphrase.isNotEmpty()) {
                "انتهاك أمني حرج: لا يمكن بناء قاعدة بيانات وصل دون مفتاح SQLCipher صالح!"
            }

            val builder = Room.databaseBuilder(
                context.applicationContext,
                WaslDatabase::class.java,
                DATABASE_NAME
            ).addMigrations(MIGRATION_1_2, MIGRATION_2_3)

            // Strictly disable destructive migration to protect user data from accidental drops
            // builder.fallbackToDestructiveMigration() is purposefully OMITTED.

            if (databaseSecurityManager != null) {
                builder.addCallback(createInitializationCallback(databaseSecurityManager))
            }

            // Enforce SQLCipher database encryption with automatic passphrase array wiping
            val factory = SupportFactory(encryptionPassphrase, null, true)
            builder.openHelperFactory(factory)

            return builder.build()
        }

        /**
         * Closes the active database instance, useful during safe file operations and testing.
         */
        fun closeDatabase() {
            synchronized(this) {
                INSTANCE?.let { db ->
                    if (db.isOpen) {
                        db.close()
                    }
                }
                INSTANCE = null
            }
        }
    }
}
