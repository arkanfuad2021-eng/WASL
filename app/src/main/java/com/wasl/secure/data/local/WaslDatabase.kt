package com.wasl.secure.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import com.wasl.secure.data.local.dao.ConversationDao
import com.wasl.secure.data.local.dao.HandshakeDao
import com.wasl.secure.data.local.dao.MessageChunkDao
import com.wasl.secure.data.local.dao.MessageDao
import com.wasl.secure.data.local.entity.ConversationEntity
import com.wasl.secure.data.local.entity.HandshakeEntity
import com.wasl.secure.data.local.entity.MessageChunkEntity
import com.wasl.secure.data.local.entity.MessageEntity
import com.wasl.secure.data.local.entity.SimPreferenceEntity
import net.sqlcipher.database.SupportFactory

@Database(
    entities = [
        ConversationEntity::class,
        MessageEntity::class,
        HandshakeEntity::class,
        SimPreferenceEntity::class,
        MessageChunkEntity::class
    ],
    version = 1,
    exportSchema = false
)
abstract class WaslDatabase : RoomDatabase() {

    abstract fun conversationDao(): ConversationDao
    abstract fun messageDao(): MessageDao
    abstract fun handshakeDao(): HandshakeDao
    abstract fun messageChunkDao(): MessageChunkDao

    companion object {
        private const val DATABASE_NAME = "wasl_encrypted.db"

        @Volatile
        private var INSTANCE: WaslDatabase? = null

        fun getInstance(context: Context, encryptionPassphrase: ByteArray? = null): WaslDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: buildDatabase(context, encryptionPassphrase).also { INSTANCE = it }
            }
        }

        private fun buildDatabase(context: Context, encryptionPassphrase: ByteArray?): WaslDatabase {
            val builder = Room.databaseBuilder(
                context.applicationContext,
                WaslDatabase::class.java,
                DATABASE_NAME
            )

            // If an encryption passphrase is provided, enforce SQLCipher full database encryption
            encryptionPassphrase?.let { passphrase ->
                val factory = SupportFactory(passphrase)
                builder.openHelperFactory(factory)
            }

            return builder.build()
        }
    }
}
