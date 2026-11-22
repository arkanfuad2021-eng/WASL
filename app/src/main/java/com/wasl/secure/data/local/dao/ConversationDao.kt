package com.wasl.secure.data.local.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.wasl.secure.data.local.entity.ConversationEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface ConversationDao {

    @Query("SELECT * FROM conversations ORDER BY lastMessageTimestamp DESC")
    fun getAllConversations(): Flow<List<ConversationEntity>>

    @Query("SELECT * FROM conversations WHERE id = :id LIMIT 1")
    suspend fun getConversationById(id: String): ConversationEntity?

    @Query("SELECT * FROM conversations WHERE phoneNumber = :phoneNumber LIMIT 1")
    suspend fun getConversationByPhone(phoneNumber: String): ConversationEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertOrUpdate(conversation: ConversationEntity)

    @Update
    suspend fun update(conversation: ConversationEntity)

    @Query("UPDATE conversations SET nextOutboundCounter = nextOutboundCounter + 1 WHERE id = :id")
    suspend fun incrementOutboundCounter(id: String)

    @Query("UPDATE conversations SET defaultSubscriptionId = :subId WHERE id = :id")
    suspend fun updateDefaultSim(id: String, subId: Int)

    @Query("DELETE FROM conversations WHERE id = :id")
    suspend fun deleteById(id: String)

    @Query("DELETE FROM conversations WHERE id IN (:ids)")
    suspend fun deleteByIds(ids: List<String>)
}
