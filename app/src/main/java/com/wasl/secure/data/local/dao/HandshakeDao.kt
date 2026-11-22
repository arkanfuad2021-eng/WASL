package com.wasl.secure.data.local.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.wasl.secure.data.local.entity.HandshakeEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface HandshakeDao {

    @Query("SELECT * FROM handshake_requests WHERE requestId = :requestId LIMIT 1")
    suspend fun getByRequestId(requestId: String): HandshakeEntity?

    @Query("SELECT * FROM handshake_requests WHERE phoneNumber = :phone AND status = 'WAITING' ORDER BY createdAt DESC LIMIT 1")
    suspend fun getActiveWaitingRequest(phone: String): HandshakeEntity?

    @Query("SELECT * FROM handshake_requests WHERE isIncoming = 1 AND status = 'WAITING' ORDER BY createdAt DESC")
    fun getPendingIncomingRequests(): Flow<List<HandshakeEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertOrUpdate(request: HandshakeEntity)

    @Update
    suspend fun update(request: HandshakeEntity)

    @Query("UPDATE handshake_requests SET status = :status WHERE requestId = :requestId")
    suspend fun updateStatus(requestId: String, status: String)

    @Query("DELETE FROM handshake_requests WHERE requestId = :requestId")
    suspend fun delete(requestId: String)
}
