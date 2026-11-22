package com.wasl.secure.data.local.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "handshake_requests")
data class HandshakeEntity(
    @PrimaryKey
    val requestId: String,
    val conversationId: String,
    val phoneNumber: String,
    val isIncoming: Boolean,
    val status: String,
    val createdAt: Long,
    val expiredAt: Long,
    val rejectedAt: Long?,
    val ephemeralPrivateKeyBase64: String?, // Protected locally until handshake completion
    val peerEphemeralPublicKeyBase64: String?
)

@Entity(tableName = "sim_preferences")
data class SimPreferenceEntity(
    @PrimaryKey
    val phoneNumber: String,
    val subscriptionId: Int,
    val updatedAt: Long
)
