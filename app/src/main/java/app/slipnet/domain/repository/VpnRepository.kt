package app.slipnet.domain.repository

import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.TrafficStats
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow

interface VpnRepository {
    val connectionState: StateFlow<ConnectionState>
    val trafficStats: StateFlow<TrafficStats>

    suspend fun connect(profile: ServerProfile): Result<Unit>
    suspend fun disconnect(): Result<Unit>
    fun isConnected(): Boolean
    fun getConnectedProfile(): ServerProfile?
}
