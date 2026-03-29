package app.slipnet.service

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * In-process singleton bus between DnsScannerViewModel (writer) and ScanService (reader).
 * No IPC or serialization needed — both live in the same process.
 *
 * Also provides a process-scoped [scanScope] for long-running scan/E2E jobs
 * so they survive ViewModel clearing (e.g. user navigates away from the
 * scanner screen while a scan is running).
 */
object ScanStateHolder {
    private val _state = MutableStateFlow(ScanServiceState())
    val state: StateFlow<ScanServiceState> = _state.asStateFlow()

    /** Process-scoped scope for scan jobs that must survive ViewModel lifecycle. */
    private var scopeJob = SupervisorJob()
    var scanScope = CoroutineScope(scopeJob + Dispatchers.IO)
        private set

    fun update(transform: (ScanServiceState) -> ScanServiceState) = _state.update(transform)

    /** Cancel all running scan coroutines and recreate the scope, but keep state. */
    fun cancelScope() {
        scopeJob.cancel()
        scopeJob = SupervisorJob()
        scanScope = CoroutineScope(scopeJob + Dispatchers.IO)
    }

    /** Cancel scope AND clear all state. */
    fun reset() {
        cancelScope()
        _state.value = ScanServiceState()
    }
}
