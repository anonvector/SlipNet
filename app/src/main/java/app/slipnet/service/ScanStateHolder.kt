package app.slipnet.service

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * In-process singleton bus between DnsScannerViewModel (writer) and ScanService (reader).
 * No IPC or serialization needed — both live in the same process.
 */
object ScanStateHolder {
    private val _state = MutableStateFlow(ScanServiceState())
    val state: StateFlow<ScanServiceState> = _state.asStateFlow()

    fun update(transform: (ScanServiceState) -> ScanServiceState) = _state.update(transform)
    fun reset() { _state.value = ScanServiceState() }
}
