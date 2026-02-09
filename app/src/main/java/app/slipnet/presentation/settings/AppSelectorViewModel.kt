package app.slipnet.presentation.settings

import android.content.Context
import android.content.pm.ApplicationInfo
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import app.slipnet.data.local.datastore.PreferencesDataStore
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

data class InstalledApp(
    val packageName: String,
    val appName: String,
    val isSystemApp: Boolean
)

data class AppSelectorUiState(
    val apps: List<InstalledApp> = emptyList(),
    val selectedApps: Set<String> = emptySet(),
    val searchQuery: String = "",
    val showSystemApps: Boolean = false,
    val showSelectedOnly: Boolean = false,
    val isLoading: Boolean = true
)

@HiltViewModel
class AppSelectorViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    private val preferencesDataStore: PreferencesDataStore
) : ViewModel() {

    private val _uiState = MutableStateFlow(AppSelectorUiState())
    val uiState: StateFlow<AppSelectorUiState> = _uiState.asStateFlow()

    private var allApps: List<InstalledApp> = emptyList()

    init {
        loadApps()
    }

    private fun loadApps() {
        viewModelScope.launch {
            val savedApps = preferencesDataStore.splitTunnelingApps.first()

            val installed = withContext(Dispatchers.IO) {
                val pm = context.packageManager
                pm.getInstalledApplications(0)
                    .filter { it.packageName != context.packageName }
                    .map { appInfo ->
                        InstalledApp(
                            packageName = appInfo.packageName,
                            appName = pm.getApplicationLabel(appInfo).toString(),
                            isSystemApp = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                        )
                    }
                    .sortedBy { it.appName.lowercase() }
            }

            allApps = installed
            _uiState.value = _uiState.value.copy(
                apps = filterApps(installed, "", showSystem = false, selectedOnly = false, selectedApps = savedApps),
                selectedApps = savedApps,
                isLoading = false
            )
        }
    }

    fun toggleApp(packageName: String) {
        val current = _uiState.value.selectedApps
        val updated = if (packageName in current) current - packageName else current + packageName
        _uiState.value = _uiState.value.copy(
            selectedApps = updated,
            apps = filterApps(allApps, _uiState.value.searchQuery, _uiState.value.showSystemApps, _uiState.value.showSelectedOnly, updated)
        )
        viewModelScope.launch {
            preferencesDataStore.setSplitTunnelingApps(updated)
        }
    }

    fun updateSearchQuery(query: String) {
        val state = _uiState.value
        _uiState.value = state.copy(
            searchQuery = query,
            apps = filterApps(allApps, query, state.showSystemApps, state.showSelectedOnly, state.selectedApps)
        )
    }

    fun toggleSystemApps() {
        val state = _uiState.value
        val show = !state.showSystemApps
        _uiState.value = state.copy(
            showSystemApps = show,
            apps = filterApps(allApps, state.searchQuery, show, state.showSelectedOnly, state.selectedApps)
        )
    }

    fun toggleSelectedOnly() {
        val state = _uiState.value
        val show = !state.showSelectedOnly
        _uiState.value = state.copy(
            showSelectedOnly = show,
            apps = filterApps(allApps, state.searchQuery, state.showSystemApps, show, state.selectedApps)
        )
    }

    private fun filterApps(
        apps: List<InstalledApp>,
        query: String,
        showSystem: Boolean,
        selectedOnly: Boolean,
        selectedApps: Set<String>
    ): List<InstalledApp> {
        return apps.filter { app ->
            (showSystem || !app.isSystemApp) &&
                    (!selectedOnly || app.packageName in selectedApps) &&
                    (query.isBlank() ||
                            app.appName.contains(query, ignoreCase = true) ||
                            app.packageName.contains(query, ignoreCase = true))
        }
    }
}
