package app.slipnet.presentation

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import androidx.navigation.compose.rememberNavController
import app.slipnet.data.local.datastore.DarkMode
import app.slipnet.data.local.datastore.PreferencesDataStore
import app.slipnet.presentation.navigation.NavGraph
import app.slipnet.presentation.theme.SlipstreamTheme
import app.slipnet.service.VpnConnectionManager
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    @Inject
    lateinit var preferencesDataStore: PreferencesDataStore

    @Inject
    lateinit var connectionManager: VpnConnectionManager

    private val _deepLinkUri = MutableStateFlow<String?>(null)
    val deepLinkUri: StateFlow<String?> = _deepLinkUri.asStateFlow()

    fun consumeDeepLink() {
        _deepLinkUri.value = null
    }

    private var pendingVpnAction: (() -> Unit)? = null

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            pendingVpnAction?.invoke()
        }
        pendingVpnAction = null
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        // Notification permission result - continue regardless
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)

        handleDeepLink(intent)
        requestNotificationPermissionIfNeeded()

        setContent {
            val darkMode by preferencesDataStore.darkMode.collectAsState(initial = DarkMode.SYSTEM)

            SlipstreamTheme(darkMode = darkMode) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val navController = rememberNavController()
                    NavGraph(navController = navController)
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleDeepLink(intent)
    }

    private fun handleDeepLink(intent: Intent?) {
        val uri = intent?.data?.toString()
        if (uri != null && uri.startsWith("slipnet://")) {
            _deepLinkUri.value = uri
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(
                    this,
                    Manifest.permission.POST_NOTIFICATIONS
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    fun requestVpnPermissionAndConnect(onPermissionGranted: () -> Unit) {
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            pendingVpnAction = onPermissionGranted
            vpnPermissionLauncher.launch(vpnIntent)
        } else {
            onPermissionGranted()
        }
    }

    fun hasVpnPermission(): Boolean {
        return VpnService.prepare(this) == null
    }
}
