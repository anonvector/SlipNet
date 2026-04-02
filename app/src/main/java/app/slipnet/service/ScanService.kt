package app.slipnet.service

import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Lightweight foreground service that keeps the DNS scan process alive when the
 * app is backgrounded and shows a sticky progress notification.
 *
 * Scan logic stays in DnsScannerViewModel; this service is purely a process-keepalive
 * wrapper that observes ScanStateHolder and updates the notification accordingly.
 * Android is far less likely to kill a process that owns a foreground service.
 */
@AndroidEntryPoint
class ScanService : Service() {

    companion object {
        const val ACTION_STOP = "app.slipnet.SCAN_STOP"
    }

    @Inject
    lateinit var notificationHelper: NotificationHelper

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var observerJob: Job? = null
    private val notificationManager by lazy { getSystemService(NotificationManager::class.java) }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            // User tapped "Stop" in the notification — signal the ViewModel to stop.
            ScanStateHolder.update { it.copy(stopRequested = true) }
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        val initialState = ScanStateHolder.state.value
        val notification = notificationHelper.createScanNotification(
            initialState.scannedCount, initialState.totalCount,
            initialState.workingCount, initialState.isE2eRunning
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NotificationHelper.SCAN_NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            )
        } else {
            startForeground(NotificationHelper.SCAN_NOTIFICATION_ID, notification)
        }

        // Observe scan state and keep the notification current; stop self when done.
        observerJob?.cancel()
        observerJob = serviceScope.launch {
            ScanStateHolder.state.collect { s ->
                if (!s.isScanning && !s.isE2eRunning) {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                    return@collect
                }
                notificationManager.notify(
                    NotificationHelper.SCAN_NOTIFICATION_ID,
                    notificationHelper.createScanNotification(
                        scannedCount = s.scannedCount, totalCount = s.totalCount,
                        workingCount = s.workingCount, isE2eRunning = s.isE2eRunning,
                        isScanning = s.isScanning,
                        e2eTestedCount = s.e2eTestedCount, e2eTotalCount = s.e2eTotalCount,
                        e2ePassedCount = s.e2ePassedCount
                    )
                )
            }
        }

        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        serviceScope.cancel()
        super.onDestroy()
    }
}
