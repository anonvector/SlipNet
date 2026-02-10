package app.slipnet.presentation.home

import android.os.Process
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.BufferedReader
import java.io.InputStreamReader

data class LogLine(val raw: String, val level: Char)

object LogReader {

    private val TAGS = listOf(
        "SlipNetVpnService",
        "DnsttBridge",
        "SlipstreamBridge",
        "SlipstreamSocksBridge",
        "SshTunnelBridge",
        "HevSocks5Tunnel",
        "DohBridge",
        "KotlinTunnelManager"
    )

    private const val MAX_LINES = 500

    fun start(scope: CoroutineScope): Triple<SnapshotStateList<LogLine>, Job, () -> Unit> {
        val lines = mutableStateListOf<LogLine>()

        val cmd = mutableListOf("logcat", "-v", "time", "-T", "$MAX_LINES", "--pid=${Process.myPid()}")
        TAGS.forEach { cmd.add("$it:*") }
        cmd.add("*:S") // silence everything else

        var process: java.lang.Process? = null

        val job = scope.launch(Dispatchers.IO) {
            try {
                process = Runtime.getRuntime().exec(cmd.toTypedArray())
                val reader = BufferedReader(InputStreamReader(process!!.inputStream))
                var line: String?
                while (isActive) {
                    line = reader.readLine() ?: break
                    val level = parseLevel(line)
                    val logLine = LogLine(raw = line, level = level)
                    launch(Dispatchers.Main) {
                        lines.add(logLine)
                        while (lines.size > MAX_LINES) {
                            lines.removeAt(0)
                        }
                    }
                }
            } catch (_: Exception) {
            } finally {
                process?.destroy()
            }
        }

        val clear: () -> Unit = { lines.clear() }

        return Triple(lines, job, clear)
    }

    private fun parseLevel(line: String): Char {
        // logcat -v time format: "MM-DD HH:MM:SS.mmm D/Tag( PID): message"
        // The level character is at position after the timestamp
        val match = Regex("""^\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+([VDIWEFS])\/""").find(line)
        return match?.groupValues?.get(1)?.firstOrNull() ?: 'I'
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DebugLogSheet(onDismiss: () -> Unit) {
    val sheetState = rememberModalBottomSheetState(
        skipPartiallyExpanded = false,
        confirmValueChange = { true }
    )
    val (lines, job, clear) = remember { LogReader.start(CoroutineScope(Dispatchers.Default)) }
    val listState = rememberLazyListState()
    val clipboardManager = LocalClipboardManager.current

    DisposableEffect(Unit) {
        onDispose {
            job.cancel()
        }
    }

    // Auto-scroll to bottom when new lines arrive
    LaunchedEffect(lines.size) {
        if (lines.isNotEmpty()) {
            listState.animateScrollToItem(lines.size - 1)
        }
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .defaultMinSize(minHeight = 500.dp)
                .fillMaxHeight(0.95f)
        ) {
            // Header
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Debug Logs",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.weight(1f)
                )
                Text(
                    text = "${lines.size} lines",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.width(8.dp))
                IconButton(onClick = {
                    val text = lines.joinToString("\n") { it.raw }
                    clipboardManager.setText(AnnotatedString(text))
                }) {
                    Icon(
                        Icons.Default.ContentCopy,
                        contentDescription = "Copy logs",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                IconButton(onClick = clear) {
                    Icon(
                        Icons.Default.DeleteSweep,
                        contentDescription = "Clear logs",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                IconButton(onClick = onDismiss) {
                    Icon(
                        Icons.Default.Close,
                        contentDescription = "Close",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            // Log lines
            val horizontalScrollState = rememberScrollState()
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .padding(horizontal = 8.dp)
                    .horizontalScroll(horizontalScrollState)
            ) {
                items(lines, key = null) { logLine ->
                    Text(
                        text = logLine.raw,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        lineHeight = 15.sp,
                        color = levelColor(logLine.level),
                        softWrap = false,
                        modifier = Modifier.padding(vertical = 1.dp)
                    )
                }
            }
        }
    }
}

@Composable
private fun levelColor(level: Char): Color {
    return when (level) {
        'E' -> MaterialTheme.colorScheme.error
        'W' -> Color(0xFFFF9800)
        'D' -> MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
        'V' -> MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
        else -> MaterialTheme.colorScheme.onSurface
    }
}
