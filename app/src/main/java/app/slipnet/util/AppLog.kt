package app.slipnet.util

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicLong

data class LogEntry(val id: Long, val raw: String, val level: Char)

/**
 * In-memory log buffer that wraps [android.util.Log].
 *
 * Every call forwards to the real Android logger AND appends to a ring buffer
 * that the debug-log UI can observe without spawning a `logcat` process
 * (which triggers Google Play Protect).
 *
 * Usage: replace `import android.util.Log` with
 *        `import app.slipnet.util.AppLog as Log`
 * — no other code changes needed.
 */
object AppLog {
    private const val MAX_LINES = 500
    private val nextId = AtomicLong(0)
    private val buffer = ArrayDeque<LogEntry>()

    // Lazy snapshot — only rebuilt when the debug sheet is open (observerCount > 0).
    private val _lines = MutableStateFlow<List<LogEntry>>(emptyList())
    val lines: StateFlow<List<LogEntry>> = _lines.asStateFlow()

    // Track whether anyone is observing so we skip work when not needed.
    @Volatile var observerCount = 0
        private set

    private val dateFormat = object : ThreadLocal<SimpleDateFormat>() {
        override fun initialValue() = SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US)
    }

    private fun append(level: Char, tag: String, msg: String) {
        val id = nextId.getAndIncrement()
        val entry = if (observerCount > 0) {
            val ts = dateFormat.get()!!.format(Date())
            LogEntry(id, "$ts $level/$tag: $msg", level)
        } else {
            // Lightweight entry — no timestamp formatting when nobody is watching
            LogEntry(id, "$level/$tag: $msg", level)
        }
        synchronized(buffer) {
            buffer.addLast(entry)
            while (buffer.size > MAX_LINES) buffer.removeFirst()
            if (observerCount > 0) {
                _lines.value = ArrayList(buffer)
            }
        }
    }

    /** Call from debug sheet onStart/onStop to enable/disable snapshots. */
    fun addObserver() {
        observerCount++
        // Immediately snapshot current buffer for new observer
        synchronized(buffer) {
            _lines.value = ArrayList(buffer)
        }
    }

    fun removeObserver() {
        observerCount = (observerCount - 1).coerceAtLeast(0)
    }

    fun v(tag: String, msg: String): Int {
        append('V', tag, msg)
        return android.util.Log.v(tag, msg)
    }

    fun d(tag: String, msg: String): Int {
        append('D', tag, msg)
        return android.util.Log.d(tag, msg)
    }

    fun i(tag: String, msg: String): Int {
        append('I', tag, msg)
        return android.util.Log.i(tag, msg)
    }

    fun w(tag: String, msg: String): Int {
        append('W', tag, msg)
        return android.util.Log.w(tag, msg)
    }

    @JvmStatic
    fun w(tag: String, msg: String, tr: Throwable?): Int {
        append('W', tag, if (tr != null) "$msg\n${tr.stackTraceToString()}" else msg)
        return android.util.Log.w(tag, msg, tr)
    }

    fun e(tag: String, msg: String): Int {
        append('E', tag, msg)
        return android.util.Log.e(tag, msg)
    }

    @JvmStatic
    fun e(tag: String, msg: String, tr: Throwable?): Int {
        append('E', tag, if (tr != null) "$msg\n${tr.stackTraceToString()}" else msg)
        return android.util.Log.e(tag, msg, tr)
    }

    fun clear() {
        synchronized(buffer) {
            buffer.clear()
            _lines.value = emptyList()
        }
    }
}
