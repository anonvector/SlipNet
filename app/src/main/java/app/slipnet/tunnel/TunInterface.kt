package app.slipnet.tunnel

import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.nio.ByteBuffer

/**
 * Interface for reading and writing IP packets from the TUN device.
 */
class TunInterface(private val fd: ParcelFileDescriptor) {
    companion object {
        private const val TAG = "TunInterface"
        const val MAX_PACKET_SIZE = 1500
        private const val VERBOSE_LOGGING = false  // Disable for production
    }

    private val inputStream = FileInputStream(fd.fileDescriptor)
    private val outputStream = FileOutputStream(fd.fileDescriptor)

    @Volatile
    private var isClosed = false

    /**
     * Read a packet from the TUN device.
     * Returns null if the device is closed or no data is available.
     */
    suspend fun readPacket(): ByteArray? = withContext(Dispatchers.IO) {
        if (isClosed) return@withContext null

        try {
            val buffer = ByteArray(MAX_PACKET_SIZE)
            val length = inputStream.read(buffer)

            if (length > 0) {
                buffer.copyOf(length)
            } else {
                null
            }
        } catch (e: IOException) {
            if (!isClosed) {
                Log.e(TAG, "Error reading from TUN: ${e.message}")
            }
            null
        }
    }

    /**
     * Write a packet to the TUN device.
     * Returns true if successful.
     */
    suspend fun writePacket(packet: ByteArray): Boolean = withContext(Dispatchers.IO) {
        if (isClosed) return@withContext false

        try {
            outputStream.write(packet)
            true
        } catch (e: IOException) {
            if (!isClosed) {
                Log.e(TAG, "Error writing to TUN: ${e.message}")
            }
            false
        }
    }

    /**
     * Close the TUN interface.
     */
    fun close() {
        isClosed = true
        try {
            inputStream.close()
        } catch (e: Exception) { }
        try {
            outputStream.close()
        } catch (e: Exception) { }
    }
}
