package app.slipnet.tunnel

import android.os.ParcelFileDescriptor
import app.slipnet.util.AppLog as Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Interface for reading and writing IP packets from the TUN device.
 */
class TunInterface(private val fd: ParcelFileDescriptor) {
    companion object {
        private const val TAG = "TunInterface"
        const val MAX_PACKET_SIZE = 1500
    }

    private val inputStream = FileInputStream(fd.fileDescriptor)
    private val outputStream = FileOutputStream(fd.fileDescriptor)

    private val isClosed = AtomicBoolean(false)

    /**
     * Read a packet from the TUN device.
     * Returns null if the device is closed or no data is available.
     */
    fun readPacket(): ByteArray? {
        if (isClosed.get()) return null

        val buffer = ByteArray(MAX_PACKET_SIZE)
        return try {
            val length = inputStream.read(buffer)
            if (length > 0) {
                buffer.copyOf(length)
            } else {
                null
            }
        } catch (e: IOException) {
            if (!isClosed.get()) {
                Log.e(TAG, "Error reading from TUN: ${e.message}")
            }
            null
        }
    }

    /**
     * Write a packet to the TUN device.
     * Returns true if successful.
     */
    fun writePacket(packet: ByteArray): Boolean {
        if (isClosed.get()) return false

        return try {
            outputStream.write(packet)
            true
        } catch (e: IOException) {
            if (!isClosed.get()) {
                Log.e(TAG, "Error writing to TUN: ${e.message}")
            }
            false
        }
    }

    /**
     * Check if the interface is closed.
     */
    fun isClosed(): Boolean = isClosed.get()

    /**
     * Close the TUN interface.
     */
    fun close() {
        if (isClosed.getAndSet(true)) return

        try {
            inputStream.close()
        } catch (e: Exception) { }
        try {
            outputStream.close()
        } catch (e: Exception) { }
    }
}
