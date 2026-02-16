package app.slipnet.tunnel

import app.slipnet.util.AppLog as Log
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.Socket

/**
 * Manages a single TCP connection through the tunnel.
 */
class TunnelConnection(
    private val streamId: Long,
    private val srcAddr: InetAddress,
    private val srcPort: Int,
    private val dstAddr: InetAddress,
    private val dstPort: Int,
    private val clientIsn: Long,
    private val socket: Socket,
    private val onPacketToTun: suspend (ByteArray) -> Unit,
    private val onConnectionClosed: (Long) -> Unit,
    // Optional: pre-established sequence numbers from early SYN-ACK
    initialSeqNum: Long? = null,
    initialAckNum: Long? = null,
    private val bufferedData: List<ByteArray> = emptyList(),
    private val verboseLogging: Boolean = false
) {
    companion object {
        private const val TAG = "TunnelConnection"
        private const val BUFFER_SIZE = 65536  // 64KB buffer
        // Max TCP payload to respect MTU 1500 (1500 - 20 IP - 20 TCP = 1460)
        private const val MAX_TCP_PAYLOAD = 1460
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Data channel for sending data from app to tunnel
    private val outboundChannel = Channel<ByteArray>(32)

    // Sequence numbers - use provided values or generate new ones
    private val ourIsn: Long = initialSeqNum?.minus(1) ?: (Math.random() * Int.MAX_VALUE).toLong()
    private var ourSeqNum: Long = initialSeqNum ?: ourIsn
    private var clientAckNum: Long = initialAckNum ?: (clientIsn + 1) // ACK the SYN

    // Track if SYN-ACK was already sent (for early SYN-ACK case)
    private var synAckSent: Boolean = initialSeqNum != null

    @Volatile
    private var isRunning = true

    @Volatile
    private var isClosing = false

    private var inputStream: InputStream? = null
    private var outputStream: OutputStream? = null

    /**
     * Start the connection handler
     */
    fun start() {
        try {
            if (verboseLogging) Log.d(TAG, "Starting connection $streamId: socket connected=${socket.isConnected}, closed=${socket.isClosed}")

            // Configure socket for better performance
            socket.tcpNoDelay = true

            inputStream = socket.getInputStream()
            outputStream = socket.getOutputStream()

            if (verboseLogging) Log.d(TAG, "Connection $streamId: got streams")

            // Send SYN-ACK if not already sent (early SYN-ACK case)
            if (!synAckSent) {
                scope.launch {
                    sendSynAck()
                }
            } else {
                if (verboseLogging) Log.d(TAG, "[$streamId] SYN-ACK already sent (early)")
            }

            // Send any buffered data to the tunnel
            if (bufferedData.isNotEmpty()) {
                scope.launch {
                    try {
                        if (verboseLogging) Log.d(TAG, "[$streamId] Sending ${bufferedData.size} buffered chunks to tunnel")
                        val out = outputStream ?: return@launch
                        for (data in bufferedData) {
                            if (!isRunning || socket.isClosed) break
                            out.write(data)
                            if (verboseLogging) Log.d(TAG, "[$streamId] Sent buffered ${data.size} bytes")
                        }
                        out.flush()
                    } catch (e: Exception) {
                        if (verboseLogging) Log.d(TAG, "[$streamId] Error sending buffered data: ${e.message}")
                    }
                }
            }

            // Start reader (tunnel -> TUN)
            scope.launch {
                if (verboseLogging) Log.i(TAG, "Reader coroutine starting for connection $streamId")
                readFromTunnel()
            }

            // Start writer (app -> tunnel)
            scope.launch {
                if (verboseLogging) Log.i(TAG, "Writer coroutine starting for connection $streamId")
                writeToTunnel()
            }

            if (verboseLogging) Log.i(TAG, "Connection $streamId started for $dstAddr:$dstPort")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start connection $streamId: ${e.message}", e)
            close()
        }
    }

    /**
     * Resend SYN-ACK (for SYN retransmits)
     */
    fun resendSynAck() {
        scope.launch {
            val packet = TcpPacketBuilder.buildSynAck(
                srcAddr = dstAddr,
                srcPort = dstPort,
                dstAddr = srcAddr,
                dstPort = srcPort,
                seqNum = ourIsn,
                ackNum = clientAckNum
            )
            if (packet != null) {
                if (verboseLogging) Log.d(TAG, "[$streamId] >>> SYN-ACK (retransmit)")
                onPacketToTun(packet)
            }
        }
    }

    /**
     * Send data to the tunnel (from app)
     */
    suspend fun sendData(data: ByteArray) {
        if (!isRunning) return
        if (isClosing) {
            if (verboseLogging) Log.v(TAG, "[$streamId] Ignoring data during graceful close")
            return
        }
        try {
            outboundChannel.send(data)
        } catch (e: kotlinx.coroutines.channels.ClosedSendChannelException) {
            if (verboseLogging) Log.v(TAG, "[$streamId] Channel closed, ignoring ${data.size} bytes")
        } catch (e: Exception) {
            Log.w(TAG, "[$streamId] Failed to queue data: ${e.message}")
        }
    }

    /**
     * Handle FIN from client - client is done sending, but we may still receive data from tunnel
     */
    fun handleClientFin() {
        if (isClosing) return
        isClosing = true

        if (verboseLogging) Log.d(TAG, "[$streamId] Client FIN received, stopping outbound")

        clientAckNum += 1
        outboundChannel.close()

        scope.launch {
            try {
                val packet = TcpPacketBuilder.buildAck(
                    srcAddr = dstAddr,
                    srcPort = dstPort,
                    dstAddr = srcAddr,
                    dstPort = srcPort,
                    seqNum = ourSeqNum,
                    ackNum = clientAckNum
                )
                if (packet != null) {
                    if (verboseLogging) Log.d(TAG, "[$streamId] >>> ACK for FIN")
                    onPacketToTun(packet)
                }

                delay(10000)

                if (isRunning) {
                    if (verboseLogging) Log.d(TAG, "[$streamId] Tunnel didn't close in time, forcing close")
                    close()
                }
            } catch (e: Exception) {
                Log.e(TAG, "[$streamId] Error handling client FIN: ${e.message}")
            }
        }
    }

    /**
     * Close the connection immediately
     */
    fun close() {
        if (!isRunning) return

        if (isClosing) {
            forceClose()
            return
        }

        isClosing = true
        if (verboseLogging) Log.d(TAG, "Closing connection $streamId")

        scope.launch {
            try {
                sendFinAck()
            } catch (e: Exception) {
                Log.e(TAG, "Error sending FIN: ${e.message}")
            }
        }

        forceClose()
    }

    private fun forceClose() {
        if (!isRunning) return
        isRunning = false

        if (verboseLogging) Log.d(TAG, "[$streamId] Force closing")

        try {
            socket.close()
        } catch (e: Exception) { }

        outboundChannel.close()
        scope.cancel()

        onConnectionClosed(streamId)
    }

    private suspend fun sendSynAck() {
        val packet = TcpPacketBuilder.buildSynAck(
            srcAddr = dstAddr,
            srcPort = dstPort,
            dstAddr = srcAddr,
            dstPort = srcPort,
            seqNum = ourIsn,
            ackNum = clientAckNum
        )

        if (packet != null) {
            if (verboseLogging) Log.i(TAG, "[$streamId] >>> SYN-ACK: $dstAddr:$dstPort -> $srcAddr:$srcPort")
            onPacketToTun(packet)
            ourSeqNum = ourIsn + 1
        } else {
            Log.e(TAG, "[$streamId] Failed to build SYN-ACK")
        }
    }

    private suspend fun sendFinAck() {
        val packet = TcpPacketBuilder.buildFinAck(
            srcAddr = dstAddr,
            srcPort = dstPort,
            dstAddr = srcAddr,
            dstPort = srcPort,
            seqNum = ourSeqNum,
            ackNum = clientAckNum
        )

        if (packet != null) {
            if (verboseLogging) Log.i(TAG, "[$streamId] >>> FIN-ACK")
            onPacketToTun(packet)
        } else {
            Log.e(TAG, "[$streamId] Failed to build FIN-ACK")
        }
    }

    private suspend fun readFromTunnel() {
        if (verboseLogging) Log.i(TAG, "Reader task started for $streamId")
        var tunnelClosed = false
        val buffer = ByteArray(BUFFER_SIZE)

        try {
            val input = inputStream ?: return

            while (isRunning) {
                if (socket.isClosed || !socket.isConnected) {
                    break
                }

                val bytesRead = input.read(buffer)

                if (bytesRead < 0) {
                    if (verboseLogging) Log.d(TAG, "[$streamId] Tunnel closed (EOF)")
                    tunnelClosed = true
                    break
                }

                if (bytesRead > 0) {
                    if (verboseLogging) Log.v(TAG, "[$streamId] Read $bytesRead bytes from tunnel")
                    sendDataToTun(buffer, bytesRead)
                }
            }
        } catch (e: java.net.SocketException) {
            if (isClosing) {
                if (verboseLogging) Log.d(TAG, "[$streamId] Socket closed during graceful shutdown")
            } else {
                Log.w(TAG, "[$streamId] Socket exception in reader: ${e.message}")
            }
            tunnelClosed = true
        } catch (e: java.io.IOException) {
            Log.w(TAG, "[$streamId] IO exception in reader: ${e.message}")
            tunnelClosed = true
        } catch (e: Exception) {
            if (e is kotlinx.coroutines.CancellationException) {
                if (verboseLogging) Log.d(TAG, "[$streamId] Reader cancelled")
            } else {
                Log.e(TAG, "[$streamId] Error reading from tunnel: ${e.message}", e)
            }
        }

        if (verboseLogging) Log.i(TAG, "Reader task exiting for $streamId (tunnelClosed=$tunnelClosed)")

        if (tunnelClosed && isRunning) {
            try {
                sendFinAck()
            } catch (e: Exception) {
                Log.e(TAG, "[$streamId] Error sending FIN: ${e.message}")
            }
        }

        close()
    }

    /**
     * Send data to TUN, segmenting if necessary.
     */
    private suspend fun sendDataToTun(buffer: ByteArray, length: Int) {
        if (length <= MAX_TCP_PAYLOAD) {
            val data = buffer.copyOf(length)
            sendSinglePacket(data)
        } else {
            // Segment data
            if (verboseLogging) Log.d(TAG, "[$streamId] Segmenting $length bytes into chunks of $MAX_TCP_PAYLOAD")
            var offset = 0
            while (offset < length) {
                val chunkSize = minOf(MAX_TCP_PAYLOAD, length - offset)
                val chunk = buffer.copyOfRange(offset, offset + chunkSize)
                sendSinglePacket(chunk)
                offset += chunkSize
            }
        }
    }

    private suspend fun sendSinglePacket(data: ByteArray) {
        val packet = TcpPacketBuilder.buildDataPacket(
            srcAddr = dstAddr,
            srcPort = dstPort,
            dstAddr = srcAddr,
            dstPort = srcPort,
            seqNum = ourSeqNum,
            ackNum = clientAckNum,
            payload = data
        )

        if (packet != null) {
            if (verboseLogging) Log.v(TAG, "[$streamId] >>> DATA: len=${data.size}")
            onPacketToTun(packet)
            ourSeqNum += data.size
        } else {
            Log.e(TAG, "[$streamId] Failed to build data packet for ${data.size} bytes")
        }
    }

    /**
     * Send an ACK to the client
     */
    suspend fun sendAck() {
        val packet = TcpPacketBuilder.buildAck(
            srcAddr = dstAddr,
            srcPort = dstPort,
            dstAddr = srcAddr,
            dstPort = srcPort,
            seqNum = ourSeqNum,
            ackNum = clientAckNum
        )

        if (packet != null) {
            if (verboseLogging) Log.v(TAG, "[$streamId] >>> ACK")
            onPacketToTun(packet)
        }
    }

    private suspend fun writeToTunnel() {
        if (verboseLogging) Log.i(TAG, "Writer task started for $streamId")
        try {
            val out = outputStream ?: return

            for (data in outboundChannel) {
                if (!isRunning) {
                    if (verboseLogging) Log.d(TAG, "[$streamId] Writer exiting (not running)")
                    break
                }

                if (socket.isClosed || !socket.isConnected) {
                    Log.w(TAG, "[$streamId] Socket not connected, discarding ${data.size} bytes")
                    break
                }

                if (verboseLogging) Log.v(TAG, "[$streamId] Writing ${data.size} bytes to tunnel")
                out.write(data)
                out.flush()
            }
        } catch (e: kotlinx.coroutines.channels.ClosedReceiveChannelException) {
            if (verboseLogging) Log.d(TAG, "[$streamId] Outbound channel closed (client FIN)")
        } catch (e: java.net.SocketException) {
            Log.w(TAG, "[$streamId] Socket exception in writer: ${e.message}")
        } catch (e: java.io.IOException) {
            Log.w(TAG, "[$streamId] IO exception in writer: ${e.message}")
        } catch (e: Exception) {
            if (e is kotlinx.coroutines.CancellationException) {
                if (verboseLogging) Log.d(TAG, "[$streamId] Writer cancelled")
            } else {
                Log.e(TAG, "[$streamId] Error writing to tunnel: ${e.message}", e)
            }
        }

        if (verboseLogging) Log.i(TAG, "Writer task exiting for $streamId")
        if (!isClosing) {
            close()
        }
    }

    /**
     * Handle ACK from client
     */
    fun handleAck(ackNum: Long) {
        if (verboseLogging) Log.v(TAG, "[$streamId] <<< ACK received: ack=$ackNum")
    }

    /**
     * Update client sequence based on received data
     */
    fun updateClientSeq(seqNum: Long, dataLen: Int) {
        val expectedAck = seqNum + dataLen
        if (expectedAck > clientAckNum) {
            clientAckNum = expectedAck
        }
    }
}
