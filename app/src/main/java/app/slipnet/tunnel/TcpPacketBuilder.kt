package app.slipnet.tunnel

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer

/**
 * Builds TCP/IP packets for sending to the TUN device.
 */
object TcpPacketBuilder {

    /**
     * Build a SYN-ACK packet to complete TCP handshake
     */
    fun buildSynAck(
        srcAddr: InetAddress,
        srcPort: Int,
        dstAddr: InetAddress,
        dstPort: Int,
        seqNum: Long,
        ackNum: Long
    ): ByteArray? {
        return when {
            srcAddr is Inet4Address && dstAddr is Inet4Address ->
                buildTcpPacketV4(srcAddr, srcPort, dstAddr, dstPort, seqNum, ackNum,
                    TcpFlags.SYN or TcpFlags.ACK, ByteArray(0), includeMss = true)
            srcAddr is Inet6Address && dstAddr is Inet6Address ->
                buildTcpPacketV6(srcAddr, srcPort, dstAddr, dstPort, seqNum, ackNum,
                    TcpFlags.SYN or TcpFlags.ACK, ByteArray(0), includeMss = true)
            else -> null
        }
    }

    /**
     * Build a data packet with PSH+ACK flags
     */
    fun buildDataPacket(
        srcAddr: InetAddress,
        srcPort: Int,
        dstAddr: InetAddress,
        dstPort: Int,
        seqNum: Long,
        ackNum: Long,
        payload: ByteArray
    ): ByteArray? {
        return when {
            srcAddr is Inet4Address && dstAddr is Inet4Address ->
                buildTcpPacketV4(srcAddr, srcPort, dstAddr, dstPort, seqNum, ackNum,
                    TcpFlags.PSH or TcpFlags.ACK, payload, includeMss = false)
            srcAddr is Inet6Address && dstAddr is Inet6Address ->
                buildTcpPacketV6(srcAddr, srcPort, dstAddr, dstPort, seqNum, ackNum,
                    TcpFlags.PSH or TcpFlags.ACK, payload, includeMss = false)
            else -> null
        }
    }

    /**
     * Build a FIN-ACK packet to close connection
     */
    fun buildFinAck(
        srcAddr: InetAddress,
        srcPort: Int,
        dstAddr: InetAddress,
        dstPort: Int,
        seqNum: Long,
        ackNum: Long
    ): ByteArray? {
        return when {
            srcAddr is Inet4Address && dstAddr is Inet4Address ->
                buildTcpPacketV4(srcAddr, srcPort, dstAddr, dstPort, seqNum, ackNum,
                    TcpFlags.FIN or TcpFlags.ACK, ByteArray(0), includeMss = false)
            srcAddr is Inet6Address && dstAddr is Inet6Address ->
                buildTcpPacketV6(srcAddr, srcPort, dstAddr, dstPort, seqNum, ackNum,
                    TcpFlags.FIN or TcpFlags.ACK, ByteArray(0), includeMss = false)
            else -> null
        }
    }

    /**
     * Build an ACK packet (no data)
     */
    fun buildAck(
        srcAddr: InetAddress,
        srcPort: Int,
        dstAddr: InetAddress,
        dstPort: Int,
        seqNum: Long,
        ackNum: Long
    ): ByteArray? {
        return when {
            srcAddr is Inet4Address && dstAddr is Inet4Address ->
                buildTcpPacketV4(srcAddr, srcPort, dstAddr, dstPort, seqNum, ackNum,
                    TcpFlags.ACK, ByteArray(0), includeMss = false)
            srcAddr is Inet6Address && dstAddr is Inet6Address ->
                buildTcpPacketV6(srcAddr, srcPort, dstAddr, dstPort, seqNum, ackNum,
                    TcpFlags.ACK, ByteArray(0), includeMss = false)
            else -> null
        }
    }

    /**
     * Build an RST packet to reset connection
     */
    fun buildRst(
        srcAddr: InetAddress,
        srcPort: Int,
        dstAddr: InetAddress,
        dstPort: Int,
        seqNum: Long,
        ackNum: Long
    ): ByteArray? {
        return when {
            srcAddr is Inet4Address && dstAddr is Inet4Address ->
                buildTcpPacketV4(srcAddr, srcPort, dstAddr, dstPort, seqNum, ackNum,
                    TcpFlags.RST or TcpFlags.ACK, ByteArray(0), includeMss = false)
            srcAddr is Inet6Address && dstAddr is Inet6Address ->
                buildTcpPacketV6(srcAddr, srcPort, dstAddr, dstPort, seqNum, ackNum,
                    TcpFlags.RST or TcpFlags.ACK, ByteArray(0), includeMss = false)
            else -> null
        }
    }

    private fun buildTcpPacketV4(
        srcAddr: Inet4Address,
        srcPort: Int,
        dstAddr: Inet4Address,
        dstPort: Int,
        seqNum: Long,
        ackNum: Long,
        flags: Int,
        payload: ByteArray,
        includeMss: Boolean
    ): ByteArray {
        val tcpHeaderLen = if (includeMss) 24 else 20
        val ipHeaderLen = 20
        val totalLen = ipHeaderLen + tcpHeaderLen + payload.size

        val buffer = ByteBuffer.allocate(totalLen)

        // IPv4 header
        buffer.put((0x45).toByte()) // Version + IHL
        buffer.put(0x00.toByte()) // DSCP + ECN
        buffer.putShort(totalLen.toShort()) // Total length
        buffer.putShort(0x0000.toShort()) // Identification
        buffer.putShort(0x4000.toShort()) // Flags (Don't Fragment) + Fragment offset
        buffer.put(64.toByte()) // TTL
        buffer.put(Protocol.TCP.toByte()) // Protocol
        buffer.putShort(0x0000.toShort()) // Header checksum (placeholder)
        buffer.put(srcAddr.address) // Source IP
        buffer.put(dstAddr.address) // Destination IP

        // Calculate and set IP checksum
        val ipHeader = buffer.array().copyOfRange(0, ipHeaderLen)
        val ipChecksum = calculateIpChecksum(ipHeader)
        buffer.putShort(10, ipChecksum.toShort())

        // TCP header
        val tcpStart = buffer.position()
        buffer.putShort(srcPort.toShort()) // Source port
        buffer.putShort(dstPort.toShort()) // Destination port
        buffer.putInt(seqNum.toInt()) // Sequence number
        buffer.putInt(ackNum.toInt()) // Acknowledgment number
        buffer.put(((tcpHeaderLen / 4) shl 4).toByte()) // Data offset
        buffer.put(flags.toByte()) // Flags
        buffer.putShort(0xFFFF.toShort()) // Window size
        buffer.putShort(0x0000.toShort()) // Checksum (placeholder)
        buffer.putShort(0x0000.toShort()) // Urgent pointer

        // MSS option for SYN-ACK
        if (includeMss) {
            buffer.put(0x02.toByte()) // Kind: MSS
            buffer.put(0x04.toByte()) // Length: 4
            buffer.putShort(1460.toShort()) // MSS value
        }

        // Payload
        if (payload.isNotEmpty()) {
            buffer.put(payload)
        }

        // Calculate and set TCP checksum
        val tcpSegment = buffer.array().copyOfRange(tcpStart, totalLen)
        val tcpChecksum = calculateTcpChecksumV4(srcAddr, dstAddr, tcpSegment)
        buffer.putShort(tcpStart + 16, tcpChecksum.toShort())

        return buffer.array()
    }

    private fun buildTcpPacketV6(
        srcAddr: Inet6Address,
        srcPort: Int,
        dstAddr: Inet6Address,
        dstPort: Int,
        seqNum: Long,
        ackNum: Long,
        flags: Int,
        payload: ByteArray,
        includeMss: Boolean
    ): ByteArray {
        val tcpHeaderLen = if (includeMss) 24 else 20
        val ipHeaderLen = 40
        val tcpLen = tcpHeaderLen + payload.size
        val totalLen = ipHeaderLen + tcpLen

        val buffer = ByteBuffer.allocate(totalLen)

        // IPv6 header
        buffer.put(0x60.toByte()) // Version + Traffic class (high 4 bits)
        buffer.put(0x00.toByte()) // Traffic class (low) + Flow label
        buffer.putShort(0x0000.toShort()) // Flow label
        buffer.putShort(tcpLen.toShort()) // Payload length
        buffer.put(Protocol.TCP.toByte()) // Next header
        buffer.put(64.toByte()) // Hop limit
        buffer.put(srcAddr.address) // Source IP
        buffer.put(dstAddr.address) // Destination IP

        // TCP header
        val tcpStart = buffer.position()
        buffer.putShort(srcPort.toShort()) // Source port
        buffer.putShort(dstPort.toShort()) // Destination port
        buffer.putInt(seqNum.toInt()) // Sequence number
        buffer.putInt(ackNum.toInt()) // Acknowledgment number
        buffer.put(((tcpHeaderLen / 4) shl 4).toByte()) // Data offset
        buffer.put(flags.toByte()) // Flags
        buffer.putShort(0xFFFF.toShort()) // Window size
        buffer.putShort(0x0000.toShort()) // Checksum (placeholder)
        buffer.putShort(0x0000.toShort()) // Urgent pointer

        // MSS option for SYN-ACK
        if (includeMss) {
            buffer.put(0x02.toByte()) // Kind: MSS
            buffer.put(0x04.toByte()) // Length: 4
            buffer.putShort(1460.toShort()) // MSS value
        }

        // Payload
        if (payload.isNotEmpty()) {
            buffer.put(payload)
        }

        // Calculate and set TCP checksum
        val tcpSegment = buffer.array().copyOfRange(tcpStart, totalLen)
        val tcpChecksum = calculateTcpChecksumV6(srcAddr, dstAddr, tcpSegment)
        buffer.putShort(tcpStart + 16, tcpChecksum.toShort())

        return buffer.array()
    }

    /**
     * Calculate IPv4 header checksum
     */
    private fun calculateIpChecksum(header: ByteArray): Int {
        var sum = 0L

        var i = 0
        while (i < header.size) {
            if (i == 10) { // Skip checksum field
                i += 2
                continue
            }
            val word = if (i + 1 < header.size) {
                ((header[i].toInt() and 0xFF) shl 8) or (header[i + 1].toInt() and 0xFF)
            } else {
                (header[i].toInt() and 0xFF) shl 8
            }
            sum += word
            i += 2
        }

        while (sum > 0xFFFF) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }

        return (sum.inv() and 0xFFFF).toInt()
    }

    /**
     * Calculate TCP checksum for IPv4
     */
    private fun calculateTcpChecksumV4(
        srcAddr: Inet4Address,
        dstAddr: Inet4Address,
        tcpSegment: ByteArray
    ): Int {
        var sum = 0L

        // Pseudo header: src IP
        val srcBytes = srcAddr.address
        sum += ((srcBytes[0].toInt() and 0xFF) shl 8) or (srcBytes[1].toInt() and 0xFF)
        sum += ((srcBytes[2].toInt() and 0xFF) shl 8) or (srcBytes[3].toInt() and 0xFF)

        // Pseudo header: dst IP
        val dstBytes = dstAddr.address
        sum += ((dstBytes[0].toInt() and 0xFF) shl 8) or (dstBytes[1].toInt() and 0xFF)
        sum += ((dstBytes[2].toInt() and 0xFF) shl 8) or (dstBytes[3].toInt() and 0xFF)

        // Pseudo header: protocol
        sum += Protocol.TCP

        // Pseudo header: TCP length
        sum += tcpSegment.size

        // TCP segment
        var i = 0
        while (i < tcpSegment.size) {
            val word = if (i + 1 < tcpSegment.size) {
                ((tcpSegment[i].toInt() and 0xFF) shl 8) or (tcpSegment[i + 1].toInt() and 0xFF)
            } else {
                (tcpSegment[i].toInt() and 0xFF) shl 8
            }
            // Skip checksum field (bytes 16-17)
            if (i != 16) {
                sum += word
            }
            i += 2
        }

        while (sum > 0xFFFF) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }

        return (sum.inv() and 0xFFFF).toInt()
    }

    /**
     * Calculate TCP checksum for IPv6
     */
    private fun calculateTcpChecksumV6(
        srcAddr: Inet6Address,
        dstAddr: Inet6Address,
        tcpSegment: ByteArray
    ): Int {
        var sum = 0L

        // Pseudo header: src IP (16 bytes)
        val srcBytes = srcAddr.address
        for (i in srcBytes.indices step 2) {
            sum += ((srcBytes[i].toInt() and 0xFF) shl 8) or (srcBytes[i + 1].toInt() and 0xFF)
        }

        // Pseudo header: dst IP (16 bytes)
        val dstBytes = dstAddr.address
        for (i in dstBytes.indices step 2) {
            sum += ((dstBytes[i].toInt() and 0xFF) shl 8) or (dstBytes[i + 1].toInt() and 0xFF)
        }

        // Pseudo header: TCP length (32-bit)
        sum += tcpSegment.size

        // Pseudo header: next header (TCP = 6)
        sum += Protocol.TCP

        // TCP segment
        var i = 0
        while (i < tcpSegment.size) {
            val word = if (i + 1 < tcpSegment.size) {
                ((tcpSegment[i].toInt() and 0xFF) shl 8) or (tcpSegment[i + 1].toInt() and 0xFF)
            } else {
                (tcpSegment[i].toInt() and 0xFF) shl 8
            }
            // Skip checksum field (bytes 16-17)
            if (i != 16) {
                sum += word
            }
            i += 2
        }

        while (sum > 0xFFFF) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }

        return (sum.inv() and 0xFFFF).toInt()
    }
}
