package app.slipnet.tunnel

import java.net.InetAddress

/**
 * Protocol constants
 */
object Protocol {
    const val TCP = 6
    const val UDP = 17
    const val ICMP = 1
}

/**
 * TCP flags
 */
object TcpFlags {
    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10
    const val URG = 0x20
}

/**
 * Parsed TCP header information
 */
data class TcpHeader(
    val srcPort: Int,
    val dstPort: Int,
    val seqNum: Long,
    val ackNum: Long,
    val dataOffset: Int,
    val flags: Int,
    val windowSize: Int,
    val payload: ByteArray
) {
    val isSyn: Boolean get() = (flags and TcpFlags.SYN) != 0
    val isAck: Boolean get() = (flags and TcpFlags.ACK) != 0
    val isFin: Boolean get() = (flags and TcpFlags.FIN) != 0
    val isRst: Boolean get() = (flags and TcpFlags.RST) != 0
    val isPsh: Boolean get() = (flags and TcpFlags.PSH) != 0

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TcpHeader) return false
        return srcPort == other.srcPort && dstPort == other.dstPort &&
                seqNum == other.seqNum && ackNum == other.ackNum
    }

    override fun hashCode(): Int = srcPort * 31 + dstPort
}

/**
 * Parsed IP packet information
 */
data class IpPacket(
    val version: Int,
    val protocol: Int,
    val srcAddress: InetAddress,
    val dstAddress: InetAddress,
    val tcpHeader: TcpHeader?,
    val rawData: ByteArray
) {
    val isTcp: Boolean get() = protocol == Protocol.TCP
    val isUdp: Boolean get() = protocol == Protocol.UDP

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is IpPacket) return false
        return version == other.version && protocol == other.protocol &&
                srcAddress == other.srcAddress && dstAddress == other.dstAddress
    }

    override fun hashCode(): Int = srcAddress.hashCode() * 31 + dstAddress.hashCode()
}

/**
 * Connection key for NAT table (5-tuple)
 */
data class ConnectionKey(
    val srcAddress: InetAddress,
    val srcPort: Int,
    val dstAddress: InetAddress,
    val dstPort: Int,
    val protocol: Int
) {
    fun reverse(): ConnectionKey = ConnectionKey(
        srcAddress = dstAddress,
        srcPort = dstPort,
        dstAddress = srcAddress,
        dstPort = srcPort,
        protocol = protocol
    )
}

/**
 * IP packet parser
 */
object IpPacketParser {

    /**
     * Parse an IP packet from raw bytes
     */
    fun parse(data: ByteArray): IpPacket? {
        if (data.isEmpty()) return null

        val version = (data[0].toInt() and 0xF0) shr 4

        return when (version) {
            4 -> parseIpv4(data)
            6 -> parseIpv6(data)
            else -> null
        }
    }

    private fun parseIpv4(data: ByteArray): IpPacket? {
        if (data.size < 20) return null

        val ihl = (data[0].toInt() and 0x0F) * 4
        if (data.size < ihl) return null

        val protocol = data[9].toInt() and 0xFF
        val srcAddr = InetAddress.getByAddress(data.copyOfRange(12, 16))
        val dstAddr = InetAddress.getByAddress(data.copyOfRange(16, 20))

        val tcpHeader = if (protocol == Protocol.TCP && data.size >= ihl + 20) {
            parseTcpHeader(data, ihl)
        } else null

        return IpPacket(
            version = 4,
            protocol = protocol,
            srcAddress = srcAddr,
            dstAddress = dstAddr,
            tcpHeader = tcpHeader,
            rawData = data
        )
    }

    private fun parseIpv6(data: ByteArray): IpPacket? {
        if (data.size < 40) return null

        val protocol = data[6].toInt() and 0xFF
        val srcAddr = InetAddress.getByAddress(data.copyOfRange(8, 24))
        val dstAddr = InetAddress.getByAddress(data.copyOfRange(24, 40))

        val tcpHeader = if (protocol == Protocol.TCP && data.size >= 60) {
            parseTcpHeader(data, 40)
        } else null

        return IpPacket(
            version = 6,
            protocol = protocol,
            srcAddress = srcAddr,
            dstAddress = dstAddr,
            tcpHeader = tcpHeader,
            rawData = data
        )
    }

    private fun parseTcpHeader(data: ByteArray, offset: Int): TcpHeader? {
        if (data.size < offset + 20) return null

        val srcPort = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
        val dstPort = ((data[offset + 2].toInt() and 0xFF) shl 8) or (data[offset + 3].toInt() and 0xFF)

        val seqNum = ((data[offset + 4].toLong() and 0xFF) shl 24) or
                ((data[offset + 5].toLong() and 0xFF) shl 16) or
                ((data[offset + 6].toLong() and 0xFF) shl 8) or
                (data[offset + 7].toLong() and 0xFF)

        val ackNum = ((data[offset + 8].toLong() and 0xFF) shl 24) or
                ((data[offset + 9].toLong() and 0xFF) shl 16) or
                ((data[offset + 10].toLong() and 0xFF) shl 8) or
                (data[offset + 11].toLong() and 0xFF)

        val dataOffset = ((data[offset + 12].toInt() and 0xF0) shr 4) * 4
        val flags = data[offset + 13].toInt() and 0xFF
        val windowSize = ((data[offset + 14].toInt() and 0xFF) shl 8) or (data[offset + 15].toInt() and 0xFF)

        val payloadStart = offset + dataOffset
        val payload = if (payloadStart < data.size) {
            data.copyOfRange(payloadStart, data.size)
        } else {
            ByteArray(0)
        }

        return TcpHeader(
            srcPort = srcPort,
            dstPort = dstPort,
            seqNum = seqNum,
            ackNum = ackNum,
            dataOffset = dataOffset,
            flags = flags,
            windowSize = windowSize,
            payload = payload
        )
    }

    /**
     * Extract connection key from a packet
     */
    fun extractConnectionKey(packet: IpPacket): ConnectionKey? {
        val tcpHeader = packet.tcpHeader ?: return null

        return ConnectionKey(
            srcAddress = packet.srcAddress,
            srcPort = tcpHeader.srcPort,
            dstAddress = packet.dstAddress,
            dstPort = tcpHeader.dstPort,
            protocol = packet.protocol
        )
    }
}
