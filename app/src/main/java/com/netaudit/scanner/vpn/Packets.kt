package com.netaudit.scanner.vpn

import java.nio.ByteBuffer

/** Minimal IPv4 + TCP/UDP packet parsing and building for the userspace forwarder. */
object Packets {

    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

    // ---- IPv4 ----
    fun ipVersion(b: ByteArray) = (b[0].toInt() and 0xF0) ushr 4
    fun ipHeaderLen(b: ByteArray) = (b[0].toInt() and 0x0F) * 4
    fun ipProtocol(b: ByteArray) = b[9].toInt() and 0xFF
    fun ipTotalLen(b: ByteArray) = ((b[2].toInt() and 0xFF) shl 8) or (b[3].toInt() and 0xFF)
    fun ipSrc(b: ByteArray) = readInt(b, 12)
    fun ipDst(b: ByteArray) = readInt(b, 16)

    fun ipToString(v: Int) =
        "${v ushr 24 and 0xff}.${v ushr 16 and 0xff}.${v ushr 8 and 0xff}.${v and 0xff}"

    private fun readInt(b: ByteArray, off: Int) =
        (b[off].toInt() and 0xFF shl 24) or (b[off + 1].toInt() and 0xFF shl 16) or
            (b[off + 2].toInt() and 0xFF shl 8) or (b[off + 3].toInt() and 0xFF)

    // ---- TCP ----
    fun tcpSrcPort(b: ByteArray, ipHl: Int) = ((b[ipHl].toInt() and 0xFF) shl 8) or (b[ipHl + 1].toInt() and 0xFF)
    fun tcpDstPort(b: ByteArray, ipHl: Int) = ((b[ipHl + 2].toInt() and 0xFF) shl 8) or (b[ipHl + 3].toInt() and 0xFF)
    fun tcpSeq(b: ByteArray, ipHl: Int) = uintAt(b, ipHl + 4)
    fun tcpAck(b: ByteArray, ipHl: Int) = uintAt(b, ipHl + 8)
    fun tcpDataOffset(b: ByteArray, ipHl: Int) = ((b[ipHl + 12].toInt() and 0xF0) ushr 4) * 4
    fun tcpFlags(b: ByteArray, ipHl: Int) = b[ipHl + 13].toInt() and 0xFF

    const val FIN = 0x01; const val SYN = 0x02; const val RST = 0x04
    const val PSH = 0x08; const val ACK = 0x10

    private fun uintAt(b: ByteArray, off: Int): Long =
        ((b[off].toLong() and 0xFF) shl 24) or ((b[off + 1].toLong() and 0xFF) shl 16) or
            ((b[off + 2].toLong() and 0xFF) shl 8) or (b[off + 3].toLong() and 0xFF)

    /** Build an IPv4/TCP packet (src/dst are packet-level; for app-bound packets src=remote, dst=tun). */
    fun buildTcp(
        srcIp: Int, dstIp: Int, srcPort: Int, dstPort: Int,
        seq: Long, ack: Long, flags: Int, payload: ByteArray?, window: Int = 65535
    ): ByteArray {
        val plLen = payload?.size ?: 0
        val total = 20 + 20 + plLen
        val buf = ByteBuffer.allocate(total)
        // IP header
        buf.put(0x45.toByte())            // version 4, IHL 5
        buf.put(0)                        // DSCP
        buf.putShort(total.toShort())
        buf.putShort(0)                   // id
        buf.putShort(0x4000.toShort())    // flags: DF
        buf.put(64)                       // TTL
        buf.put(PROTO_TCP.toByte())
        buf.putShort(0)                   // checksum placeholder
        buf.putInt(srcIp)
        buf.putInt(dstIp)
        // TCP header
        buf.putShort(srcPort.toShort())
        buf.putShort(dstPort.toShort())
        buf.putInt(seq.toInt())
        buf.putInt(ack.toInt())
        buf.put((5 shl 4).toByte())       // data offset 5, reserved
        buf.put(flags.toByte())
        buf.putShort(window.toShort())
        buf.putShort(0)                   // checksum placeholder
        buf.putShort(0)                   // urgent ptr
        if (payload != null) buf.put(payload)
        val arr = buf.array()
        ipChecksum(arr, 0, 20)
        tcpUdpChecksum(arr, srcIp, dstIp, PROTO_TCP, 20, 20 + plLen)
        return arr
    }

    fun buildUdp(srcIp: Int, dstIp: Int, srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
        val udpLen = 8 + payload.size
        val total = 20 + udpLen
        val buf = ByteBuffer.allocate(total)
        buf.put(0x45.toByte()); buf.put(0)
        buf.putShort(total.toShort()); buf.putShort(0)
        buf.putShort(0x4000.toShort()); buf.put(64); buf.put(PROTO_UDP.toByte())
        buf.putShort(0); buf.putInt(srcIp); buf.putInt(dstIp)
        buf.putShort(srcPort.toShort()); buf.putShort(dstPort.toShort())
        buf.putShort(udpLen.toShort()); buf.putShort(0)
        buf.put(payload)
        val arr = buf.array()
        ipChecksum(arr, 0, 20)
        tcpUdpChecksum(arr, srcIp, dstIp, PROTO_UDP, 20, 20 + udpLen)
        return arr
    }

    private fun ipChecksum(b: ByteArray, off: Int, len: Int) {
        b[off + 10] = 0; b[off + 11] = 0
        var sum = 0L
        var i = off
        while (i < off + len) {
            sum += ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)
            i += 2
        }
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        val cs = sum.inv().toInt() and 0xFFFF
        b[off + 10] = (cs ushr 8).toByte(); b[off + 11] = (cs and 0xFF).toByte()
    }

    private fun tcpUdpChecksum(b: ByteArray, srcIp: Int, dstIp: Int, proto: Int, l4Off: Int, l4End: Int) {
        val len = l4End - l4Off
        // checksum field location: TCP=16, UDP=6 from l4 start
        val csPos = l4Off + if (proto == PROTO_TCP) 16 else 6
        b[csPos] = 0; b[csPos + 1] = 0
        var sum = 0L
        // pseudo header
        sum += (srcIp ushr 16 and 0xFFFF).toLong(); sum += (srcIp and 0xFFFF).toLong()
        sum += (dstIp ushr 16 and 0xFFFF).toLong(); sum += (dstIp and 0xFFFF).toLong()
        sum += proto.toLong(); sum += len.toLong()
        var i = l4Off
        while (i + 1 < l4End) {
            sum += (((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)).toLong()
            i += 2
        }
        if (i < l4End) sum += ((b[i].toInt() and 0xFF) shl 8).toLong()
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        var cs = sum.inv().toInt() and 0xFFFF
        if (proto == PROTO_UDP && cs == 0) cs = 0xFFFF
        b[csPos] = (cs ushr 8).toByte(); b[csPos + 1] = (cs and 0xFF).toByte()
    }
}
