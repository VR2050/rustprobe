package io.rustprobe.app

import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import android.system.OsConstants
import java.net.InetAddress
import java.net.InetSocketAddress

class ConnectionOwnerResolver(
    private val connectivityManager: ConnectivityManager,
) {
    fun resolveOwnerUid(query: PendingOwnerQuery): OwnerResolutionTrace? {
        val protocolNumber = when (query.protocol) {
            "Tcp" -> OsConstants.IPPROTO_TCP
            "Udp" -> OsConstants.IPPROTO_UDP
            else -> return null
        }

        val attemptedDirections = mutableListOf<String>()
        val directUid = resolveOwnerUid(
            protocolNumber = protocolNumber,
            localAddress = query.srcAddr,
            localPort = query.srcPort,
            remoteAddress = query.dstAddr,
            remotePort = query.dstPort,
            directionLabel = "forward",
            attemptedDirections = attemptedDirections,
        )
        if (directUid >= 0) {
            return OwnerResolutionTrace(
                uid = directUid,
                matchedDirection = "forward",
                attemptedDirections = attemptedDirections,
            )
        }

        val reverseUid = resolveOwnerUid(
            protocolNumber = protocolNumber,
            localAddress = query.dstAddr,
            localPort = query.dstPort,
            remoteAddress = query.srcAddr,
            remotePort = query.srcPort,
            directionLabel = "reverse",
            attemptedDirections = attemptedDirections,
        )
        if (reverseUid >= 0) {
            return OwnerResolutionTrace(
                uid = reverseUid,
                matchedDirection = "reverse",
                attemptedDirections = attemptedDirections,
            )
        }

        return null
    }

    fun resolveOwnerUid(
        protocolNumber: Int,
        localAddress: String,
        localPort: Int,
        remoteAddress: String,
        remotePort: Int,
        directionLabel: String,
        attemptedDirections: MutableList<String>,
    ): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return Process.INVALID_UID
        }

        attemptedDirections += directionLabel
        val local = InetSocketAddress(InetAddress.getByName(localAddress), localPort)
        val remote = InetSocketAddress(InetAddress.getByName(remoteAddress), remotePort)
        return connectivityManager.getConnectionOwnerUid(protocolNumber, local, remote)
    }
}
