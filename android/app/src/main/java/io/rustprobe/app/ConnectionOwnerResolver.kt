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
    fun resolveOwnerUid(query: PendingOwnerQuery): Int {
        val protocolNumber = when (query.protocol) {
            "Tcp" -> OsConstants.IPPROTO_TCP
            "Udp" -> OsConstants.IPPROTO_UDP
            else -> return Process.INVALID_UID
        }

        return resolveOwnerUid(
            protocolNumber = protocolNumber,
            localAddress = query.srcAddr,
            localPort = query.srcPort,
            remoteAddress = query.dstAddr,
            remotePort = query.dstPort,
        )
    }

    fun resolveOwnerUid(
        protocolNumber: Int,
        localAddress: String,
        localPort: Int,
        remoteAddress: String,
        remotePort: Int,
    ): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return Process.INVALID_UID
        }

        val local = InetSocketAddress(InetAddress.getByName(localAddress), localPort)
        val remote = InetSocketAddress(InetAddress.getByName(remoteAddress), remotePort)
        return connectivityManager.getConnectionOwnerUid(protocolNumber, local, remote)
    }
}
