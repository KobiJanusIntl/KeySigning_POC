package org.kobinoke.keysigning

import java.time.Instant

data class PhoneKeyAcl(
    val aclId: String,
    val lockMac: String,
    val phoneKeyId: String,
    val phonePublicKey: ByteArray, // raw 32-byte key
    val issuedAt: Instant,
    val expiresAt: Instant,
    val schedule: List<TimeWindow>,
    val permissions: Permissions,
    val meta: Meta,
    var signature: Signature? = null
) {
    data class TimeWindow(val start: Instant, val end: Instant)
    data class Permissions(
        val unlock: Boolean,
        val overrideOverlock: Boolean,
        val configWrite: Boolean,
        val fwUpdate: Boolean
    )
    data class Meta(val ttlHours: Int, val timeSource: String, val hwType: String)
    data class Signature(val algorithm: String, val value: String)
}
