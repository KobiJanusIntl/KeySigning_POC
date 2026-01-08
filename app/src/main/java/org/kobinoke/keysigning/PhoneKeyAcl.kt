package org.kobinoke.keysigning

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.time.Instant

data class PhoneKeyAcl(
    val aclId: String,
    val lockMac: String,
    val phoneKeyId: String,
    val phonePublicKey: String,
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

/** Canonicalize ACL into bytes for signing */
fun PhoneKeyManager.canonicalizeAcl(acl: PhoneKeyAcl): ByteArray {
    val json = JSONObject().apply {
        put("aclId", acl.aclId)
        put("lockMac", acl.lockMac)
        put("phoneKeyId", acl.phoneKeyId)
        put("phonePublicKey", acl.phonePublicKey)
        put("issuedAt", iso8601String(acl.issuedAt))
        put("expiresAt", iso8601String(acl.expiresAt))
        put("schedule", JSONArray().apply {
            acl.schedule.forEach { w ->
                put(JSONObject().apply {
                    put("start", iso8601String(w.start))
                    put("end", iso8601String(w.end))
                })
            }
        })
        put("permissions", JSONObject().apply {
            put("unlock", acl.permissions.unlock)
            put("overrideOverlock", acl.permissions.overrideOverlock)
            put("configWrite", acl.permissions.configWrite)
            put("fwUpdate", acl.permissions.fwUpdate)
        })
        put("meta", JSONObject().apply {
            put("ttlHours", acl.meta.ttlHours)
            put("timeSource", acl.meta.timeSource)
            put("hwType", acl.meta.hwType)
        })
        // omit signature field
    }

    val canonicalJson = canonicalizeJSON(json)
    return canonicalJson.toString().toByteArray(StandardCharsets.UTF_8)
}

/** Sign ACL and attach signature */
fun PhoneKeyManager.signAcl(acl: PhoneKeyAcl) {
    val canonicalBytes = canonicalizeAcl(acl)
    val signatureBytes = sign(canonicalBytes)
    acl.signature = PhoneKeyAcl.Signature(
        algorithm = "Ed25519",
        value = Base64.encodeToString(signatureBytes, Base64.NO_WRAP)
    )
}
