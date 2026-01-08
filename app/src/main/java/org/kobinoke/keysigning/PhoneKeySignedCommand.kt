package org.kobinoke.keysigning

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.util.UUID

data class PhoneKeySignedCommand(
    val commandId: String,
    val type: String,
    val createdAt: Instant,
    val nonce: ByteArray,             // 16–32 random bytes
    val payload: Map<String, String>,
    var signature: Signature? = null
) {
    data class Signature(
        val algorithm: String,         // "Ed25519"
        val value: String              // Base64-encoded signature
    )
}

/** Canonicalize command JSON (remove signature, sorted keys) */
fun PhoneKeyManager.canonicalizeCommand(command: PhoneKeySignedCommand): ByteArray {
    val json = JSONObject().apply {
        put("commandId", command.commandId)
        put("type", command.type)
        put("createdAt", iso8601String(command.createdAt))
        put("nonce", Base64.encodeToString(command.nonce, Base64.NO_WRAP))
        put("payload", JSONObject(command.payload))
        // omit signature
    }

    val canonicalJson = canonicalizeJSON(json)
    return canonicalJson.toString().toByteArray(StandardCharsets.UTF_8)
}

/** Sign a command and attach signature */
fun PhoneKeyManager.signCommand(command: PhoneKeySignedCommand) {
    val canonicalBytes = canonicalizeCommand(command)
    val signatureBytes = sign(canonicalBytes)
    command.signature = PhoneKeySignedCommand.Signature(
        algorithm = "Ed25519",
        value = Base64.encodeToString(signatureBytes, Base64.NO_WRAP)
    )
}

/** Generate a random nonce for commands (default 16 bytes) */
fun generateNonce(size: Int = 16): ByteArray {
    val bytes = ByteArray(size)
    java.security.SecureRandom().nextBytes(bytes)
    return bytes
}

/** Example helper to create a command with nonce and current time */
fun PhoneKeyManager.createCommand(
    type: String,
    payload: Map<String, String>,
    commandId: String = UUID.randomUUID().toString()
): PhoneKeySignedCommand {
    val cmd = PhoneKeySignedCommand(
        commandId = commandId,
        type = type,
        createdAt = Instant.now(),
        nonce = generateNonce(),
        payload = payload
    )
    signCommand(cmd)
    return cmd
}
