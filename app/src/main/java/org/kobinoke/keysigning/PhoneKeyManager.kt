package org.kobinoke.keysigning

import android.content.Context
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.signature.SignatureConfig
import com.google.crypto.tink.signature.SignatureKeyTemplates
import com.google.crypto.tink.signature.PublicKeySignFactory
import com.google.crypto.tink.JsonKeysetReader
import com.google.crypto.tink.JsonKeysetWriter
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.util.UUID

class PhoneKeyManager(context: Context) {

    init {
        SignatureConfig.register() // Initialize Tink
    }

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        "phone_keys",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    private var keyHandle: KeysetHandle? = null

    /** Generate or load Ed25519 keypair */
    fun ensureKeys(): KeysetHandle {
        val savedKey = prefs.getString("ed25519_seed", null)
        if (savedKey != null) {
            keyHandle = CleartextKeysetHandle.read(JsonKeysetReader.withString(savedKey))
        } else {
            keyHandle = KeysetHandle.generateNew(SignatureKeyTemplates.ED25519)

            val baos = ByteArrayOutputStream()
            CleartextKeysetHandle.write(keyHandle, JsonKeysetWriter.withOutputStream(baos))
            prefs.edit().putString("ed25519_seed", baos.toString(StandardCharsets.UTF_8.name())).apply()
        }
        return keyHandle!!
    }

    /** Sign arbitrary data */
    fun sign(data: ByteArray): ByteArray {
        val handle = keyHandle ?: ensureKeys()
        val signer = PublicKeySignFactory.getPrimitive(handle)
        return signer.sign(data)
    }

    /** Delete stored keys */
    fun destroyKeys() {
        prefs.edit().remove("ed25519_seed").apply()
        keyHandle = null
    }

    /** Return raw 32-byte Ed25519 public key (exact iOS parity) */
    fun getRawPublicKey(): ByteArray {
        val handle = keyHandle ?: ensureKeys()
        val publicHandle = handle.publicKeysetHandle

        val baos = ByteArrayOutputStream()
        CleartextKeysetHandle.write(publicHandle, JsonKeysetWriter.withOutputStream(baos))
        val json = baos.toString(StandardCharsets.UTF_8.name())

        val keysetJson = JSONObject(json)
        val keyArray = keysetJson.getJSONArray("key")
        val keyObj = keyArray.getJSONObject(0)
        val keyData = keyObj.getJSONObject("keyData")
        val keyBytesBase64 = keyData.getString("value")
        return Base64.decode(keyBytesBase64, Base64.NO_WRAP)
    }

    /** KeyId derived from private seed (SHA256 -> UUID) */
    fun getKeyId(): String {
        val handle = keyHandle ?: ensureKeys()
        val baos = ByteArrayOutputStream()
        CleartextKeysetHandle.write(handle, JsonKeysetWriter.withOutputStream(baos))
        val json = baos.toString(StandardCharsets.UTF_8.name())

        val keysetJson = JSONObject(json)
        val keyArray = keysetJson.getJSONArray("key")
        val keyObj = keyArray.getJSONObject(0)
        val keyData = keyObj.getJSONObject("keyData")
        val keyBytesBase64 = keyData.getString("value")
        val seedBytes = Base64.decode(keyBytesBase64, Base64.NO_WRAP)

        val digest = MessageDigest.getInstance("SHA-256").digest(seedBytes)
        val uuidBytes = digest.copyOf(16)
        return UUID.nameUUIDFromBytes(uuidBytes).toString()
    }

    /** ISO8601 helper */
    fun iso8601String(date: Instant): String =
        DateTimeFormatter.ISO_INSTANT.format(date)

    /** Canonicalize JSONObject recursively */
    fun canonicalizeJSON(json: JSONObject): JSONObject {
        val sortedKeys = json.keys().asSequence().sorted()
        val sortedJson = JSONObject()
        for (key in sortedKeys) {
            val value = json.get(key)
            sortedJson.put(
                key,
                when (value) {
                    is JSONObject -> canonicalizeJSON(value)
                    is JSONArray -> JSONArray().apply {
                        for (i in 0 until value.length()) {
                            val v = value.get(i)
                            put(if (v is JSONObject) canonicalizeJSON(v) else v)
                        }
                    }
                    else -> value
                }
            )
        }
        return sortedJson
    }

    /** Create a signed command (nonce + timestamp + signature) */
    fun createCommand(type: String, payload: Map<String, Any>): PhoneKeySignedCommand {
        val timestamp = Instant.now()
        val nonce = UUID.randomUUID().toString()

        val commandJson = JSONObject().apply {
            put("type", type)
            put("payload", JSONObject(payload))
            put("nonce", nonce)
            put("timestamp", iso8601String(timestamp))
        }

        val canonicalBytes = canonicalizeJSON(commandJson).toString().toByteArray(Charsets.UTF_8)
        val signatureBytes = sign(canonicalBytes)
        val signatureB64 = Base64.encodeToString(signatureBytes, Base64.NO_WRAP)

        return PhoneKeySignedCommand(
            command = type,
            payload = payload,
            nonce = nonce,
            timestamp = timestamp,
            signature = signatureB64
        )
    }
}

/** Signed command representation */
data class PhoneKeySignedCommand(
    val command: String,
    val payload: Map<String, Any>,
    val nonce: String,
    val timestamp: Instant,
    val signature: String
)
