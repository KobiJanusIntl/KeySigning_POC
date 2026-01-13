package org.kobinoke.keysigning

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.google.crypto.tink.BinaryKeysetReader
import com.google.crypto.tink.BinaryKeysetWriter
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
import java.security.KeyStore
import java.security.MessageDigest
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class PhoneKeyManager(private val context: Context) {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEYSTORE_AES_ALIAS = "phone_key_wrap"
        private const val PREFS_NAME = "phone_keys"
        private const val PREF_ENCRYPTED_KEYSET = "encrypted_ed25519_keyset"
        private const val PREF_IV = "encrypted_ed25519_iv"
    }

    private val prefs =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private var keyHandle: KeysetHandle? = null

    init {
        SignatureConfig.register()
        ensureKeystoreAesKey()
    }

    // ------------------------------------------------------------------------
    // Keystore AES key (hardware-backed when possible)
    // ------------------------------------------------------------------------

    private fun ensureKeystoreAesKey() {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (!ks.containsAlias(KEYSTORE_AES_ALIAS)) {
            val keyGen = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE
            )

            val spec = KeyGenParameterSpec.Builder(
                KEYSTORE_AES_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(false) // set true for biometric-gated signing
                .build()

            keyGen.init(spec)
            keyGen.generateKey()
        }
    }

    private fun getKeystoreAesKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return ks.getKey(KEYSTORE_AES_ALIAS, null) as SecretKey
    }

    // ------------------------------------------------------------------------
    // Key lifecycle
    // ------------------------------------------------------------------------

    fun ensureKeys(): KeysetHandle {
        keyHandle?.let { return it }

        val encrypted = prefs.getString(PREF_ENCRYPTED_KEYSET, null)
        val iv = prefs.getString(PREF_IV, null)

        keyHandle =
            if (encrypted != null && iv != null) {
                decryptKeyset(
                    Base64.decode(encrypted, Base64.NO_WRAP),
                    Base64.decode(iv, Base64.NO_WRAP)
                )
            } else {
                val handle = KeysetHandle.generateNew(SignatureKeyTemplates.ED25519)
                persistKeyset(handle)
                handle
            }

        return keyHandle!!
    }

    fun destroyKeys() {
        prefs.edit().clear().apply()
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        ks.deleteEntry(KEYSTORE_AES_ALIAS)
        keyHandle = null
    }

    // ------------------------------------------------------------------------
    // Keyset encryption / decryption
    // ------------------------------------------------------------------------

    private fun persistKeyset(handle: KeysetHandle) {
        val serialized = ByteArrayOutputStream().use {
            CleartextKeysetHandle.write(
                handle,
                BinaryKeysetWriter.withOutputStream(it)
            )
            it.toByteArray()
        }

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getKeystoreAesKey())
        val ciphertext = cipher.doFinal(serialized)
        val iv = cipher.iv

        // Zero plaintext ASAP
        serialized.fill(0)

        prefs.edit()
            .putString(
                PREF_ENCRYPTED_KEYSET,
                Base64.encodeToString(ciphertext, Base64.NO_WRAP)
            )
            .putString(
                PREF_IV,
                Base64.encodeToString(iv, Base64.NO_WRAP)
            )
            .apply()
    }

    private fun decryptKeyset(ciphertext: ByteArray, iv: ByteArray): KeysetHandle {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            getKeystoreAesKey(),
            GCMParameterSpec(128, iv)
        )

        val plaintext = cipher.doFinal(ciphertext)

        val handle = plaintext.inputStream().use {
            CleartextKeysetHandle.read(
                BinaryKeysetReader.withInputStream(it)
            )
        }

        plaintext.fill(0)
        return handle
    }

    // ------------------------------------------------------------------------
    // Signing
    // ------------------------------------------------------------------------

    fun sign(data: ByteArray): ByteArray {
        val handle = ensureKeys()
        val signer = PublicKeySignFactory.getPrimitive(handle)
        return signer.sign(data)
    }

    fun signAcl(acl: PhoneKeyAcl): PhoneKeyAcl {
        val aclJson = JSONObject().apply {
            put("aclId", acl.aclId)
            put("lockMac", acl.lockMac)
            put("phoneKeyId", acl.phoneKeyId)
            put(
                "phonePublicKey",
                Base64.encodeToString(acl.phonePublicKey, Base64.NO_WRAP)
            )
            put("issuedAt", iso8601String(acl.issuedAt))
            put("expiresAt", iso8601String(acl.expiresAt))
        }

        val canonicalBytes = canonicalizeJSON(aclJson)
            .toString()
            .toByteArray(Charsets.UTF_8)

        val sig = Base64.encodeToString(sign(canonicalBytes), Base64.NO_WRAP)

        return acl.copy(
            signature = PhoneKeyAcl.Signature(
                algorithm = "Ed25519",
                value = sig
            )
        )
    }

    fun createCommand(
        type: String,
        payload: Map<String, Any>
    ): PhoneKeySignedCommand {

        val timestamp = Instant.now()
        val nonce = UUID.randomUUID().toString()

        val commandJson = JSONObject().apply {
            put("type", type)
            put("payload", JSONObject(payload))
            put("nonce", nonce)
            put("timestamp", iso8601String(timestamp))
        }

        val canonicalBytes = canonicalizeJSON(commandJson)
            .toString()
            .toByteArray(Charsets.UTF_8)

        val signatureB64 = Base64.encodeToString(
            sign(canonicalBytes),
            Base64.NO_WRAP
        )

        return PhoneKeySignedCommand(
            command = type,
            payload = payload,
            nonce = nonce,
            timestamp = timestamp,
            signature = signatureB64
        )
    }


    // ------------------------------------------------------------------------
    // Public key + Key ID
    // ------------------------------------------------------------------------

    fun getRawPublicKey(): ByteArray {
        val handle = ensureKeys()
        val publicHandle = handle.publicKeysetHandle

        val baos = ByteArrayOutputStream()
        CleartextKeysetHandle.write(
            publicHandle,
            JsonKeysetWriter.withOutputStream(baos)
        )

        val json = JSONObject(baos.toString(Charsets.UTF_8.name()))
        val keyData = json
            .getJSONArray("key")
            .getJSONObject(0)
            .getJSONObject("keyData")
            .getString("value")

        return Base64.decode(keyData, Base64.NO_WRAP) // 32 bytes
    }

    fun getKeyId(): String {
        val handle = ensureKeys()

        val baos = ByteArrayOutputStream()
        CleartextKeysetHandle.write(
            handle,
            JsonKeysetWriter.withOutputStream(baos)
        )

        val json = JSONObject(baos.toString(Charsets.UTF_8.name()))
        val seedB64 = json
            .getJSONArray("key")
            .getJSONObject(0)
            .getJSONObject("keyData")
            .getString("value")

        val seed = Base64.decode(seedB64, Base64.NO_WRAP)
        val digest = MessageDigest.getInstance("SHA-256").digest(seed)
        seed.fill(0)

        return UUID.nameUUIDFromBytes(digest.copyOf(16)).toString()
    }

    // ------------------------------------------------------------------------
    // Utilities
    // ------------------------------------------------------------------------

    fun iso8601String(date: Instant): String =
        DateTimeFormatter.ISO_INSTANT.format(date)

    fun canonicalizeJSON(json: JSONObject): JSONObject {
        val sorted = JSONObject()
        json.keys().asSequence().sorted().forEach { key ->
            val value = json.get(key)
            sorted.put(
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
        return sorted
    }
}

data class PhoneKeySignedCommand(
    val command: String,
    val payload: Map<String, Any>,
    val nonce: String,
    val timestamp: Instant,
    val signature: String
)
