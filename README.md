# Phone Key Cryptography & Signing Architecture (Android)

This document describes a production-grade **phone-as-key cryptographic system** implemented on Android using:

- Ed25519 for modern digital signatures
- Google Tink for cryptographic primitives
- Android Keystore for hardware-backed key protection
- Canonical JSON signing for Android, iOS, and backend parity

The design is robust, auditable, and safe to deploy in real-world environments. This is exactly what Google, banks, and wallet apps do.

---

## Architecture Overview


Android Keystore does not support Ed25519 directly. Therefore, Ed25519 keys are generated and used by Tink, and the private key material is protected at rest using a Keystore-backed AES key (envelope encryption).

---

## Key Lifecycle

### First Launch

1. Generate an Ed25519 keypair using Tink
2. Serialize the private keyset in binary form
3. Encrypt the serialized keyset using a Keystore AES-256-GCM key
4. Persist the encrypted blob and IV in app storage

### App Restart

1. Load the encrypted keyset and IV
2. Decrypt using the Keystore AES key
3. Load into a Tink `KeysetHandle`
4. Use the key in memory for signing

### Key Destruction

- Delete the encrypted keyset
- Delete the Keystore AES key
- The cryptographic identity is permanently destroyed

---

## Security Properties

| Threat | Mitigation |
|------|-----------|
| App data extraction | Encrypted private key |
| APK cloning | Keystore-bound key |
| Command tampering | Ed25519 signature |
| Replay attacks | Nonce + timestamp |
| Cross-device reuse | Device-bound key |
| Rooted devices | Best-effort only |

No Android solution can fully protect secrets on a rooted device.

---

## Core Components

---

## PhoneKeyManager

`PhoneKeyManager` is responsible for all cryptographic operations and key management:

- Ed25519 key generation
- Keystore AES key creation and usage
- Secure key persistence
- Signing ACLs and commands
- Canonical JSON processing

Private key material is never exposed outside this class.

---

## PhoneKeyAcl (Access Control List)

Represents a signed permission grant for a specific lock.

```kotlin
data class PhoneKeyAcl(
    val aclId: String,
    val lockMac: String,
    val phoneKeyId: String,
    val phonePublicKey: ByteArray,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val schedule: List<TimeWindow>,
    val permissions: Permissions,
    val meta: Meta,
    val signature: Signature?
)
