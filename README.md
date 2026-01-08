# Phone Key Signing

Phone Key Signing POC (Android)

This repository contains a proof-of-concept (POC) Android implementation for phone key signing for NFC applications. It demonstrates generating, storing, and using Ed25519 keys securely on a device, including signing arbitrary data and structured commands in a canonical format.

Features

Ed25519 Key Management

Generate and persist a 32-byte Ed25519 keypair using Google Tink.

Secure storage using Android EncryptedSharedPreferences with MasterKey.

Signing Data

Sign arbitrary byte arrays with the device’s private key.

Retrieve the corresponding public key for verification.

Signed Commands

Create structured commands including commandId, timestamp, nonce, and payload.

Automatically canonicalize JSON (sorted keys, deterministic formatting).

Sign commands with Ed25519 and attach Base64-encoded signature.

Access Control List (ACL)

Model phone key permissions, schedules, and metadata for fine-grained authorization.

Canonical JSON representation for signing and verification.

Dependencies

AndroidX Security (EncryptedSharedPreferences, MasterKey)

Google Tink (tink-android)

Kotlin Standard Library

AndroidX Core, AppCompat, Material, and ConstraintLayout

Project Structure

PhoneKeyManager.kt
Handles key generation, storage, signing, and command creation.

PhoneKeyAcl.kt
Defines ACL structures, permissions, time windows, and canonicalization utilities.

UI / Example Usage
A sample activity can be used to test signing, public key retrieval, and command creation on a device.
