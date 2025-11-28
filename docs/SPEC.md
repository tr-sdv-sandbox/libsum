# libsum Specification

## Certificate Format

### X.509 Structure

Update certificates are X.509 v3 certificates with two custom extensions:

```
Certificate:
  Version: 3
  Subject: CN=Secure Update Manifest
  SubjectPublicKeyInfo: Device X25519 public key (32 bytes)
  Issuer: Intermediate CA
  Validity: notBefore, notAfter
  SignatureAlgorithm: Ed25519
  Extensions:
    - keyUsage: digitalSignature (critical)
    - extendedKeyUsage: codeSigning (critical)
    - 1.3.6.1.3.1 (Device Metadata, protobuf) - CRITICAL
    - 1.3.6.1.3.2 (Update Manifest, protobuf) - CRITICAL
```

### Extension 1.3.6.1.3.1: Device Metadata

Protocol Buffers format:

```protobuf
message DeviceMetadata {
  string device_type = 1;              // "ESP32-Gateway", "Root-CA", etc.
  string hardware_id = 2;              // "DEVICE-12345"
  string manufacturer = 3;             // "Acme Corp"
  string hardware_version = 4;         // "v2.1" (optional)
  repeated ArtifactConstraint requires = 5;  // Device state requirements
}

message ArtifactConstraint {
  string name = 1;                // "firmware"
  string type = 2;                // "firmware"
  string target_ecu = 3;          // "primary"
  uint64 min_security_version = 4;  // Minimum required (inclusive)
  uint64 max_security_version = 5;  // Maximum compatible (inclusive, 0 = no limit)
                                     // Used for sequential migrations (e.g., Android 8→9→10, can't skip)
}
```

**Purpose**: Device identification and compatibility requirements.

**Security**: Cryptographically signed with certificate. Verified atomically during certificate load. Use `GetDeviceMetadata()` after `UpdateCertificate::LoadFromFile()` to access verified data.

**Workshop Use Case**:
```
Device at: firmware@primary security_version=10

Update A (after verification):
  DeviceMetadata.requires: firmware@primary min=5, max=12
  Manifest.artifacts[0]: firmware@primary security_version=15

Update B (after verification):
  DeviceMetadata.requires: firmware@primary min=15
  Manifest.artifacts[0]: firmware@primary security_version=20

Workshop decision (after verifying certificates):
  - Device (v10) matches Update A requirements (10 in [5,12]) → Apply A
  - After A, device (v15) matches Update B requirements (15 >= 15) → Apply B
```

### Extension 1.3.6.1.3.2: Update Manifest

Protocol Buffers format (simplified view):

```protobuf
message Manifest {
  uint64 manifest_version = 2;         // For replay protection
  ManifestType type = 5;                // FULL or DELTA
  repeated Artifact artifacts = 10;
  repeated EncryptionParams encryption = 12;
  bytes signature = 20;
  bytes signing_cert = 21;
}

enum ManifestType {
  FULL = 0;   // Complete system state
  DELTA = 1;  // Partial update
}

message Artifact {
  string name = 1;
  string type = 2;
  string target_ecu = 3;
  uint32 install_order = 4;
  SemVer version = 50;
  uint64 security_version = 51;
  string hash_algorithm = 10;
  bytes expected_hash = 11;
  uint64 size = 12;
  bytes ciphertext_hash = 13;          // SHA-256 of encrypted file (for content-addressable storage)
  uint64 ciphertext_size = 14;
  string signature_algorithm = 20;
  bytes signature = 21;
  repeated Source sources = 40;
}

message EncryptionParams {
  string artifact_name = 1;
  string device_id = 2;
  string algorithm = 10;          // "AES-128-GCM"
  bytes iv = 11;                  // 12 bytes
  bytes tag = 12;                 // 16 bytes
  string key_wrapping_algorithm = 20;  // "X25519-HKDF-SHA256-ChaCha20Poly1305"
  bytes wrapped_key = 21;         // 76 bytes (ephemeral_pubkey + nonce + ciphertext + tag)
}
```

**Security**: Cryptographically signed with certificate. Verified atomically during certificate load. Use `GetManifest()` after `UpdateCertificate::LoadFromFile()` to access verified data.

## Versioning Model

### Three Independent Version Types

#### 1. Artifact Version (SemVer)
- **Type**: Semantic version (major.minor.patch-prerelease+build)
- **Scope**: Per artifact
- **Purpose**: Feature compatibility
- **Monotonicity**: Not enforced (can upgrade/downgrade)
- **Example**: "1.2.3", "2.0.0-beta.1+git.abc"

#### 2. Artifact Security Version
- **Type**: uint64
- **Scope**: Per artifact
- **Purpose**: Rollback protection
- **Monotonicity**: Enforced (must increase or stay same)
- **Storage**: Device persistent storage
- **Validation**: Reject if `new_security_version < last_security_version`
- **Example**: 0 (initial), 1 (first security patch), 2 (second patch)

#### 3. Manifest Version
- **Type**: uint64
- **Scope**: Per manifest
- **Purpose**: Replay protection
- **Monotonicity**: Enforced (must increase)
- **Storage**: Device persistent storage
- **Validation**: Reject if `new_manifest_version <= last_manifest_version`
- **Example**: 1 (first manifest), 2 (second manifest), 3 (third manifest)

### Version Validation Logic

```c
// Rollback protection (per artifact)
if (manifest.artifact[i].security_version < device.last_security_version[i]) {
    return ROLLBACK_REJECTED;
}

// Replay protection (per manifest)
if (manifest.manifest_version <= device.last_manifest_version) {
    return REPLAY_REJECTED;
}
```

## Encryption Model

### Software Encryption

1. Generate random AES-128 key (16 bytes)
2. Generate random IV (12 bytes for GCM)
3. Encrypt software with AES-128-GCM:
   - Input: plaintext software
   - Key: 16-byte AES key
   - IV: 12-byte nonce
   - Output: ciphertext + 16-byte auth tag

### Key Wrapping (Per-Device)

For each target device:

1. Load device X25519 public key (32 bytes)
2. Generate ephemeral X25519 keypair
3. Compute shared secret via X25519 ECDH
4. Wrap AES key using ChaCha20-Poly1305:
   - Shared secret → ChaCha20-Poly1305 key (via HKDF-SHA256)
   - AES key → plaintext
   - Output: wrapped_key = ephemeral_pubkey (32) + nonce (12) + ciphertext (16) + tag (16) = 76 bytes

### Key Unwrapping (Device)

1. Load device X25519 private key (32 bytes)
2. Extract ephemeral public key from wrapped_key (first 32 bytes)
3. Compute shared secret via X25519 ECDH
4. Unwrap AES key using ChaCha20-Poly1305:
   - Shared secret → ChaCha20-Poly1305 key (via HKDF-SHA256)
   - Extract: nonce (12 bytes), ciphertext (16 bytes), tag (16 bytes)
   - Output: AES key (16 bytes)

### Decryption

1. Unwrap AES key
2. Decrypt software with AES-128-GCM:
   - Input: ciphertext from firmware.enc
   - Key: unwrapped AES key
   - IV: from manifest
   - Auth tag: from manifest
   - Output: plaintext software

## Hash and Signature Model

### Software Hash

```
SHA-256(plaintext_software) → 32-byte hash
```

Stored in manifest `expected_hash`, verified after decryption.

### Software Signature

```
Ed25519_sign(signing_key, SHA-256(plaintext_software)) → 64-byte signature
```

Stored in manifest artifact.signature, verified after decryption.

### Certificate Signature

```
Ed25519_sign(ca_key, TBSCertificate) → certificate signature
```

Standard X.509 signature covering all certificate fields including both extensions.

## PKI Hierarchy

### Three-Tier Model

```
Root CA (offline)
  │
  ├─ signs ──→ Intermediate CA (online)
  │               │
  │               ├─ signs ──→ Update Certificate 1
  │               ├─ signs ──→ Update Certificate 2
  │               └─ signs ──→ Update Certificate N
  │
  └─ Trust Anchor (pre-installed on devices)
```

### Certificate Types

#### Root CA Certificate
- **Subject**: Root CA identity
- **Issuer**: Self (self-signed)
- **KeyUsage**: keyCertSign, cRLSign
- **Validity**: 10 years
- **Storage**: Pre-installed on devices (trust anchor)
- **Private Key**: Offline HSM, air-gapped

#### Intermediate CA Certificate
- **Subject**: Intermediate CA identity
- **Issuer**: Root CA
- **KeyUsage**: keyCertSign, cRLSign
- **Validity**: 1-3 years
- **Storage**: Included in update.crt PEM bundle
- **Private Key**: Online HSM with access controls

#### Update Certificate
- **Subject**: "Secure Update Manifest"
- **Issuer**: Intermediate CA
- **SubjectPublicKeyInfo**: Device X25519 public key
- **KeyUsage**: digitalSignature
- **ExtendedKeyUsage**: codeSigning
- **Extensions**: Device Metadata (OID 1.3.6.1.3.1) + Update Manifest (OID 1.3.6.1.3.2)
- **Validity**: 30-90 days
- **Storage**: Distributed as update.crt

### Certificate Distribution

**PEM Bundle Format (update.crt)**:
```
-----BEGIN CERTIFICATE-----
<Update Certificate>
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
<Intermediate CA Certificate>
-----END CERTIFICATE-----
```

**Validation Chain**:
```
Update Cert → Intermediate CA Cert → Root CA Cert (pre-installed)
   (verify)        (verify)              (trust anchor)
```

## Revocation Model

### Timestamp-Based Revocation

No CRL or OCSP required. Uses certificate `notBefore` timestamp.

**Emergency Revocation Procedure**:

1. **Detection**: Intermediate CA compromised at time T
2. **Backend Action**:
   - Issue new intermediate CA with `notBefore = T + 1`
   - Sign new intermediate with root CA
   - Create emergency update certificate with new intermediate
   - Distribute emergency update
3. **Device Action**:
   - Receive emergency update
   - Persist revocation timestamp: `reject_before = T`
   - Store in NVS: `nvs_set_i64("reject_before", T)`
4. **Future Validation**:
   - Load: `reject_before = nvs_get_i64("reject_before")`
   - For each certificate in chain:
     - If `cert.notBefore < reject_before`: **REJECT**

### Validation Logic

```c
int64_t reject_before = load_from_nvs("reject_before");

for (cert in certificate_chain) {
    if (cert.not_before_timestamp < reject_before) {
        return CERTIFICATE_REVOKED;
    }
}
```

## Cryptographic Algorithms

| Operation | Algorithm | Key Size | Output Size |
|-----------|-----------|----------|-------------|
| Signing | Ed25519 | 32 bytes private | 64 bytes signature |
| Key Agreement | X25519 | 32 bytes private | 32 bytes shared secret |
| AEAD (key wrap) | ChaCha20-Poly1305 | 32 bytes | ciphertext + 16 bytes tag |
| Symmetric Encryption | AES-128-GCM | 16 bytes | ciphertext + 16 bytes tag |
| Hashing | SHA-256 | N/A | 32 bytes |
| Key Derivation | HKDF-SHA256 | N/A | variable |

## File Format

### Update Distribution

**Files**:
- `update.crt` - PEM certificate bundle (text)
- `firmware.enc` - Encrypted firmware (binary)
- `ca.crt` - Root CA certificate (pre-installed on device)

**Certificate Size**: ~8-16 KB depending on manifest complexity

**Firmware Size**: `plaintext_size` (ciphertext size equals plaintext for AES-GCM, tag stored in manifest)

### Manifest Size Estimate

Base manifest: ~200 bytes
Per artifact: ~150 bytes
Per encryption params: ~100 bytes
Per source URL: ~50 bytes

Example: 3 artifacts, 2 sources each = 200 + 3×150 + 3×100 + 6×50 = 1250 bytes

## Security Properties

### Authenticity
- Certificate signature covers all fields including both extensions (device metadata + manifest)
- Software signature verified after decryption
- Only CA private key can sign certificates

### Confidentiality
- AES-128-GCM encrypts firmware
- X25519 + ChaCha20-Poly1305 wraps AES key per device
- Only device with matching private key can unwrap

### Integrity
- SHA-256 hash verified after decryption
- GCM auth tag prevents tampering
- Certificate signature prevents manifest tampering
- Device metadata in signed certificate prevents metadata tampering

### Rollback Protection
- `security_version` monotonic counter per artifact
- Device rejects `new_security_version < last_security_version`
- Persistent storage prevents rollback

### Replay Protection
- `manifest_version` monotonic counter
- Device rejects `new_manifest_version <= last_manifest_version`
- Prevents re-installation of same update

### Revocation
- Timestamp-based, no CRL/OCSP
- Works offline
- Granular (can revoke specific intermediate CA)

## OID Registration

Current OIDs are experimental:
- `1.3.6.1.3.1` - Device Metadata extension (protobuf)
- `1.3.6.1.3.2` - Update Manifest extension (protobuf)

Production deployment requires registering Private Enterprise Number (PEN) at:
https://www.iana.org/assignments/enterprise-numbers/

Replace with: `1.3.6.1.4.1.<PEN>.<extension>`
