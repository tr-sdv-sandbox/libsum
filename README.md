# libsum - Secure Update Manifest

Library for cryptographically signed and encrypted software updates using X.509 certificates. Supports both offline and online OTA deployments.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Overview

**libsum** provides a framework for software updates in embedded systems, IoT devices, and general computing platforms. Updates are distributed as **X.509 certificates** containing embedded manifests and device metadata, with encrypted firmware as a separate file.

### Key Features

- **Certificate + Encrypted Firmware Distribution** - .crt certificate + .enc encrypted firmware
- **Offline Security** - USB/SD card delivery works without network connectivity
- **Cryptographic Authenticity** - Ed25519 signatures verify update source
- **Encryption** - X25519 key wrapping + AES-128-GCM encryption
- **Device-Specific** - Per-device encryption via public key cryptography
- **Anti-Rollback & Replay Prevention** - Version tracking blocks downgrades and re-installations
- **Certificate Revocation** - Timestamp-based emergency revocation without CRL/OCSP
- **API Design** - Manifests accessible only after signature verification

### Security Model

```
┌─────────────────────────────────────────┐
│ Backend (Build Time)                    │
│ 1. Hash software (SHA-256)              │
│ 2. Sign hash (Ed25519)                  │
│ 3. Encrypt software (AES-128-GCM)       │
│ 4. Wrap key with device pubkey (X25519)│
│ 5. Embed in X.509 certificate           │
│ 6. Sign certificate with CA key         │
└─────────────────────────────────────────┘
                 │
                 ▼
        ┌─────────────────┐
        │ Distribution    │
        │ - update.crt    │  ← Single file, any transport
        │ - firmware.enc  │  ← Encrypted payload
        └─────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│ Device (Runtime)                        │
│ 1. Verify certificate signature ✓      │
│ 2. Extract verified manifest            │
│ 3. Unwrap key with device private key   │
│ 4. Decrypt software                     │
│ 5. Verify software hash/signature ✓    │
└─────────────────────────────────────────┘
```

## Quick Start

### Installation

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install build-essential cmake libssl-dev libgoogle-glog-dev nlohmann-json3-dev

# Build
mkdir build && cd build
cmake ..
make -j$(nproc)

# Run tests
ctest --output-on-failure

# Install (optional)
sudo make install
```

### Basic Workflow

#### 1. Generate Keys

```bash
# Root CA signing key (Ed25519 - OFFLINE HSM STORAGE!)
./tools/sum-keygen --type ed25519 --output ca.key
./tools/sum-keygen --public ca.key --output ca.pub

# Intermediate CA signing key (Ed25519 - online, signs updates)
./tools/sum-keygen --type ed25519 --output intermediate.key
./tools/sum-keygen --public intermediate.key --output intermediate.pub

# Device encryption key (X25519 - stored on device)
./tools/sum-keygen --type x25519 --output device.key
./tools/sum-keygen --public device.key --output device.pub
```

**PKI Hierarchy Options:**
- **Root CA** - Signs intermediate CAs
- **Intermediate CA** - Signs update certificates
- Separation allows revoking intermediate CA without replacing root on devices

#### 2. Create Update Certificate (Backend)

```bash
./tools/sum-generate \
  --software firmware.bin \
  --device-pubkey device.pub \
  --backend-key intermediate.key \
  --backend-cert intermediate.crt \
  --hardware-id DEVICE-12345 \
  --manufacturer "Acme Corp" \
  --device-type "ESP32-Gateway" \
  --hardware-version "v2.1" \
  --artifact-name firmware \
  --artifact-type firmware \
  --target-ecu primary \
  --sw-version "1.0.0" \
  --sw-security-version 42 \
  --manifest-version 1 \
  --output update.crt \
  --encrypted-output firmware.enc
```

**Output:**
- `update.crt` - PEM certificate bundle containing:
  - Update certificate (signed by intermediate CA)
  - Intermediate CA certificate (signed by root CA)
- `firmware.enc` - Encrypted firmware

**Note:** update.crt is a PEM bundle with the complete chain (except root CA)

#### 3. Verify and Install (Device)

```bash
./tools/sum-verify \
  --certificate update.crt \
  --encrypted-software firmware.enc \
  --device-key device.key \
  --backend-ca ca.crt \
  --output firmware.bin
```

Outputs verified, decrypted `firmware.bin`.

## Architecture

### X.509 Certificate Structure

```
┌─────────────────────────────────────────┐
│  X.509 Certificate (update.crt)         │
├─────────────────────────────────────────┤
│  Standard Fields:                       │
│  - Subject: "Secure Update Certificate" │
│  - Public Key (device's public key)     │
│  - Validity: notBefore/notAfter          │
│  - Signature Algorithm: Ed25519          │
│  - keyUsage: digitalSignature            │
│  - extendedKeyUsage: codeSigning         │
├─────────────────────────────────────────┤
│  Extension #1 (OID 1.3.6.1.3.1) CRITICAL│
│  Device Metadata (Protobuf):            │
│  {                                       │
│    "hardware_id": "DEVICE-12345",       │
│    "manufacturer": "Acme Corp",         │
│    "device_type": "ESP32-Gateway",      │
│    "hardware_version": "v2.1",          │
│    "requires": [{                        │
│      "name": "firmware",                │
│      "min_security_version": 5          │
│    }]                                    │
│  }                                       │
│  ⚠️  Cryptographically signed            │
│     (verified during certificate load)  │
├─────────────────────────────────────────┤
│  Extension #2 (OID 1.3.6.1.3.2) CRITICAL│
│  Secure Update Manifest (Protobuf):     │
│  {                                       │
│    "manifest_version": 42,              │
│    "type": "FULL",                      │
│    "artifacts": [{                       │
│      "name": "application",             │
│      "type": "firmware",                │
│      "target_ecu": "primary",           │
│      "version": "1.0.0",                │
│      "security_version": 15,            │
│      "hash_algorithm": "SHA-256",       │
│      "expected_hash": "...",            │
│      "signature": "...",                │
│      "size": 12345                      │
│    }],                                   │
│    "encryption": [{                      │
│      "algorithm": "AES-128-GCM",        │
│      "iv": "...",                        │
│      "wrapped_key": "..." (X25519)      │
│    }]                                    │
│  }                                       │
│  ✅ Verified during certificate load     │
└─────────────────────────────────────────┘
        ↓ Signed by CA private key
   Cryptographic integrity for ALL fields
```

### Deployment Modes

**Offline OTA (Workshop/Field Service):**
```
Technician USB Stick:
  ├── update.crt     (PEM bundle: update cert + intermediate cert)
  └── firmware.enc   (encrypted firmware)

Device has: ca.crt (root CA, pre-installed)
Device applies update without internet connection
```

**Online OTA (Traditional):**
```
HTTPS/MQTT/CoAP Download:
  ├── update.crt     (PEM bundle with certificate chain)
  └── firmware.enc   (encrypted firmware)

Device has: ca.crt (root CA, pre-installed)
Same security guarantees, different transport
```

**Certificate Chain Validation:**
```
update.crt (PEM bundle):
  ├─ Update Certificate ──→ signed by intermediate CA
  └─ Intermediate CA Cert ─→ signed by root CA

Device validates:
  Update cert → Intermediate cert → Root CA (pre-installed)
```

### Workshop Filtering (Device Requirements)

Certificates contain **device requirements** in the DeviceMetadata extension for workshop technicians to determine compatibility:

```
Device Metadata (VERIFIED - signed with certificate):
  ├─ hardware_id, manufacturer, device_type    (device identification)
  └─ requires: [ArtifactConstraint]            (device state requirements)

Manifest (VERIFIED - accessible after certificate verification):
  ├─ manifest_version                          (for ordering updates)
  ├─ type (FULL or DELTA)                      (update type)
  └─ artifacts: [ArtifactInfo]                 (what this update provides)
```

**Workshop Use Case:**
```
Device State: firmware@primary security_version=10

USB Stick has:
  ├─ update_v5.crt:  artifacts[firmware@primary sv=15], requires sv [5,12]
  └─ update_v6.crt:  artifacts[firmware@primary sv=20], requires sv ≥15

Technician determines (after verifying certificates):
  1. Device (sv=10) matches update_v5 requirements (10 in [5,12]) → Apply v5
  2. After v5, device (sv=15) matches update_v6 requirements (15≥15) → Apply v6
  3. Cannot skip v5 and jump to v6 (sv=10 < 15)
```

**⚠️ Security Note:** All metadata is cryptographically signed. Certificates must be verified against root CA before extracting metadata or manifest.

### Content-Addressable Storage

All artifacts include a **ciphertext_hash** (SHA-256 of encrypted file) enabling content-addressable storage without additional flags:

```
Artifact always contains:
  ├─ ciphertext_hash (32 bytes SHA-256)
  ├─ ciphertext_size (for download progress)
  └─ sources[] (priority-ordered download locations)
```

**Source Type Determines Fetch Method:**

```cpp
// Traditional HTTP/HTTPS sources
builder.AddArtifact("firmware", encrypted)
    .AddSource("https://cdn.example.com/firmware.enc", 0, "https")
    .AddSource("https://backup.example.com/firmware.enc", 1, "https");

// Content-addressable sources (IPFS, local cache, P2P)
builder.AddArtifact("firmware", encrypted)
    .AddSource("ipfs://QmHash...", 0, "ipfs")           // Use ciphertext_hash as IPFS CID
    .AddSource("ca://local-cache", 1, "ca")            // Lookup in local cache by hash
    .AddSource("https://cdn.example.com/fw.enc", 2);   // HTTP fallback

// Client fetches in priority order, verifies with ciphertext_hash
```

**Device-Side Fetch Logic:**

```cpp
for (const auto& source : artifact.sources) {
    std::vector<uint8_t> data;

    if (source.type == "ipfs") {
        // Fetch from IPFS using ciphertext_hash as CID
        data = ipfs_client.Get(artifact.ciphertext_hash);
    } else if (source.type == "ca") {
        // Lookup in local cache by hash
        data = cache.Lookup(artifact.ciphertext_hash);
    } else if (source.type == "bittorrent") {
        // Use ciphertext_hash as infohash
        data = torrent_client.Download(artifact.ciphertext_hash);
    } else {
        // Default: fetch from source.uri (HTTP/HTTPS)
        data = http_client.Get(source.uri);
    }

    // Verify download integrity (ALWAYS)
    if (SHA256(data) == artifact.ciphertext_hash) {
        return data;  // Success!
    }
}
```

**Benefits:**

- **Deduplication**: Same firmware = same hash → cache once, reuse everywhere
- **P2P Distribution**: Devices can fetch from peers (IPFS, BitTorrent, mesh networks)
- **Offline Caching**: Workshop can cache by hash, apply any compatible update
- **Source Flexibility**: Add new storage backends without protocol changes
- **Integrity**: Hash verification detects corrupted/wrong downloads before decryption

**No Boolean Flag Needed**: The presence of a content-addressable source type (ipfs, ca, bittorrent) implies CA support. The protocol provides the hash and verification; client chooses which CA systems to implement.

## C++ API Examples

### Backend: Generate Update Certificate

```cpp
#include "sum/crypto.h"
#include "sum/manifest.h"
#include "sum/manifest_builder.h"

using namespace sum;

// Load keys and CA certificate
auto ca_key = crypto::PrivateKey::LoadFromFile("ca.key");
auto ca_cert = crypto::Certificate::LoadFromFile("ca.crt");
auto device_pubkey = crypto::PublicKey::LoadFromFile("device.pub");

// Read firmware
auto firmware = ReadBinaryFile("firmware.bin");

// Create device metadata (device identification + requirements)
DeviceMetadata device_meta;
device_meta.hardware_id = "DEVICE-12345";      // Links to device pubkey in DB
device_meta.manufacturer = "Acme Corp";
device_meta.device_type = "ESP32-Gateway";
device_meta.hardware_version = "v2.1";

// Device state requirements (optional - for compatibility checking)
ArtifactConstraint requires_constraint;
requires_constraint.name = "firmware";
requires_constraint.type = "firmware";
requires_constraint.target_ecu = "primary";
requires_constraint.min_security_version = 0;  // Accept any version (fresh install)
requires_constraint.max_security_version = 0;  // No upper limit
device_meta.requires.push_back(requires_constraint);

// Encrypt firmware once
auto encrypted_artifact = EncryptSoftware(firmware);

// Build manifest with single artifact
ManifestBuilder builder(ca_key, ca_cert);
builder.AddArtifact("firmware", encrypted_artifact)
    .SetType("firmware")
    .SetTargetECU("primary")
    .SetVersion(SemVer{1, 0, 0, "", ""})
    .SetSecurityVersion(42);

// Generate update certificate
auto [certificate, encrypted_files] = builder.BuildCertificate(
    device_pubkey,
    device_meta,
    1,   // manifest_version
    90   // validity days
);

// Extract encrypted firmware
auto encrypted_firmware = encrypted_files.at("firmware");

// Save for distribution
WriteBinaryFile("update.crt", certificate.ToDER());
WriteBinaryFile("firmware.enc", encrypted_firmware);
```

### Device: Verify and Install Update

```cpp
#include "sum/crypto.h"
#include "sum/manifest.h"
#include "sum/client/validator.h"

using namespace sum;

// Load encrypted firmware
auto encrypted_firmware = ReadBinaryFile("firmware.enc");

// Step 1: Load root CA and device key
auto root_ca = crypto::Certificate::LoadFromFile("ca.crt");
auto device_key = crypto::PrivateKey::LoadFromFile("device.key");

// Step 2: Load and verify update certificate atomically
// This performs full chain validation: update → intermediate → root
auto update_cert = crypto::UpdateCertificate::LoadFromFile(
    "update.crt",                             // PEM bundle (update + intermediate)
    root_ca,                                  // Root CA for verification
    time(nullptr),                            // Trusted time (for expiry check)
    LoadFromFlash("reject_before", 0)         // Certificate revocation timestamp
);
// ✅ Certificate is now VERIFIED - all extensions are cryptographically protected

// Step 3: Extract verified device metadata
auto metadata = update_cert.GetDeviceMetadata();
if (metadata.hardware_id != MY_HARDWARE_ID) {
    return; // Not for this device
}

// Step 4: Check device compatibility (verified metadata)
if (!metadata.requires.empty()) {
    auto current_sv = LoadFromFlash("current_security_version", 0);
    for (const auto& constraint : metadata.requires) {
        if (constraint.name == "firmware" && constraint.target_ecu == "primary") {
            if (current_sv < constraint.min_security_version) {
                LOG("Update requires security_version >= %d, current is %d",
                    constraint.min_security_version, current_sv);
                return; // Skip update, doesn't meet requirements
            }
        }
    }
}

// Step 5: Create validator with security policies
ManifestValidator validator(root_ca, device_key);
validator.SetLastInstalledVersion(LoadFromFlash("last_version", 0));
validator.SetRejectCertificatesBefore(LoadFromFlash("reject_before", 0));

// Step 6: Validate certificate and extract manifest
auto manifest = validator.ValidateCertificate(update_cert, time(nullptr));
// ✅ Throws CryptoError if signature invalid, expired, or policy violated
// ✅ Enforces anti-rollback/replay protection (version <= last rejected)

// Step 7: Unwrap encryption key
size_t artifact_index = 0;  // First artifact
auto aes_key = validator.UnwrapEncryptionKey(manifest, artifact_index);

// Step 8: Create streaming decryptor and hasher
auto decryptor = validator.CreateDecryptor(aes_key, manifest, artifact_index);
crypto::SHA256::Hasher hasher;

// Step 9: Stream decrypt and hash (process in chunks for large files)
std::ofstream output("firmware.bin", std::ios::binary);
constexpr size_t CHUNK_SIZE = 4096;
size_t offset = 0;

while (offset < encrypted_firmware.size()) {
    size_t chunk_size = std::min(CHUNK_SIZE, encrypted_firmware.size() - offset);
    std::vector<uint8_t> encrypted_chunk(
        encrypted_firmware.begin() + offset,
        encrypted_firmware.begin() + offset + chunk_size
    );

    auto decrypted_chunk = decryptor->Update(encrypted_chunk);
    hasher.Update(decrypted_chunk);
    output.write(reinterpret_cast<const char*>(decrypted_chunk.data()),
                 decrypted_chunk.size());

    offset += chunk_size;
}

// Finalize decryption
auto final_chunk = decryptor->Finalize();
if (!final_chunk.empty()) {
    hasher.Update(final_chunk);
    output.write(reinterpret_cast<const char*>(final_chunk.data()),
                 final_chunk.size());
}
output.close();

// Step 10: Verify hash and signature
auto computed_hash = hasher.Finalize();
if (!validator.VerifySignature(computed_hash, manifest, artifact_index)) {
    throw std::runtime_error("Signature verification failed!");
}

// Step 11: Install verified firmware
InstallFirmware("firmware.bin");

// Step 12: Persist new version (anti-rollback/replay protection)
SaveToFlash("last_version", manifest.GetManifestVersion());
```

## Security Features

### Attack Resistance

| Attack Vector | Defense Mechanism |
|---------------|-------------------|
| Malicious Update | Ed25519 signature verification - untrusted updates rejected |
| Man-in-the-Middle | Certificate signature covers ALL extensions |
| Replay Attack | SetLastInstalledVersion() rejects same version (version <= last) |
| Rollback Attack | SetLastInstalledVersion() rejects older versions |
| Compromised CA | SetRejectCertificatesBefore() enables emergency revocation |
| Tampered Metadata | Metadata in signed certificate |
| Tampered Manifest | Manifest in signed certificate, API enforces verification |
| Firmware Extraction | Per-device X25519 key wrapping + AES encryption |
| Wrong Device | Device-specific encryption + hardware_id |
| Offline Attacks | Self-contained certificates work offline securely |

### Cryptographic Algorithms

| Component | Algorithm | Security Level |
|-----------|-----------|----------------|
| Signing | Ed25519 | 128-bit |
| Key Wrapping | X25519 + ChaCha20-Poly1305 | 128-bit |
| Symmetric Encryption | AES-128-GCM | 128-bit |
| Hashing | SHA-256 | 256-bit |
| Certificates | X.509 v3 | - |

**Curve25519 Cryptography:**
- **Ed25519**: Signing and verification
- **X25519**: ECDH key agreement

### Secure-by-Design API

**Atomic Verification - Impossible to bypass:**

```cpp
// ❌ Does not exist - cannot load certificate without verification
auto cert = UpdateCertificate::LoadFromFile("update.crt");

// ✅ ONLY way - verification is atomic with load
auto cert = UpdateCertificate::LoadFromFile(
    "update.crt",
    root_ca,          // Must provide root CA
    time(nullptr),    // Must provide trusted time
    reject_before     // Optional: certificate revocation
);
// ✅ Certificate is VERIFIED - all extensions are now trusted
```

**All data is verified:**

```cpp
// Load with atomic verification
auto cert = UpdateCertificate::LoadFromFile("update.crt", root_ca, time(nullptr));

// Extract verified data (no parameters needed - verification already done)
auto metadata = cert.GetDeviceMetadata();  // ✅ Cryptographically verified
auto manifest = cert.GetManifest();        // ✅ Cryptographically verified

// Access verified fields
LOG("Hardware ID: %s", metadata.hardware_id.c_str());
LOG("Manifest version: %lu", manifest.GetManifestVersion());
LOG("Manifest type: %s", manifest.GetType() == ManifestType::FULL ? "FULL" : "DELTA");
LOG("Artifacts: %zu", manifest.GetArtifacts().size());
```

## Command-Line Tools

### sum-keygen

Generate Ed25519 or X25519 key pairs:

```bash
# Generate Ed25519 signing key (for backend/CA)
./sum-keygen --type ed25519 --output backend.key

# Generate X25519 encryption key (for devices)
./sum-keygen --type x25519 --output device.key

# Extract public key from private key
./sum-keygen --public device.key --output device.pub
```

### sum-generate

Create update certificates:

```bash
./sum-generate \
  --software firmware.bin \
  --device-pubkey device.pub \
  --backend-key ca.key \
  --backend-cert ca.crt \
  --hardware-id DEVICE-12345 \
  --manufacturer "Acme Corp" \
  --device-type "ESP32-Gateway" \
  --hardware-version "v2.1" \
  --artifact-name firmware \
  --artifact-type firmware \
  --target-ecu primary \
  --sw-version "1.0.0" \
  --sw-security-version 42 \
  --manifest-version 1 \
  --output update.crt \
  --encrypted-output firmware.enc
```

### sum-verify

Verify and decrypt updates:

```bash
./sum-verify \
  --certificate update.crt \
  --encrypted-software firmware.enc \
  --device-key device.key \
  --backend-ca ca.crt \
  --output firmware.bin \
  --show-metadata
```

## Testing

```bash
# Run all tests
ctest --output-on-failure

# Run specific test suite
ctest -R IntegrationTest

# Run tools integration test
ctest -R ToolsIntegrationTest -V
```

Test suites cover crypto primitives, manifest parsing, end-to-end workflows, tampering detection, anti-rollback, revocation, CA hierarchy, timestamp validation, and corrupt data handling.

## Documentation

API documentation available via Doxygen: `make docs`

## Security Notes

### Backend

**PKI Hierarchy:**
- Root CA signs intermediate CAs
- Intermediate CA signs update certificates
- Allows revoking intermediate without replacing root on devices

**Key Storage:**
- Root CA: Hardware Security Module (HSM), offline
- Intermediate CA: HSM with access controls

**Certificate Validity:**
- Root CA: 10 years
- Intermediate CA: 1-3 years
- Update certificates: 30-90 days

**OID Registration:**
- Current OIDs are experimental (1.3.6.1.3.x)
- Replace with registered PEN from https://www.iana.org/assignments/enterprise-numbers/

### Device

**Key Storage:**
- Secure element (ATECC608, TPM 2.0) or encrypted flash

**Time Source:**
- Hardware RTC or secure NTP for certificate expiration validation

**Rollback Protection:**
```cpp
validator.SetLastInstalledVersion(LoadFromFlash("last_version", 0));
SaveToFlash("last_version", manifest.GetManifestVersion());  // after install
```

**Revocation:**
```cpp
validator.SetRejectCertificatesBefore(LoadFromFlash("reject_before", 0));
```

**Atomic Updates:**
- Double-buffering or A/B partitions

## Platform Support

- Linux (Ubuntu 22.04+)
- ESP32, STM32, Linux-based IoT devices
- GCC 9+, Clang 10+
- C++17

## Dependencies

- OpenSSL 1.1.1+
- nlohmann/json
- Google Logging (glog)
- Google Test (testing only)

## License

Apache License 2.0

## Security Vulnerabilities

Contact maintainers privately. Do not open public GitHub issues.
