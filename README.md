# libsum - Secure Update Manifest

A modern, security-focused library for cryptographically signed and encrypted software updates using X.509 certificates. Designed for both offline and online OTA deployments.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Overview

**libsum** provides a secure framework for software updates in embedded systems, IoT devices, and general computing platforms. Updates are distributed as **X.509 certificates** containing embedded manifests and device metadata - making them secure whether delivered via USB stick in a workshop or downloaded over the internet.

### Key Features

- **Certificate-Only Distribution** - Single .crt file contains everything needed
- **Offline-First Security** - USB/SD card delivery as secure as online OTA
- **Cryptographic Authenticity** - Ed25519 signatures prevent tampering
- **IP Protection** - X25519 key wrapping + AES encryption prevents software theft
- **Device-Specific** - Per-device encryption via public key cryptography
- **Anti-Rollback & Replay Prevention** - Version tracking blocks downgrades and re-installations
- **Certificate Revocation** - Timestamp-based emergency revocation without CRL/OCSP
- **Secure-by-Design API** - Impossible to use manifests without verification
- **Production-Ready** - Comprehensive test suite with 62 passing tests

### Security Model

```
┌─────────────────────────────────────────┐
│ Backend (Build Time)                    │
│ 1. Hash software (SHA-256)              │
│ 2. Sign hash (Ed25519)                  │
│ 3. Encrypt software (AES-128-CTR)       │
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

**Production PKI Hierarchy (RECOMMENDED):**
- **Root CA** - Kept offline in HSM, only signs intermediate CAs
- **Intermediate CA** - Online, signs update certificates
- **Benefits**: Root CA compromise much less likely, can revoke intermediate

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
  --version 42 \
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

**Result:** Verified, decrypted `firmware.bin` ready to install!

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
│  Device Metadata (JSON, unencrypted):   │
│  {                                       │
│    "hardware_id": "DEVICE-12345",       │
│    "manufacturer": "Acme Corp",         │
│    "device_type": "ESP32-Gateway",      │
│    "hardware_version": "v2.1"           │
│  }                                       │
│  ⚠️  Readable without verification       │
│     (for quick filtering)                │
├─────────────────────────────────────────┤
│  Extension #2 (OID 1.3.6.1.3.2) CRITICAL│
│  Secure Update Manifest (Protobuf):     │
│  {                                       │
│    "manifest_version": 42,              │
│    "artifacts": [{                       │
│      "name": "application",             │
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
│  ✅ Requires GetVerifiedManifest()       │
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

## C++ API Examples

### Backend: Generate Update Certificate

```cpp
#include "sum/crypto.h"
#include "sum/manifest.h"
#include "sum/generator.h"

using namespace sum;

// Load keys and CA certificate
auto ca_key = crypto::PrivateKey::LoadFromFile("ca.key");
auto ca_cert = crypto::Certificate::LoadFromFile("ca.crt");
auto device_pubkey = crypto::PublicKey::LoadFromFile("device.pub");

// Read firmware
auto firmware = ReadBinaryFile("firmware.bin");

// Create device metadata
DeviceMetadata device_meta;
device_meta.hardware_id = "DEVICE-12345";      // Links to device pubkey in DB
device_meta.manufacturer = "Acme Corp";
device_meta.device_type = "ESP32-Gateway";
device_meta.hardware_version = "v2.1";

// Generate update certificate
ManifestGenerator generator(ca_key, ca_cert);
auto [certificate, encrypted_firmware] = generator.CreateCertificate(
    firmware,
    device_pubkey,
    device_meta,
    42,  // version
    true,  // use encryption
    90   // validity days
);

// Save for distribution
WriteBinaryFile("update.crt", certificate.ToDER());
WriteBinaryFile("firmware.enc", encrypted_firmware);
```

### Device: Verify and Install Update

```cpp
#include "sum/crypto.h"
#include "sum/manifest.h"
#include "sum/validator.h"

using namespace sum;

// Load certificate and encrypted firmware
auto certificate = crypto::Certificate::LoadFromFile("update.crt");
auto encrypted_firmware = ReadBinaryFile("firmware.enc");

// Step 1: Quick filtering (UNVERIFIED - for performance)
if (certificate.HasDeviceMetadata()) {
    auto metadata_json = certificate.ExtractDeviceMetadata();
    auto metadata = nlohmann::json::parse(metadata_json);

    if (metadata["hardware_id"] != MY_HARDWARE_ID) {
        return; // Not for this device, skip expensive crypto
    }
}

// Step 2: Load device key and CA cert
auto device_key = crypto::PrivateKey::LoadFromFile("device.key");
auto ca_cert = crypto::Certificate::LoadFromFile("ca.crt");

// Step 3: Set security policies (anti-rollback + revocation)
ManifestValidator validator(ca_cert, device_key);
validator.SetLastInstalledVersion(LoadFromFlash("last_version", 0));
validator.SetRejectCertificatesBefore(LoadFromFlash("reject_before", 0));

// Step 4: Validate certificate and extract VERIFIED manifest
auto manifest = validator.ValidateCertificate(certificate, time(nullptr));
// ✅ Throws CryptoError if signature invalid, expired, or policy violated

// Step 5: Decrypt and verify firmware
auto aes_key = validator.UnwrapEncryptionKey(manifest);
auto firmware = validator.DecryptSoftware(encrypted_firmware, aes_key, manifest);

if (!validator.VerifySoftware(firmware, manifest)) {
    throw std::runtime_error("Firmware verification failed");
}

// Step 6: Install verified firmware
InstallFirmware(firmware);

// Step 7: Persist new version (anti-rollback)
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
| Symmetric Encryption | AES-128-CTR | 128-bit |
| Hashing | SHA-256 | 256-bit |
| Certificates | X.509 v3 | - |

**Modern Curve25519 Cryptography:**
- **Ed25519**: Ultra-fast signing, deterministic, side-channel resistant
- **X25519**: Fast ECDH key agreement, used in Signal, WireGuard, TLS 1.3
- **Why not NIST curves?**: Curve25519 is simpler, faster, and has better security properties

### Secure-by-Design API

**Impossible to use unverified data:**

```cpp
// ❌ Does not exist - cannot load standalone manifests
Manifest::LoadFromFile("manifest.pb");

// ✅ ONLY way - must verify certificate
auto manifest_data = cert.GetVerifiedManifest(ca_cert, time(nullptr));
auto manifest = Manifest::LoadFromProtobuf(manifest_data);
```

**Clear separation of unverified vs verified:**

```cpp
// UNVERIFIED (for quick filtering)
auto metadata = cert.ExtractDeviceMetadata();

// VERIFIED (cryptographically protected)
auto manifest = validator.ValidateCertificate(cert);
auto verified_metadata = cert.GetVerifiedDeviceMetadata(ca_cert);
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
  --version 42 \
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
# Run all tests (62 tests)
ctest --output-on-failure

# Run specific test suite
ctest -R IntegrationTest

# Run tools integration test
ctest -R ToolsIntegrationTest -V
```

**Test Coverage:**
- Unit tests: Crypto primitives, manifest parsing
- Integration tests: End-to-end workflows, tampering detection, anti-rollback, revocation
- Tools tests: Complete certificate generation and verification
- Security tests: CA hierarchy, timestamp validation, corrupt data, replay attacks

## Examples

See `examples/` directory for:
- `backend_example.cpp` - Creating update certificates
- `device_example.cpp` - Verifying and installing updates
- `keygen_example.cpp` - Key management

## Documentation

- **[Security Model](docs/SECURITY.md)** - Threat model, trust hierarchy, incident response
- **API Documentation** - Build with `make docs` (requires Doxygen)

## Production Deployment

### Backend Recommendations

1. **PKI Hierarchy (CRITICAL)**
   - **Root CA**: Kept OFFLINE in air-gapped HSM
   - **Intermediate CA**: Online, signs update certificates
   - Root CA only signs intermediate CAs (rare operation)
   - Compromised intermediate can be revoked without re-deploying devices

2. **Protect Root CA Private Key**
   - Store in Hardware Security Module (HSM) - offline
   - Air-gapped system, no network access
   - Physical security (vault, access logs)
   - Multi-person authentication required

3. **Protect Intermediate CA Private Key**
   - Store in online HSM (YubiHSM, AWS CloudHSM, etc.)
   - Implement strict access controls
   - Enable comprehensive audit logging
   - Rotate intermediate CA periodically (e.g., annually)

4. **Device Database**
   - Map `hardware_id → device_public_key`
   - Validate uniqueness during enrollment

5. **Certificate Validity**
   - Root CA: Long-lived (10 years)
   - Intermediate CA: Medium-lived (1-3 years)
   - Update certificates: Short-lived (30-90 days)
   - Automated renewal process

6. **OID Registration**
   - Current OIDs are experimental (1.3.6.1.3.x)
   - Register PEN at https://www.iana.org/assignments/enterprise-numbers/

### Device Recommendations

1. **Secure Key Storage**
   - Use secure element (ATECC608, TPM 2.0)
   - Or encrypted flash with hardware keys
   - Never extract private key

2. **Trusted Time**
   - Hardware RTC with battery backup
   - Or secure NTP
   - Always validate certificate expiration

3. **Rollback & Replay Protection**
   - Load persisted version on boot: `validator.SetLastInstalledVersion(LoadFromFlash("last_version", 0))`
   - After successful install: `SaveToFlash("last_version", manifest.GetManifestVersion())`
   - Automatically rejects `manifest_version ≤ current_version`

4. **Certificate Revocation (Emergency)**
   - Load revocation timestamp on boot: `validator.SetRejectCertificatesBefore(LoadFromFlash("reject_before", 0))`
   - When emergency update received: `SaveToFlash("reject_before", emergency_timestamp)`
   - Automatically rejects intermediate CAs issued before timestamp

5. **Atomic Updates**
   - Double-buffering or A/B partitions
   - Verify before committing

## Platform Support

- **Tested on:** Linux (Ubuntu 22.04+)
- **Embedded Targets:** ESP32, STM32, Linux-based IoT devices
- **Compilers:** GCC 9+, Clang 10+
- **C++ Standard:** C++17 or later

## Dependencies

- OpenSSL 1.1.1+ (crypto library)
- nlohmann/json (JSON parsing)
- Google Logging (glog)
- Google Test (testing only)

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please:
1. Run tests: `ctest --output-on-failure`
2. Follow existing code style
3. Add tests for new features
4. Update documentation

## Security

For security vulnerabilities, please contact the maintainers privately.

**Do NOT open public GitHub issues for security vulnerabilities.**

For general security questions, see [docs/SECURITY.md](docs/SECURITY.md).

## Acknowledgments

Built with:
- OpenSSL - Cryptographic primitives
- nlohmann/json - JSON parsing
- Google Test - Testing framework
- Google Logging - Logging

---

**libsum** - Secure software updates, offline or online.
