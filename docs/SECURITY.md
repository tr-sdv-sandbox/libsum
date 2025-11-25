# libsum Security Model

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Trust Model](#trust-model)
4. [Threat Model](#threat-model)
5. [Cryptographic Guarantees](#cryptographic-guarantees)
6. [Security-by-Design Features](#security-by-design-features)
7. [Deployment Recommendations](#deployment-recommendations)
8. [Known Limitations](#known-limitations)

---

## Overview

**libsum** is a secure software update library designed for embedded systems, IoT devices, and general computing platforms. It provides cryptographically signed and optionally encrypted software updates distributed via X.509 certificates.

**Key differentiator**: Updates are secure for **offline distribution** (USB drives, workshop updates, local networks) while also supporting traditional online OTA scenarios.

### Key Security Properties

- **Authenticity**: Updates are cryptographically signed and verified
- **Integrity**: Any tampering with updates is detected and rejected
- **Confidentiality**: Optional per-device encryption protects intellectual property
- **Rollback Protection**: SetLastInstalledVersion() prevents downgrade attacks
- **Replay Protection**: SetLastInstalledVersion() prevents re-installation of same version
- **Certificate Revocation**: SetRejectCertificatesBefore() provides emergency revocation without CRL/OCSP
- **Secure-by-Design API**: Impossible to use manifests without verification
- **Offline Security**: Single .crt file contains everything needed for verified offline updates

---

## Architecture

### Distribution Format: X.509 Certificate Chains (PEM Bundles)

libsum uses X.509 certificates as the **ONLY** distribution format for software updates. This works for both:
- **Offline OTA**: USB drives, SD cards, workshop laptops, local file sharing
- **Online OTA**: HTTPS downloads, MQTT, CoAP, or any transport protocol

The certificate is self-contained and cryptographically tamper-proof.

**Production Distribution Format (PEM Bundle)**:
```
update.crt (PEM bundle):
  ├─ Update Certificate (signed by intermediate CA)
  └─ Intermediate CA Certificate (signed by root CA)

Device has pre-installed:
  └─ ca.crt (root CA certificate - trust anchor)
```

The PEM bundle format follows standard PKI practice (like TLS certificates), allowing certificate chain validation from the update certificate through intermediate(s) to the root CA.

```
┌─────────────────────────────────────────┐
│  X.509 Certificate (single .crt file)  │
├─────────────────────────────────────────┤
│  Standard X.509 Fields:                 │
│  - Subject Name                         │
│  - Public Key                          │
│  - Validity Period (notBefore/notAfter) │
│  - Digital Signature                    │
│  - keyUsage: digitalSignature           │
│  - extendedKeyUsage: codeSigning        │
├─────────────────────────────────────────┤
│  Custom Extension #1 (CRITICAL):        │
│  Device Metadata (OID: 1.3.6.1.3.1)    │
│  - hardware_id (links to device pubkey)│
│  - manufacturer                         │
│  - device_type                          │
│  - hardware_version (optional)          │
│  ⚠️  UNVERIFIED - for filtering only    │
├─────────────────────────────────────────┤
│  Custom Extension #2 (CRITICAL):        │
│  Update Manifest (OID: 1.3.6.1.3.2)     │
│  - Software artifacts + hashes          │
│  - ECDSA signatures                     │
│  - Per-device encrypted keys (ECIES)    │
│  ✅ VERIFIED - requires GetVerifiedManifest()│
└─────────────────────────────────────────┘
         ↓ Verified with CA certificate
    Cryptographic Guarantee:
    ALL fields are signed by CA
```

### Update Workflow

#### Build Time (Backend/Server)

```
1. Create Manifest in memory
   ├─ Add software artifacts (firmware, apps, etc.)
   ├─ Hash each artifact with SHA-256
   ├─ Sign each hash with backend ECDSA private key
   └─ Add per-device encryption (ECIES with device public key)

2. Create Device Metadata
   ├─ hardware_id: CRITICAL - links to device public key in database
   ├─ manufacturer, device_type: for quick filtering
   └─ hardware_version (optional)

3. CreateCertificateWithManifest()
   ├─ Embed manifest as X.509 extension
   ├─ Embed device metadata as X.509 extension
   ├─ Add keyUsage + extendedKeyUsage
   └─ Sign with CA private key → .crt file

4. Distribute .crt file
   ├─ Offline: USB drive, SD card, local network, workshop laptop
   └─ Online: HTTPS, MQTT, CoAP, or any transport
```

#### Runtime (Device/Client)

```
1. Load certificate from file
   Certificate cert = Certificate::LoadFromFile("update.crt");

2. Quick filtering (UNVERIFIED)
   auto metadata = cert.ExtractDeviceMetadata();
   if (metadata["hardware_id"] != MY_HARDWARE_ID) {
       return; // Not for this device
   }

3. Verify and extract manifest (VERIFIED)
   auto manifest_data = cert.GetVerifiedManifest(ca_cert, trusted_time);
   ✅ Signature verification REQUIRED
   ✅ Throws CryptoError if tampered
   ✅ Checks certificate expiration if trusted_time provided

4. Parse manifest
   Manifest manifest = Manifest::LoadFromProtobuf(manifest_data);

5. For each encrypted artifact:
   ├─ Unwrap AES key using device ECIES private key
   ├─ Decrypt artifact with AES-128-CTR
   ├─ Verify SHA-256 hash
   └─ Verify ECDSA signature

6. Apply update atomically
```

---

## Trust Model

### Trust Hierarchy

**Production PKI Hierarchy (3-Tier - RECOMMENDED)**:

```
┌────────────────────────────────────┐
│  Root Certificate Authority (CA)   │
│  - Holds root CA private key       │
│  - OFFLINE air-gapped HSM storage  │
│  - Only signs intermediate CAs     │
│  - Rare operation (years between)  │
└──────────────┬─────────────────────┘
               │ signs (offline)
               ↓
┌────────────────────────────────────┐
│  Intermediate CA                   │
│  - Holds intermediate private key  │
│  - ONLINE HSM (YubiHSM, CloudHSM)  │
│  - Signs update certificates       │
│  - Can be rotated/revoked          │
└──────────────┬─────────────────────┘
               │ signs (online)
               ↓
┌────────────────────────────────────┐
│  Update Certificate (PEM Bundle)   │
│  - Embedded manifest + metadata    │
│  - Signed by intermediate CA       │
│  - Bundled with intermediate cert  │
│  - Distributed to devices          │
└──────────────┬─────────────────────┘
               │ verified by
               ↓
┌────────────────────────────────────┐
│  Device                            │
│  - Has root CA certificate only    │
│  - Has device X25519 private key   │
│  - Validates full chain:           │
│    update → intermediate → root    │
└────────────────────────────────────┘
```

**Benefits of Intermediate CA**:
- Root CA kept offline → Much harder to compromise
- Intermediate CA can be rotated annually without touching devices
- Compromised intermediate can be revoked without re-deploying root CA
- Standard enterprise PKI practice

### Root of Trust

The **root CA public certificate** is the root of trust. Devices must:

1. Have root CA cert pre-installed (burned into firmware or secure storage)
2. **NEVER** accept updates signed by unknown root CAs
3. Protect root CA cert from modification
4. Validate full certificate chain: update cert → intermediate CA(s) → root CA

**Note**: Devices do NOT need intermediate CA certificates pre-installed. The intermediate certificates are bundled in the PEM update file and validated against the pre-installed root CA.

### Device Key Management

Each device has:
- **X25519 key pair**: For decrypting per-device update keys (ECDH key wrapping)
  - Private key: Stored securely on device (never leaves device)
  - Public key: Registered in backend database, linked by `hardware_id`

Backend database schema:
```
devices:
  hardware_id (PRIMARY KEY) → device_public_key (X25519)
```

When creating updates, backend:
1. Looks up device public key by `hardware_id`
2. Performs X25519 ECDH with device public key
3. Derives AES key using HKDF-SHA256
4. Wraps AES key using ChaCha20-Poly1305 AEAD
5. Embeds wrapped key in manifest

---

## Threat Model

### Threats Mitigated ✅

| Threat | Mitigation |
|--------|-----------|
| **Malicious Update** | Ed25519 signature verification - untrusted updates rejected |
| **Man-in-the-Middle** | Certificate signature covers ALL fields including extensions |
| **Replay Attack** | SetLastInstalledVersion() rejects same version (version <= last) |
| **Rollback Attack** | SetLastInstalledVersion() rejects older versions automatically |
| **Compromised Intermediate CA** | SetRejectCertificatesBefore() enables emergency timestamp-based revocation |
| **Tampered Metadata** | Device metadata in signed certificate - tampering detected |
| **Tampered Manifest** | Manifest in signed certificate - tampering detected |
| **Firmware Extraction** | Per-device X25519 + ChaCha20-Poly1305 encryption protects IP |
| **Side-Channel on Keys** | Uses OpenSSL (audited crypto library) |
| **Wrong Device Update** | Device-specific encryption + hardware_id filtering |
| **Offline Attack** | Self-contained certificates enable secure offline distribution |

### Threats NOT Mitigated ❌

| Threat | Why Not Mitigated | Recommendation |
|--------|-------------------|----------------|
| **Compromised CA Key** | If attacker gets CA private key, can sign malicious updates | Use HSM, strict key access controls |
| **Compromised Device Key** | Attacker with device private key can decrypt its updates | Use secure element / TPM |
| **Physical Tampering** | Attacker with physical access can modify device | Use secure boot, flash encryption |
| **Time-of-Check-to-Time-of-Use** | Race condition between verification and installation | Atomic update application |
| **Denial of Service** | Attacker floods with invalid updates | Rate limiting on backend |
| **Supply Chain** | Malicious component in hardware | Vendor trust, supply chain security |

---

## Cryptographic Guarantees

### Algorithms

| Purpose | Algorithm | Key Size | Standard |
|---------|-----------|----------|----------|
| CA Signing | Ed25519 | 256-bit (128-bit security) | RFC 8032 |
| Update Signing | Ed25519 | 256-bit (128-bit security) | RFC 8032 |
| Key Wrapping (ECDH) | X25519 | 256-bit (128-bit security) | RFC 7748 |
| Key Derivation | HKDF-SHA256 | 256-bit | RFC 5869 |
| AEAD Encryption | ChaCha20-Poly1305 | 256-bit key | RFC 8439 |
| Symmetric Crypto | AES-128-CTR | 128-bit | NIST SP 800-38A |
| Hashing | SHA-256 | 256-bit | FIPS 180-4 |
| Certificates | X.509 v3 | - | RFC 5280 |

**Modern Curve25519 Cryptography**:
- **Ed25519**: Ultra-fast signing, deterministic, side-channel resistant
- **X25519**: Fast ECDH key agreement, used in Signal, WireGuard, TLS 1.3
- **ChaCha20-Poly1305**: Fast AEAD cipher, better than AES on platforms without hardware AES
- **Why not NIST curves?**: Curve25519 is simpler, faster, and has better security properties

### Security Properties

1. **Non-repudiation**: Ed25519 signatures prove backend authorized the update
2. **Forward Secrecy**: Per-update AES keys (ephemeral)
3. **Confidentiality**: X25519 + ChaCha20-Poly1305 key wrapping provides IND-CCA2 security
4. **Integrity**: SHA-256 hashes provide collision resistance
5. **Authenticity**: X.509 certificate chains provide CA verification
6. **Chain Validation**: Full certificate chain validation from update → intermediate(s) → root CA

---

## Security-by-Design Features

### 1. Impossible to Use Unverified Data

The API makes it **impossible** to access manifest data without verification:

```cpp
// ❌ This won't compile - no unverified manifest access
auto manifest_data = cert.ExtractManifestExtension(); // Does not exist!

// ✅ ONLY way to access manifest - MUST verify
auto manifest_data = cert.GetVerifiedManifest(ca_cert, time(nullptr));
// Throws CryptoError if signature invalid or certificate expired
```

### 2. Certificate-Only Distribution

Updates are **only** distributed as X.509 certificates. No standalone manifest files:

```cpp
// ❌ Standalone manifest files do not exist
Manifest::LoadFromFile("manifest.pb");  // Does not exist
Manifest::SaveToFile("manifest.pb");    // Does not exist

// ✅ ONLY format: Certificate-embedded manifests
auto cert = Certificate::LoadFromFile("update.crt");
auto manifest_data = cert.GetVerifiedManifest(ca_cert, time(nullptr));
```

This ensures every update goes through the same verified path, whether delivered:
- **Offline**: Via USB stick handed to technician in workshop
- **Online**: Via HTTPS download from update server

### 3. Critical Extensions

Both custom extensions are marked **CRITICAL** in X.509:
- Clients that don't understand libsum extensions will reject certificates
- Prevents accidental trust by generic X.509 validators

### 4. Clear Separation: Unverified vs Verified

```cpp
// UNVERIFIED (for quick filtering before expensive crypto)
auto metadata = cert.ExtractDeviceMetadata();
if (metadata["hardware_id"] != MY_ID) return;

// VERIFIED (cryptographically protected)
auto manifest = cert.GetVerifiedManifest(ca_cert);
auto verified_metadata = cert.GetVerifiedDeviceMetadata(ca_cert);
```

### 5. Detailed Error Messages

Verification failures provide specific error messages:

```
✅ "Certificate verification failed: Invalid signature (certificate not signed by provided CA)"
✅ "Certificate verification failed: Certificate expired at trusted time"
✅ "Certificate verification failed: Certificate not yet valid at trusted time"
```

---

## Deployment Recommendations

### Backend/Server

1. **PKI Hierarchy (CRITICAL - Production Best Practice)**
   - **Root CA**: Kept OFFLINE in air-gapped HSM
     - Physical security (vault, multi-person access control)
     - Never connected to network
     - Only signs intermediate CA certificates (rare operation, every 1-3 years)
     - Compromise requires physical access to HSM
   - **Intermediate CA**: Online HSM (YubiHSM, AWS CloudHSM, Google Cloud HSM)
     - Signs update certificates (frequent operation)
     - Can be rotated/revoked without touching devices
     - Enable comprehensive audit logging
     - Rotate annually or if compromised
   - **Benefits**: Root CA compromise much less likely, intermediate can be revoked

2. **Protect Root CA Private Key (OFFLINE)**
   - Store in OFFLINE Hardware Security Module (HSM)
   - Air-gapped system with NO network access
   - Physical security: vault, access logs, multi-person authentication
   - Use only for signing intermediate CA certificates (rare, ceremonial operation)
   - Document all root CA operations (signing ceremony logs)

3. **Protect Intermediate CA Private Key (ONLINE)**
   - Store in online HSM (YubiHSM 2, AWS CloudHSM, Google Cloud HSM, Azure Key Vault)
   - Implement strict access controls (principle of least privilege)
   - Enable comprehensive audit logging for all signing operations
   - Automated signing service with rate limiting
   - Rotate intermediate CA annually or if compromised

4. **Certificate Validity Period**
   - Root CA: Long-lived (10 years) - rarely rotated
   - Intermediate CA: Medium-lived (1-3 years) - rotated periodically
   - Update certificates: Short-lived (30-90 days recommended)
   - Short-lived update certs limit exposure if intermediate CA compromised
   - Implement automated certificate renewal workflow

5. **Hardware ID Database**
   - Secure database mapping `hardware_id → device_public_key (X25519)`
   - Validate hardware_id uniqueness during device enrollment
   - Rotate device keys if compromised (requires re-enrollment)
   - Index by hardware_id for fast lookups during update generation

6. **OID Registration**
   - Current OIDs (1.3.6.1.3.x) are from **experimental arc**
   - For production: Register Private Enterprise Number (PEN) at https://www.iana.org/assignments/enterprise-numbers/
   - Use: `1.3.6.1.4.1.{YOUR_PEN}.1` for device metadata
   - Use: `1.3.6.1.4.1.{YOUR_PEN}.2` for manifest

### Device/Client

1. **Secure CA Certificate Storage**
   - Embed CA cert in read-only firmware
   - Or store in secure storage (if available)
   - Verify integrity on boot

2. **Secure Device Private Key Storage**
   - Use secure element (e.g., ATECC608, TPM 2.0)
   - Or encrypted flash with hardware-backed keys
   - **NEVER** extract private key from device

3. **Trusted Time Source**
   - Use hardware RTC with battery backup
   - Or secure NTP with authenticated timestamps
   - Check certificate expiration: `cert.GetVerifiedManifest(ca_cert, trusted_time)`

4. **Rollback & Replay Protection**
   - Load persisted version on boot:
     ```cpp
     validator.SetLastInstalledVersion(LoadFromFlash("last_version", 0));
     ```
   - After successful installation:
     ```cpp
     SaveToFlash("last_version", manifest.GetManifestVersion());
     ```
   - Automatically rejects updates with `manifest_version ≤ last_installed_version`
   - Prevents both rollback attacks AND replay attacks (same version)

5. **Certificate Revocation (Emergency)**
   - Load revocation timestamp on boot:
     ```cpp
     validator.SetRejectCertificatesBefore(LoadFromFlash("reject_before", 0));
     ```
   - When intermediate CA is compromised:
     1. Backend issues new intermediate CA with `notBefore = now`
     2. Backend sends emergency update with revocation timestamp
     3. Device persists timestamp:
        ```cpp
        SaveToFlash("reject_before", emergency_timestamp);
        ```
   - Automatically rejects intermediate certificates with `notBefore < reject_timestamp`
   - No CRL/OCSP infrastructure needed

6. **Atomic Updates**
   - Use double-buffering or A/B partitions
   - Verify entire update before committing
   - Maintain recovery partition

### Online vs Offline Deployment

Both use the same certificate format and verification path:

**Online OTA**:
```cpp
// Download certificate via HTTPS/MQTT/etc
download_file("https://updates.example.com/device123.crt", "update.crt");

// Verify and install (same code as offline!)
auto cert = Certificate::LoadFromFile("update.crt");
auto manifest_data = cert.GetVerifiedManifest(ca_cert, time(nullptr));
```

**Offline Workshop**:
```cpp
// Technician copies file from USB stick
copy_file("/media/usb/updates/device123.crt", "update.crt");

// Verify and install (same code as online!)
auto cert = Certificate::LoadFromFile("update.crt");
auto manifest_data = cert.GetVerifiedManifest(ca_cert, time(nullptr));
```

The key advantage: **Offline distribution is just as secure as online** because the certificate is self-contained and cryptographically verified.

---

## Known Limitations

### 1. CRL/OCSP Not Implemented (By Design)

libsum does not support traditional CRL (Certificate Revocation Lists) or OCSP (Online Certificate Status Protocol).

**Instead**: Timestamp-based revocation via `SetRejectCertificatesBefore()`:
- Simpler than CRL/OCSP infrastructure
- Works offline (no network required)
- Persists as single int64_t timestamp
- Emergency revocation: Backend issues new intermediate CA with current `notBefore`, sends revocation timestamp to devices

**Additional mitigation**: Use short-lived update certificates (30-90 days).

### 2. No Multi-Signature Support

Updates are signed by a single CA. No support for M-of-N signatures.

**Workaround**: Implement multi-signature workflow at build time (multiple parties approve before final signing).

### 3. Timestamp Validation is Optional

Devices without secure time may not validate certificate expiration.

**Impact**: Expired certificates may be accepted if `trusted_time = 0`.

**Recommendation**: Always provide trusted time in production.

### 4. Root CA Key Rotation Requires Device Updates

Root CA key rotation requires re-distributing root CA certificates to all devices.

**Mitigation**: Use intermediate CA hierarchy (now implemented):
- Root CA kept offline, rarely rotated (10+ year lifetime)
- Intermediate CA rotated periodically (1-3 years) without touching devices
- Devices only need root CA pre-installed
- Intermediate certificates distributed in PEM bundles with updates

**Best Practice**: Plan root CA rotation years in advance, use intermediate CAs for day-to-day operations.

---

## Security Auditing and Testing

### Security Tests Included

libsum includes comprehensive security tests:

1. **Tampering Detection** (`RejectTamperedManifest`, `RejectTamperedDeviceMetadata`)
   - Verifies that tampering with certificate extensions is detected
   - Confirms `GetVerifiedManifest()` throws on invalid signatures

2. **CA Verification** (`ProperCAHierarchyVerification`)
   - Tests that updates signed by wrong CA are rejected
   - Verifies correct CA chain validation

3. **Corrupt Data Handling** (`InvalidJSONInExtensions`, `CorruptExtensionData`)
   - Ensures corrupt extension data is rejected
   - Tests JSON parsing errors are handled safely

4. **Wrong Device** (`RejectWrongDevice`)
   - Verifies that ECIES decryption fails with wrong device key

5. **Tampered Software** (`RejectTamperedSoftware`)
   - Confirms hash verification detects modified binaries

### Recommended External Audits

For production deployment:
- **Cryptographic Review**: Audit by qualified cryptographer
- **Penetration Testing**: Test real deployment scenarios
- **Code Audit**: Static analysis + manual code review
- **Dependency Audit**: Verify OpenSSL version and patches

---

## Incident Response

### If Root CA Key Compromised (CRITICAL)

1. **Immediately**: Isolate offline root CA system
2. **Assess**: Determine scope of compromise (physical access breach?)
3. **Generate**: New root CA key pair on new HSM
4. **Emergency Update**: Distribute new root CA certificate to ALL devices
5. **Revoke**: All intermediate CAs signed with old root CA
6. **Audit**: Review all operations since last known-good state
7. **Investigate**: How was offline system compromised? Fix root cause
8. **Document**: Create incident report and update security procedures

**Impact**: Catastrophic - requires emergency firmware update for all devices

### If Intermediate CA Key Compromised (SEVERE)

1. **Immediately**: Disable compromised intermediate CA in signing service
2. **Generate**: New intermediate CA key pair in new online HSM
3. **Sign**: New intermediate CA certificate with root CA (offline ceremony)
4. **Deploy**: New intermediate CA to update signing infrastructure
5. **Distribute**: Next update will include new intermediate CA in PEM bundle
6. **Revoke**: All update certificates signed with old intermediate CA (if CRL implemented)
7. **Audit**: Review all updates signed since compromise
8. **Investigate**: How was online HSM compromised? Fix security controls

**Impact**: Moderate - devices automatically validate new intermediate on next update
**Benefit**: NO emergency device updates required - this is why we use intermediate CAs!

### If Device Key Compromised

1. **Identify**: Which device(s) affected
2. **Blacklist**: Mark device as compromised in backend
3. **Rekey**: Device must generate new key pair
4. **Update**: Backend database with new public key
5. **Future Updates**: Use new device key for encryption

---

## References

- **X.509 Certificates**: [RFC 5280](https://tools.ietf.org/html/rfc5280)
- **ECDSA**: [FIPS 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)
- **AES**: [NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
- **SHA-256**: [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- **ECIES**: [IEEE 1363a](https://ieeexplore.ieee.org/document/891000)
- **OpenSSL**: [https://www.openssl.org/](https://www.openssl.org/)

---

## Contact

For security issues, please report to: **[your-security-email]**

Do NOT open public GitHub issues for security vulnerabilities.
