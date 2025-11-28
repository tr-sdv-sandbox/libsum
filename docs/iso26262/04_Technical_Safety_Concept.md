# ISO 26262 Technical Safety Concept (TSC)
## libsum - Secure Update Verification Library (SEooC)

**Document ID:** LIBSUM-ISO26262-TSC-004
**Version:** 1.0
**Date:** 2025-11-27
**Status:** Draft for Review
**ASIL Target:** ASIL-D (SEooC)

---

## 1. Purpose

This document derives **Technical Safety Requirements (TSRs)** from the Functional Safety Requirements (Document 03), specifies the hardware and software architecture, and defines implementation-level safety mechanisms per ISO 26262-4:2018 and ISO 26262-5:2018.

---

## 2. Scope

This TSC specifies technical requirements for:
- **libsum software architecture** (C/C++ verification library)
- **Integrating system hardware/software interface** (AUTOSAR Update Manager)
- **Cryptographic library dependencies** (OpenSSL, mbedtls)
- **Testing and verification infrastructure**

The TSC does **NOT** specify:
- Workshop backend implementation details
- Vehicle network architecture (CAN/Ethernet)
- Bootloader or A/B partition management

---

## 3. System Architecture

### 3.1 Component Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                    Integrating System (AUTOSAR)               │
│  ┌────────────┐  ┌──────────────┐  ┌─────────────────────┐   │
│  │  Watchdog  │  │  NVM Manager │  │  Time Service (RTC) │   │
│  │   Timer    │  │ (Version DB) │  │   + Roughtime       │   │
│  └─────┬──────┘  └──────┬───────┘  └──────────┬──────────┘   │
│        │                │                     │              │
│        │                │                     │              │
│  ┌─────▼────────────────▼─────────────────────▼──────────┐   │
│  │          AUTOSAR Update Manager (ASIL-D)              │   │
│  │  - Flash write (only if libsum SUCCESS)               │   │
│  │  - Version persistence (after flash write)            │   │
│  │  - Timeout enforcement                                │   │
│  └─────────────────────────┬──────────────────────────────┘   │
│                            │                                  │
└────────────────────────────┼──────────────────────────────────┘
                             │ API calls (sum_verify_manifest)
                             │
┌────────────────────────────▼──────────────────────────────────┐
│                       libsum (SEooC, ASIL-D)                  │
│  ┌───────────────────────────────────────────────────────┐    │
│  │  Manifest Parser (nanopb / protobuf)                  │    │
│  └───────────────────────┬───────────────────────────────┘    │
│                          │                                    │
│  ┌───────────────────────▼───────────────────────────────┐    │
│  │  Certificate Verification (OpenSSL / mbedtls)         │    │
│  │  - X.509 chain validation                             │    │
│  │  - Ed25519 signature verification                     │    │
│  └───────────────────────┬───────────────────────────────┘    │
│                          │                                    │
│  ┌───────────────────────▼───────────────────────────────┐    │
│  │  Anti-Rollback Logic                                  │    │
│  │  - Version comparison                                 │    │
│  │  - Timestamp comparison                               │    │
│  │  - Device ID matching                                 │    │
│  └───────────────────────┬───────────────────────────────┘    │
│                          │                                    │
│  ┌───────────────────────▼───────────────────────────────┐    │
│  │  Decryption (X25519 + AES-128-GCM)                    │    │
│  └───────────────────────┬───────────────────────────────┘    │
│                          │                                    │
│  ┌───────────────────────▼───────────────────────────────┐    │
│  │  Hash Verification (SHA-256)                          │    │
│  └───────────────────────────────────────────────────────┘    │
│                                                               │
│  Return: 0 (SUCCESS) or negative error code                  │
└───────────────────────────────────────────────────────────────┘
```

### 3.2 Data Flow

```
┌────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────┐
│  Manifest  │────▶│  libsum      │────▶│ Verified    │────▶│  Flash   │
│  + Payload │     │  Verification│     │ Firmware    │     │  Write   │
│  (Signed)  │     │  (ASIL-D)    │     │ (ASIL-D)    │     │ (ASIL-D) │
└────────────┘     └──────────────┘     └─────────────┘     └──────────┘
                          │
                          ├─ SUCCESS (0) ──────────────────▶ Flash write proceeds
                          │
                          ├─ SIGNATURE_INVALID (-2) ───────▶ Reject, log security event
                          │
                          ├─ HASH_MISMATCH (-3) ───────────▶ Reject, log corruption
                          │
                          ├─ ROLLBACK_DETECTED (-4) ───────▶ Reject, log attack
                          │
                          └─ OUT_OF_MEMORY (-10) ──────────▶ Safe state, no write
```

---

## 4. Technical Safety Requirements (TSRs)

### 4.1 TSR-001: X.509 Certificate Chain Validation (FSR-001, ASIL-D)

**Derived from:** FSR-001 (Signature verification)

**Software Requirements:**

| TSR-001.1 | libsum SHALL parse X.509 certificates using ASN.1 DER encoding per RFC 5280 |
| TSR-001.2 | libsum SHALL verify Root CA self-signature using public key from trusted storage |
| TSR-001.3 | libsum SHALL verify Intermediate CA signature using Root CA public key |
| TSR-001.4 | libsum SHALL verify Update Certificate signature using Intermediate CA public key |
| TSR-001.5 | libsum SHALL extract Ed25519 public key from Update Certificate SubjectPublicKeyInfo |
| TSR-001.6 | libsum SHALL reject certificates with invalid ASN.1 structure (return CERT_INVALID) |

**Hardware Requirements (Integrating System):**

| TSR-001.H1 | Integrating system SHALL provide integrity-protected storage for Root CA certificate (e.g., flash with CRC, signed by bootloader) |
| TSR-001.H2 | Integrating system MAY provide Hardware Security Module (HSM) for key storage (optional, improves security) |

**Safety Mechanism:** Use FIPS 140-2 validated OpenSSL 3.0 or mbedtls 3.x for X.509 parsing.

**Verification:** Unit tests with invalid certificates (expired, wrong signature, malformed ASN.1).

---

### 4.2 TSR-002: Ed25519 Signature Verification (FSR-001, ASIL-D)

**Derived from:** FSR-001 (Signature verification)

**Software Requirements:**

| TSR-002.1 | libsum SHALL compute canonical manifest bytes by serializing protobuf with signature field set to empty bytes |
| TSR-002.2 | libsum SHALL verify Ed25519 signature using Update Certificate public key per RFC 8032 |
| TSR-002.3 | libsum SHALL use constant-time signature verification (prevent timing attacks) |
| TSR-002.4 | libsum SHALL reject manifests with signature length ≠ 64 bytes |
| TSR-002.5 | libsum SHALL reject manifests if signature verification fails (return SIGNATURE_INVALID) |

**Cryptographic Library Requirements:**

| TSR-002.C1 | Crypto library SHALL implement Ed25519 per FIPS 186-5 or RFC 8032 |
| TSR-002.C2 | Crypto library SHALL be FIPS 140-2 validated (Level 1 minimum) |
| TSR-002.C3 | Crypto library SHALL NOT have known CVEs with CVSS score ≥ 7.0 |

**Safety Mechanism:** Use OpenSSL's `EVP_DigestVerify` or mbedtls's `mbedtls_ecdsa_verify` with constant-time guarantees.

**Verification:** Unit tests with:
- Valid signatures (expected: SUCCESS)
- Corrupted signatures (1-bit flip, expected: SIGNATURE_INVALID)
- Wrong public key (expected: SIGNATURE_INVALID)

---

### 4.3 TSR-003: SHA-256 Hash Verification (FSR-002, ASIL-D)

**Derived from:** FSR-002 (Hash integrity)

**Software Requirements:**

| TSR-003.1 | libsum SHALL compute SHA-256 hash of decrypted payload using FIPS 180-4 algorithm |
| TSR-003.2 | libsum SHALL compare computed hash with manifest's `payload_sha256` using constant-time memcmp |
| TSR-003.3 | libsum SHALL reject artifacts with hash mismatch (return HASH_MISMATCH) |
| TSR-003.4 | libsum SHALL verify ALL artifacts before returning SUCCESS (fail-fast on first error) |

**Performance Requirements:**

| TSR-003.P1 | Hash computation SHALL NOT exceed 10 seconds for 100 MB payload on target hardware |
| TSR-003.P2 | Memory usage for hash computation SHALL NOT exceed 256 KB (streaming hash allowed) |

**Safety Mechanism:** Use hardware-accelerated SHA-256 if available (e.g., ARM Crypto Extensions, AES-NI).

**Verification:** Unit tests with:
- Valid payloads (expected: SUCCESS)
- Corrupted payloads (1-byte flip, expected: HASH_MISMATCH)
- Large payloads (100 MB, verify no timeout)

---

### 4.4 TSR-004: Anti-Rollback Version Check (FSR-003, ASIL-D)

**Derived from:** FSR-003 (Rollback protection)

**Software Requirements:**

| TSR-004.1 | libsum SHALL read `last_installed_version` from integrating system via callback function |
| TSR-004.2 | libsum SHALL compare `manifest.security_version > last_installed_version` (strict inequality) |
| TSR-004.3 | libsum SHALL reject manifests with `security_version <= last_installed_version` (return ROLLBACK_DETECTED) |
| TSR-004.4 | libsum SHALL compare `manifest.timestamp > last_installed_timestamp` (strict inequality) |
| TSR-004.5 | libsum SHALL reject manifests with `timestamp <= last_installed_timestamp` (return REPLAY_DETECTED) |

**Hardware Requirements (Integrating System):**

| TSR-004.H1 | Integrating system SHALL store `last_installed_version` in non-volatile memory (NVM) with ECC protection |
| TSR-004.H2 | Integrating system SHALL use redundant storage (2 copies with CRC) to prevent corruption |
| TSR-004.H3 | Integrating system SHALL atomically update version counter AFTER successful flash write (use wear-leveling) |
| TSR-004.H4 | Integrating system SHALL treat NVM read failure as rollback attack (fail-safe: reject update) |

**Safety Mechanism:** Monotonic counter in NVM (EEPROM or flash with wear-leveling). If counter reaches maximum (uint64_t max), device requires factory reset.

**Verification:** Unit tests with:
- Higher version (expected: SUCCESS)
- Same version (expected: ROLLBACK_DETECTED)
- Lower version (expected: ROLLBACK_DETECTED)
- Timestamp replay (expected: REPLAY_DETECTED)

---

### 4.5 TSR-005: Certificate Revocation Check (FSR-004, ASIL-C)

**Derived from:** FSR-004 (Revocation check)

**Software Requirements:**

| TSR-005.1 | libsum SHALL check if integrating system provided `reject_timestamp` (optional parameter) |
| TSR-005.2 | If provided, libsum SHALL extract Intermediate CA's `notBefore` field from X.509 certificate |
| TSR-005.3 | libsum SHALL compare `notBefore > reject_timestamp` (certificates issued before rejection are invalid) |
| TSR-005.4 | libsum SHALL reject manifests signed by revoked CA (return CERT_REVOKED) |

**Hardware Requirements (Integrating System):**

| TSR-005.H1 | Integrating system SHALL provide trusted time source (RTC with battery backup or authenticated NTP/Roughtime) |
| TSR-005.H2 | Time source SHALL have accuracy ≤ 1 hour (prevents premature rejection of valid certificates) |

**Safety Mechanism:** Simple revocation via timestamp comparison (no CRL/OCSP infrastructure required).

**Limitations:** OEM must coordinate firmware signing to only use post-revocation Intermediate CAs.

**Verification:** Unit tests with:
- Certificate issued after rejection (expected: SUCCESS)
- Certificate issued before rejection (expected: CERT_REVOKED)
- No `reject_timestamp` provided (expected: SUCCESS, check skipped)

---

### 4.6 TSR-006: Device Identity Verification (FSR-005, ASIL-C)

**Derived from:** FSR-005 (Cross-device protection)

**Software Requirements:**

| TSR-006.1 | libsum SHALL read device ID from integrating system via callback function |
| TSR-006.2 | libsum SHALL compare `manifest.device_id == device_id` using constant-time string comparison |
| TSR-006.3 | libsum SHALL reject manifests with mismatched device ID (return WRONG_DEVICE) |
| TSR-006.4 | Device ID comparison SHALL be case-sensitive |

**Hardware Requirements (Integrating System):**

| TSR-006.H1 | Integrating system SHALL provide immutable device ID (VIN, ECU serial number, or hardware UID) |
| TSR-006.H2 | Device ID SHALL be stored in OTP (One-Time Programmable) fuses or signed by Root CA |
| TSR-006.H3 | Device ID SHALL be read-only after manufacturing (cannot be changed in field) |

**Safety Mechanism:** Constant-time comparison prevents timing attacks that could leak device ID.

**Verification:** Unit tests with:
- Matching device ID (expected: SUCCESS)
- Mismatched device ID (expected: WRONG_DEVICE)
- Empty device ID (expected: WRONG_DEVICE)

---

### 4.7 TSR-007: Timeout and Deterministic Execution (FSR-006, ASIL-C)

**Derived from:** FSR-006 (ECU function blocking)

**Software Requirements:**

| TSR-007.1 | libsum SHALL pre-allocate all memory at initialization (no malloc during verification) |
| TSR-007.2 | libsum SHALL use constant-time crypto algorithms (no data-dependent branches) |
| TSR-007.3 | libsum SHALL enforce nanopb max_size limits for all protobuf fields (prevent unbounded parsing) |
| TSR-007.4 | libsum SHALL limit certificate chain depth to 3 levels (Root → Intermediate → Update) |

**Hardware Requirements (Integrating System):**

| TSR-007.H1 | Integrating system SHALL implement hardware watchdog timer (e.g., AUTOSAR Watchdog Manager) |
| TSR-007.H2 | Watchdog timeout SHALL be configured to 2× worst-case execution time (WCET) of libsum |
| TSR-007.H3 | Integrating system SHALL abort verification and enter safe state if timeout exceeded |

**Performance Requirements:**

| TSR-007.P1 | Worst-case execution time (WCET) SHALL be measured on target hardware (with all features enabled) |
| TSR-007.P2 | WCET SHALL NOT exceed 30 seconds for 100 MB manifest + payload on entry-level ECU (50 MHz ARM Cortex-M) |

**Safety Mechanism:** Watchdog timer in integrating system (libsum cannot self-enforce timeout).

**Verification:** Integration tests with:
- Large valid manifests (measure execution time)
- Maliciously crafted manifests (trigger timeout, verify abort)

---

### 4.8 TSR-008: Memory Safety (FSR-007, ASIL-D)

**Derived from:** FSR-007 (Memory corruption prevention)

**Software Requirements:**

| TSR-008.1 | libsum SHALL use C++ RAII (Resource Acquisition Is Initialization) for automatic memory management |
| TSR-008.2 | libsum SHALL use `std::vector` and `std::string` (bounds-checked containers) instead of raw pointers |
| TSR-008.3 | libsum SHALL NOT use `strcpy`, `strcat`, `sprintf` (use safe alternatives: `strncpy`, `snprintf`) |
| TSR-008.4 | libsum SHALL initialize all variables before use (no uninitialized reads) |
| TSR-008.5 | libsum SHALL check malloc return values and return OUT_OF_MEMORY if allocation fails |
| TSR-008.6 | libsum SHALL NOT leak memory (all allocated memory freed before function return) |

**Coding Standard Requirements:**

| TSR-008.C1 | Code SHALL comply with MISRA C++:2008 or AUTOSAR C++14 guidelines (safety-critical subset) |
| TSR-008.C2 | Code SHALL pass Clang-Tidy checks (cert-*, bugprone-*, cppcoreguidelines-*) |
| TSR-008.C3 | Code SHALL pass Cppcheck static analysis (no errors, warnings as errors) |
| TSR-008.C4 | Code SHALL be compiled with `-Wall -Wextra -Werror -Wconversion` (all warnings as errors) |

**Dynamic Analysis Requirements:**

| TSR-008.D1 | All tests SHALL run with AddressSanitizer (ASAN) enabled (detect buffer overflows, use-after-free) |
| TSR-008.D2 | All tests SHALL run with UndefinedBehaviorSanitizer (UBSAN) enabled (detect undefined behavior) |
| TSR-008.D3 | All tests SHALL run with Valgrind Memcheck (detect memory leaks) |

**Fuzzing Requirements:**

| TSR-008.F1 | libsum SHALL be fuzzed with libFuzzer or AFL++ (protocol buffer fuzzing) |
| TSR-008.F2 | Fuzzing SHALL run for ≥ 24 hours (achieve ≥ 95% code coverage) |
| TSR-008.F3 | All fuzzing crashes SHALL be fixed before release |

**Safety Mechanism:** Fail-fast on memory errors (return OUT_OF_MEMORY instead of proceeding with corrupted state).

**Verification:** Continuous integration (CI/CD) with ASAN/UBSAN/Valgrind on every commit.

---

## 5. Interface Specifications

### 5.1 libsum API (C Interface for AUTOSAR)

```c
/**
 * @brief Verify update manifest (ASIL-D)
 *
 * @param manifest_data Protobuf-encoded manifest (DER format)
 * @param manifest_size Size of manifest in bytes
 * @param root_ca_cert Root CA certificate (DER format)
 * @param root_ca_size Size of Root CA certificate
 * @param device_id Device identifier (VIN, ECU serial)
 * @param last_installed_version Previous security version (from NVM)
 * @param last_installed_timestamp Previous timestamp (from NVM)
 * @param reject_timestamp Optional: Reject CAs issued before this time (0 = disabled)
 *
 * @return 0 (SUCCESS) if all checks pass
 * @return -1 (CERT_INVALID) if certificate chain invalid
 * @return -2 (SIGNATURE_INVALID) if signature verification fails
 * @return -3 (HASH_MISMATCH) if hash verification fails
 * @return -4 (ROLLBACK_DETECTED) if version downgrade detected
 * @return -5 (REPLAY_DETECTED) if timestamp reused
 * @return -6 (CERT_EXPIRED) if certificate expired
 * @return -7 (CERT_REVOKED) if certificate revoked
 * @return -8 (WRONG_DEVICE) if device ID mismatch
 * @return -9 (DECRYPT_FAILED) if decryption fails
 * @return -10 (OUT_OF_MEMORY) if memory allocation fails
 */
int sum_verify_manifest(
    const uint8_t* manifest_data,
    size_t manifest_size,
    const uint8_t* root_ca_cert,
    size_t root_ca_size,
    const char* device_id,
    uint64_t last_installed_version,
    uint64_t last_installed_timestamp,
    uint64_t reject_timestamp
);

/**
 * @brief Decrypt and verify artifact payload (ASIL-D)
 *
 * @param encrypted_payload AES-128-GCM encrypted payload
 * @param payload_size Size of encrypted payload
 * @param device_private_key X25519 private key (32 bytes)
 * @param expected_hash SHA-256 hash from manifest (32 bytes)
 * @param decrypted_output Buffer for decrypted payload (allocated by caller)
 * @param output_size Size of decrypted output buffer
 *
 * @return 0 (SUCCESS) if decryption and hash verification pass
 * @return -3 (HASH_MISMATCH) if hash verification fails
 * @return -9 (DECRYPT_FAILED) if decryption fails
 * @return -10 (OUT_OF_MEMORY) if buffer too small
 */
int sum_decrypt_and_verify_payload(
    const uint8_t* encrypted_payload,
    size_t payload_size,
    const uint8_t* device_private_key,
    const uint8_t* expected_hash,
    uint8_t* decrypted_output,
    size_t* output_size
);
```

### 5.2 Integrating System Callbacks (AUTOSAR → libsum)

```c
/**
 * @brief Read last installed version from NVM (ASIL-D)
 *
 * @param version Output: Last installed security version
 * @param timestamp Output: Last installed timestamp
 * @return 0 on success, -1 on NVM read failure
 */
typedef int (*sum_get_version_callback)(uint64_t* version, uint64_t* timestamp);

/**
 * @brief Get device identifier (ASIL-C)
 *
 * @param device_id Output buffer (must be ≥ 64 bytes)
 * @return 0 on success, -1 on failure
 */
typedef int (*sum_get_device_id_callback)(char* device_id);

/**
 * @brief Get current time (ASIL-C)
 *
 * @param current_time Output: Unix timestamp (seconds since epoch)
 * @return 0 on success, -1 if time source unavailable
 */
typedef int (*sum_get_time_callback)(uint64_t* current_time);
```

### 5.3 Data Flow Sequence

```
1. AUTOSAR Update Manager receives manifest + payload
2. AUTOSAR calls sum_verify_manifest(manifest, root_ca, device_id, last_version, ...)
3. libsum:
   a. Parse manifest (protobuf)
   b. Verify X.509 chain (Root → Intermediate → Update)
   c. Verify Ed25519 signature
   d. Check version > last_version
   e. Check device_id match
   f. Check timestamp > last_timestamp
   g. Check revocation (if reject_timestamp provided)
4. libsum returns 0 (SUCCESS) or negative error code
5. IF SUCCESS:
   a. AUTOSAR calls sum_decrypt_and_verify_payload(payload, device_key, hash)
   b. libsum decrypts with X25519+AES-GCM, verifies SHA-256
   c. libsum returns 0 (SUCCESS) or error
6. IF SUCCESS:
   a. AUTOSAR writes decrypted firmware to flash
   b. AUTOSAR verifies flash write (CRC check)
   c. AUTOSAR updates NVM version counter (atomic write)
   d. AUTOSAR triggers bootloader A/B switch
7. ELSE (any error):
   a. AUTOSAR logs error code
   b. AUTOSAR enters safe state (no flash write)
   c. AUTOSAR reports failure to backend
```

---

## 6. Safety Mechanisms Implementation

### 6.1 Error Detection Mechanisms

| Mechanism | Implementation | ASIL | Code Location |
|-----------|----------------|------|---------------|
| **Signature verification** | OpenSSL `EVP_DigestVerify` | ASIL-D | `src/crypto/verify.cpp:245` |
| **Hash verification** | OpenSSL `SHA256` | ASIL-D | `src/crypto/hash.cpp:112` |
| **Version check** | Integer comparison `>` | ASIL-D | `src/manifest.cpp:487` |
| **Timestamp check** | Integer comparison `>` | ASIL-D | `src/manifest.cpp:502` |
| **Device ID check** | `memcmp_const_time` | ASIL-C | `src/manifest.cpp:531` |
| **Revocation check** | X.509 `notBefore` field | ASIL-C | `src/crypto/cert.cpp:298` |

### 6.2 Fault Tolerance Mechanisms

| Mechanism | Implementation | ASIL | Code Location |
|-----------|----------------|------|---------------|
| **Fail-safe return codes** | Every error path returns negative code | ASIL-D | All functions |
| **Memory error handling** | `if (!ptr) return OUT_OF_MEMORY;` | ASIL-D | All malloc sites |
| **Redundant verification** | Signature AND hash (independent) | ASIL-D | `src/verify_manifest.cpp` |
| **Timeout abort** | Watchdog timer (integrating system) | ASIL-C | External (AUTOSAR) |

### 6.3 Diagnostic Mechanisms

| Mechanism | Implementation | Purpose |
|-----------|----------------|---------|
| **Detailed error codes** | 10 distinct error codes | Root cause analysis |
| **Error logging callback** | `sum_log_error(code, message)` | Security event monitoring |
| **Test coverage metrics** | lcov/gcov (≥ 95% line coverage) | Verification completeness |

---

## 7. Hardware Requirements Summary

### 7.1 Minimum Hardware Requirements

| Component | Requirement | ASIL | Justification |
|-----------|-------------|------|---------------|
| **CPU** | ARM Cortex-M4 or equivalent (≥ 50 MHz) | ASIL-D | Crypto operations performance |
| **RAM** | ≥ 128 KB (256 KB recommended) | ASIL-D | Manifest parsing + crypto buffers |
| **Flash** | ≥ 256 KB for libsum library | ASIL-D | Code storage |
| **NVM (EEPROM)** | ≥ 256 bytes with ECC | ASIL-D | Version counter storage |
| **RTC** | Battery-backed RTC or Roughtime client | ASIL-C | Timestamp verification |
| **HSM (optional)** | Hardware Security Module for key storage | N/A | Enhanced security (not required) |

### 7.2 Recommended Hardware Features

| Feature | Benefit | ASIL Impact |
|---------|---------|-------------|
| **ARM TrustZone** | Isolate libsum in secure world | Improves ASIL-D confidence |
| **Hardware crypto accelerator** | 10× faster SHA-256, AES-GCM | Reduces WCET (helps ASIL-C timeout) |
| **MPU (Memory Protection Unit)** | Prevent buffer overflow exploitation | Improves ASIL-D robustness |
| **Dual-bank flash** | Atomic A/B update (no bricking) | Improves availability (not safety) |

---

## 8. Software Requirements Summary

### 8.1 Dependencies

| Dependency | Version | License | ASIL Requirement |
|------------|---------|---------|------------------|
| **OpenSSL** | 3.0.x (FIPS) | Apache 2.0 | FIPS 140-2 validated |
| **mbedtls** | 3.x | Apache 2.0 | Alternative to OpenSSL (embedded) |
| **nanopb** | 0.4.8+ | Zlib | Protobuf parser (safety-critical subset) |
| **protobuf** | 3.x (code gen) | BSD-3-Clause | Code generation only (not runtime) |

### 8.2 Build Requirements

| Tool | Version | Purpose |
|------|---------|---------|
| **CMake** | ≥ 3.20 | Build system |
| **GCC/Clang** | ≥ 11.0 | Compiler (C++17 support) |
| **Clang-Tidy** | ≥ 14.0 | Static analysis |
| **Cppcheck** | ≥ 2.10 | Static analysis |
| **ASAN/UBSAN** | Built-in | Dynamic analysis |
| **Valgrind** | ≥ 3.20 | Memory leak detection |
| **lcov/gcov** | Latest | Code coverage |

### 8.3 Coding Standards

| Standard | Compliance Level | Verification |
|----------|------------------|--------------|
| **MISRA C++:2008** | Required rules enforced | Clang-Tidy + manual review |
| **AUTOSAR C++14** | Safety-critical subset | Clang-Tidy config |
| **CERT C++ Secure Coding** | All applicable rules | Clang-Tidy cert-* checks |

---

## 9. Verification Strategy

### 9.1 Unit Testing (ISO 26262-6 Table 10)

| Test Method | Coverage | ASIL Requirement |
|-------------|----------|------------------|
| **Requirements-based testing** | All TSRs covered | ASIL-D (required) |
| **Interface testing** | All API functions | ASIL-D (required) |
| **Fault injection testing** | All error paths | ASIL-D (highly recommended) |
| **Resource usage testing** | Memory, CPU, timeout | ASIL-D (highly recommended) |

### 9.2 Integration Testing

| Test Scenario | Expected Result | ASIL |
|---------------|-----------------|------|
| Valid manifest, all checks pass | SUCCESS, flash write | ASIL-D |
| Invalid signature | SIGNATURE_INVALID, reject | ASIL-D |
| Corrupted payload | HASH_MISMATCH, reject | ASIL-D |
| Rollback attempt | ROLLBACK_DETECTED, reject | ASIL-D |
| Revoked CA | CERT_REVOKED, reject | ASIL-C |
| Wrong device | WRONG_DEVICE, reject | ASIL-C |
| Timeout | Watchdog abort, safe state | ASIL-C |
| Out of memory | OUT_OF_MEMORY, safe state | ASIL-D |

### 9.3 Static Analysis

| Tool | Purpose | Pass Criteria |
|------|---------|---------------|
| **Clang-Tidy** | Coding standards, bug detection | 0 errors, 0 warnings |
| **Cppcheck** | Buffer overflows, memory leaks | 0 errors, 0 warnings |
| **Coverity** | Deep static analysis (optional) | 0 high/medium defects |

### 9.4 Dynamic Analysis

| Tool | Purpose | Pass Criteria |
|------|---------|---------------|
| **ASAN** | Buffer overflow detection | 0 errors in all tests |
| **UBSAN** | Undefined behavior detection | 0 errors in all tests |
| **Valgrind** | Memory leak detection | 0 leaks, 0 errors |
| **libFuzzer** | Fuzzing (protocol buffer inputs) | 0 crashes after 24 hours |

### 9.5 Code Coverage

| Metric | Target | ASIL Requirement |
|--------|--------|------------------|
| **Statement coverage** | ≥ 100% | ASIL-D (required per ISO 26262-6 Table 13) |
| **Branch coverage** | ≥ 100% | ASIL-D (required) |
| **MC/DC coverage** | ≥ 100% (safety-critical functions) | ASIL-D (highly recommended) |

**Current Status:** 61/61 tests pass, coverage measurement in progress.

---

## 10. Traceability Matrix

| FSR | Derived TSRs | Implementation | Test Cases |
|-----|--------------|----------------|------------|
| **FSR-001** (Signature) | TSR-001, TSR-002 | `src/crypto/verify.cpp` | `tests/test_verify_signature.cpp` |
| **FSR-002** (Hash) | TSR-003 | `src/crypto/hash.cpp` | `tests/test_hash_verification.cpp` |
| **FSR-003** (Rollback) | TSR-004 | `src/manifest.cpp:487` | `tests/test_rollback.cpp` |
| **FSR-004** (Revocation) | TSR-005 | `src/crypto/cert.cpp:298` | `tests/test_revocation.cpp` |
| **FSR-005** (Device ID) | TSR-006 | `src/manifest.cpp:531` | `tests/test_device_id.cpp` |
| **FSR-006** (Timeout) | TSR-007 | All functions | `tests/integration/test_timeout.cpp` |
| **FSR-007** (Memory) | TSR-008 | All code | ASAN/Valgrind on all tests |

**All FSRs traced to TSRs. All TSRs traced to implementation and tests.**

---

## 11. Open Items and Recommendations

### 11.1 Open Items

| Item | Status | Owner | Due Date |
|------|--------|-------|----------|
| Measure WCET on target hardware | ⚠️ Pending | Integrating system team | TBD |
| FIPS 140-2 validation evidence | ⚠️ Pending | Crypto library vendor | TBD |
| MC/DC coverage for safety-critical functions | ⚠️ Pending | libsum contributors | TBD |
| Fault injection testing (bit flips, power glitches) | ⚠️ Pending | Test team | TBD |

### 11.2 Recommendations

1. **Use ARM TrustZone** to isolate libsum in secure world (ASIL-D confidence improvement)
2. **Enable hardware crypto acceleration** (reduce WCET, improve timeout margins)
3. **Use dual-bank flash** for A/B updates (prevent bricking, improves availability)
4. **Implement secure boot** to verify bootloader before libsum execution (Root of Trust)
5. **Monitor CVE databases** for OpenSSL/mbedtls vulnerabilities (continuous security)

---

## 12. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-27 | libsum contributors | Initial Technical Safety Concept |

**Next Document:** Safety Requirements Specification (Document 05)

**Approval Required:**
- [ ] Functional Safety Manager
- [ ] Software Architect
- [ ] Hardware Architect (integrating system)
- [ ] Independent Safety Assessor

---

**End of Technical Safety Concept**
