# ISO 26262 Item Definition
## libsum - Secure Update Verification Library (SEooC)

**Document ID:** LIBSUM-ISO26262-ITEM-001
**Version:** 1.0
**Date:** 2025-11-27
**Status:** Draft for Review
**ASIL Target:** ASIL-D (SEooC - Safety Element out of Context)

---

## 1. Purpose and Scope

This document defines **libsum** as a **Safety Element out of Context (SEooC)** per ISO 26262-8:2018 for use in automotive Over-The-Air (OTA) software update systems targeting up to ASIL-D.

### 1.1 SEooC Definition

**libsum** is a **cryptographic verification library** that provides security functions for validating firmware updates. It does NOT perform the actual update installation, ECU reprogramming, or safe state management. These safety-critical functions are the responsibility of the **integrating system** (e.g., AUTOSAR Update Manager).

### 1.2 Intended Use

- **Remote OTA Updates:** Cellular/WiFi firmware distribution
- **Workshop/Dealer Updates:** USB/SD card offline distribution
- **All ECU Types:** Infotainment (QM), ADAS (ASIL-B/C), Powertrain (ASIL-D)

### 1.3 Development Scope

This item definition covers:
- ✅ **libsum library** (C++ backend, C client/libsum-tiny)
- ✅ **Cryptographic verification functions**
- ✅ **Security mechanisms**
- ❌ **NOT included:** AUTOSAR Update Manager, bootloaders, flash drivers, ECU-specific update logic

---

## 2. Item Boundary and Interfaces

### 2.1 System Context

```
┌──────────────────────────────────────────────────────────────────┐
│ Vehicle OTA Update System (ASIL-D capable)                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ AUTOSAR Update Manager / Integrating System (ASIL-D)      │ │
│  │ - Flash writing                                            │ │
│  │ - Safe state management                                    │ │
│  │ - Fault handling                                           │ │
│  │ - ECU coordination                                         │ │
│  │ - Rollback execution                                       │ │
│  │ - Bootloader management                                    │ │
│  └────────────────────────────────────────────────────────────┘ │
│                              ▲                                    │
│                              │ Interface (Assumptions of Use)    │
│                              ▼                                    │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ libsum - Security Verification Library (SEooC ASIL-D)     │ │
│  │ ┌────────────────────────────────────────────────────────┐│ │
│  │ │ Certificate Chain Validation (Ed25519)                 ││ │
│  │ │ - Root CA → Intermediate CA → Update Certificate       ││ │
│  │ │ - Timestamp validation (notBefore/notAfter)            ││ │
│  │ │ - Revocation check (timestamp-based)                   ││ │
│  │ └────────────────────────────────────────────────────────┘│ │
│  │ ┌────────────────────────────────────────────────────────┐│ │
│  │ │ Manifest Verification                                  ││ │
│  │ │ - Protobuf parsing                                     ││ │
│  │ │ - Anti-rollback check (version > last_installed)       ││ │
│  │ │ - Replay prevention (version not already installed)    ││ │
│  │ └────────────────────────────────────────────────────────┘│ │
│  │ ┌────────────────────────────────────────────────────────┐│ │
│  │ │ Firmware Decryption & Verification                     ││ │
│  │ │ - Key unwrapping (X25519 ECDH)                         ││ │
│  │ │ - AES-128-GCM decryption (streaming)                   ││ │
│  │ │ - SHA-256 hash verification                            ││ │
│  │ │ - Ed25519 signature verification                       ││ │
│  │ └────────────────────────────────────────────────────────┘│ │
│  └────────────────────────────────────────────────────────────┘ │
│                              ▲                                    │
│                              │                                    │
│                              ▼                                    │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Update Package Inputs                                      │ │
│  │ - update.crt (X.509 certificate with embedded manifest)    │ │
│  │ - firmware.enc (encrypted firmware)                        │ │
│  │ - Root CA certificate (pre-installed trust anchor)        │ │
│  │ - Device private key (X25519)                             │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### 2.2 Functional Boundaries

**libsum IS responsible for:**
- ✅ Cryptographic correctness (signature/hash verification)
- ✅ Certificate chain validation (3-tier PKI)
- ✅ Anti-rollback detection (version comparison)
- ✅ Replay attack detection (duplicate version)
- ✅ Time validation (certificate expiry)
- ✅ Firmware decryption (AES-GCM)
- ✅ Manifest integrity (protobuf parsing)
- ✅ Returning verification result (PASS/FAIL)

**libsum IS NOT responsible for:**
- ❌ Flash writing / ECU reprogramming
- ❌ Safe state transitions (degraded mode)
- ❌ Fault detection beyond crypto failures
- ❌ Bootloader switching (A/B partitions)
- ❌ ECU reset / power management
- ❌ Network communication
- ❌ Update scheduling / orchestration
- ❌ Diagnostic error reporting (DTC)

### 2.3 Interfaces

#### 2.3.1 Inputs (from Integrating System)

| Input | Type | Safety Relevance | Validation |
|-------|------|------------------|------------|
| **Update Certificate** | Binary (DER/PEM) | High | Full X.509 validation |
| **Encrypted Firmware** | Binary | High | Hash + signature verification |
| **Root CA Certificate** | Binary (DER/PEM) | Critical | Pre-installed, integrity checked |
| **Device Private Key** | Binary (32 bytes) | Critical | Secure storage, integrating system responsibility |
| **Current Time** | Unix timestamp (int64) | Medium | Trusted time source (RTC/Roughtime) |
| **Last Installed Version** | uint64 | High | Anti-rollback state |
| **Reject Timestamp** | Unix timestamp (int64) | High | Revocation state |

#### 2.3.2 Outputs (to Integrating System)

| Output | Type | Safety Relevance | Meaning |
|--------|------|------------------|---------|
| **Verification Result** | Enum (PASS/FAIL/ERROR) | Critical | GO/NO-GO decision for update |
| **Error Code** | Integer | High | Failure reason (certificate invalid, signature mismatch, etc.) |
| **Decrypted Firmware** | Binary buffer | High | Verified plaintext firmware |
| **Manifest Data** | Structured data | Medium | Update metadata (version, artifact names) |

#### 2.3.3 Error Codes (Safety-Relevant)

| Code | Name | Safety Impact | Integrating System Action |
|------|------|---------------|---------------------------|
| `0` | `SUCCESS` | None | Proceed with update |
| `-1` | `CERT_INVALID` | **High** | Reject update, log security event |
| `-2` | `SIGNATURE_INVALID` | **High** | Reject update, log security event |
| `-3` | `HASH_MISMATCH` | **High** | Reject update, corrupted firmware |
| `-4` | `ROLLBACK_DETECTED` | **High** | Reject update, potential attack |
| `-5` | `REPLAY_DETECTED` | **High** | Reject update, potential attack |
| `-6` | `CERT_EXPIRED` | **Medium** | Reject update, check time source |
| `-7` | `CERT_REVOKED` | **High** | Reject update, compromised CA |
| `-8` | `WRONG_DEVICE` | **Medium** | Reject update, wrong target |
| `-9` | `DECRYPT_FAILED` | **High** | Reject update, key/crypto error |
| `-10` | `OUT_OF_MEMORY` | **Critical** | Reject update, enter safe state |

---

## 3. Functional Description

### 3.1 Primary Safety Function

**SF-001: Reject Malicious or Corrupted Firmware**

**Behavior:**
- libsum SHALL verify cryptographic authenticity before allowing firmware to be used
- libsum SHALL detect tampering via signature verification
- libsum SHALL prevent installation of unverified firmware
- libsum SHALL return deterministic error codes

**Safety Mechanism:** Multi-layer cryptographic verification (defense in depth)

### 3.2 Update Verification Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. Certificate Chain Validation                                 │
│    ├─ Parse X.509 certificate (DER/PEM)                         │
│    ├─ Verify Root CA → Intermediate CA → Update Certificate     │
│    ├─ Check notBefore/notAfter (time validation)                │
│    ├─ Check revocation (timestamp-based)                        │
│    └─ Extract embedded manifest (protobuf)                      │
│      ⚠️ SAFETY: All manifest data cryptographically protected   │
└─────────────────────────────────────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. Manifest Validation                                          │
│    ├─ Parse protobuf manifest                                   │
│    ├─ Check manifest_version > last_installed_version           │
│    ├─ Check manifest_version not in history (replay prevention) │
│    ├─ Verify device_id matches (per-device encryption)          │
│    └─ Extract artifact metadata (hash, signature, encryption)   │
│      ⚠️ SAFETY: Anti-rollback prevents vulnerable firmware      │
└─────────────────────────────────────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. Firmware Decryption & Verification                           │
│    ├─ Unwrap AES key (X25519 ECDH)                              │
│    ├─ Decrypt firmware (AES-128-GCM streaming)                  │
│    ├─ Compute SHA-256 hash (streaming)                          │
│    ├─ Verify hash matches manifest.expected_hash                │
│    └─ Verify Ed25519 signature over hash                        │
│      ⚠️ SAFETY: Firmware verified before return to integrator   │
└─────────────────────────────────────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. Return Result to Integrating System                          │
│    ├─ SUCCESS: Decrypted firmware + manifest                    │
│    ├─ FAILURE: Error code + diagnostic info                     │
│    └─ Integrating system makes final GO/NO-GO decision          │
│      ⚠️ SAFETY: libsum only verifies, does not execute update   │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 Operating Modes

| Mode | Description | Safety Considerations |
|------|-------------|----------------------|
| **Normal Operation** | Full verification, all checks enabled | Default mode, highest security |
| **Time Validation Disabled** | Skip certificate expiry checks | ⚠️ **NOT RECOMMENDED for production**, compile-time flag only |

**Note:** libsum does NOT have degraded/safe modes. It either verifies correctly or returns an error. The integrating system handles safe states.

---

## 4. Assumptions of Use (Safety-Critical)

### 4.1 Integrating System Responsibilities

The integrating system (AUTOSAR Update Manager) **MUST**:

1. **Pre-Conditions:**
   - ✅ Provide valid Root CA certificate (integrity-protected)
   - ✅ Provide trusted time source (RTC with battery backup or Roughtime)
   - ✅ Store device private key securely (not extractable)
   - ✅ Maintain persistent storage for anti-rollback state

2. **Post-Verification Actions:**
   - ✅ ONLY write firmware to flash if libsum returns `SUCCESS`
   - ✅ Enter safe state if libsum returns `OUT_OF_MEMORY` or critical error
   - ✅ Persist new version number AFTER successful flash write
   - ✅ Trigger bootloader A/B switch AFTER verification

3. **Fault Handling:**
   - ✅ Monitor libsum execution time (detect hangs)
   - ✅ Implement timeout for verification (prevent infinite loops)
   - ✅ Log all verification failures for diagnostics
   - ✅ Report security events (rollback attempts, invalid signatures)

4. **Memory Safety:**
   - ✅ Provide sufficient stack space (8KB minimum for libsum-tiny)
   - ✅ Prevent heap exhaustion (libsum-tiny uses no heap, libsum needs ~2-4MB)
   - ✅ Validate buffer sizes before calling libsum APIs

### 4.2 Environment Assumptions

| Assumption | Justification | Risk if Violated |
|------------|---------------|------------------|
| **Root CA private key is secure** | Stored offline in HSM | Complete system compromise |
| **Device private key is secure** | Flash read-out protection enabled | Single device compromise (isolated) |
| **Time source is trusted** | RTC with battery backup or Roughtime | Expired certificate acceptance |
| **Persistent storage is reliable** | ECC-protected EEPROM/flash | Anti-rollback bypass |
| **Crypto libraries are correct** | OpenSSL 3.0+ / mbedtls 3.x (FIPS validated) | Crypto failures |

### 4.3 Threat Model (Out of Scope for libsum)

libsum **protects against**:
- ✅ Malicious firmware injection
- ✅ Firmware tampering
- ✅ Rollback attacks (older vulnerable firmware)
- ✅ Replay attacks (re-installing same version)
- ✅ Man-in-the-middle attacks
- ✅ Compromised intermediate CA (via timestamp revocation)

libsum **does NOT protect against** (integrating system responsibility):
- ❌ Physical attacks (JTAG, voltage glitching)
- ❌ Side-channel attacks (power analysis, timing)
- ❌ Fault injection during verification
- ❌ Flash write errors (integrating system must verify)
- ❌ Bootloader vulnerabilities

---

## 5. Dependent Failures (Systematic)

### 5.1 Common Cause Failures

| Failure Mode | Potential Impact | Mitigation |
|--------------|------------------|------------|
| **OpenSSL/mbedtls vulnerability** | All crypto verification fails | Use FIPS-validated versions, monitor CVEs |
| **Protobuf parsing bug** | Manifest parsing failure | Extensive fuzzing, strict size limits |
| **Time source corruption** | Expired certificate accepted | Integrating system provides trusted time, libsum validates |
| **Memory corruption** | Unpredictable behavior | libsum-tiny: no heap allocation, stack canaries recommended |

### 5.2 Independence from Vehicle Systems

libsum operates **independently** from:
- ❌ Vehicle CAN/LIN/FlexRay networks (no direct bus access)
- ❌ Sensor inputs (no physical world dependency)
- ❌ Actuator outputs (no control authority)
- ❌ Other ECU functions (pure verification logic)

**Result:** libsum failures do NOT propagate to vehicle control systems.

---

## 6. Safety-Related Elements

### 6.1 Safety Mechanisms in libsum

| Mechanism | Type | ASIL | Diagnostic Coverage |
|-----------|------|------|---------------------|
| **Signature Verification** | Detection | ASIL-D | 99% (crypto failures detected) |
| **Hash Verification** | Detection | ASIL-D | 99% (corruption detected) |
| **Anti-Rollback Check** | Prevention | ASIL-D | 100% (version comparison) |
| **Certificate Chain Validation** | Detection | ASIL-D | 99% (chain breaks detected) |
| **Time Validation** | Detection | ASIL-B | 95% (depends on time source) |
| **Input Validation** | Prevention | ASIL-C | 100% (bounds checking) |

### 6.2 Safety Requirements Allocation

**Allocated to libsum:**
- SR-LIB-001: Cryptographic correctness (signature/hash verification)
- SR-LIB-002: Deterministic behavior (same inputs → same outputs)
- SR-LIB-003: Error detection (all crypto failures reported)
- SR-LIB-004: No side effects (read-only operation)

**Allocated to Integrating System:**
- SR-INT-001: Safe state management (on verification failure)
- SR-INT-002: Flash write protection (only after SUCCESS)
- SR-INT-003: Fault containment (timeout, watchdog)
- SR-INT-004: Diagnostic logging (DTC generation)

---

## 7. Item Configuration

### 7.1 Variants

| Variant | Language | Target | Memory | Crypto Library |
|---------|----------|--------|--------|----------------|
| **libsum** | C++ | Build system, Linux ECUs | 2-4 MB heap | OpenSSL 3.0+ |
| **libsum-tiny** | C | Embedded (ESP32, STM32) | **0 heap**, 8KB stack | mbedtls 3.x |

### 7.2 Configuration Options (Safety-Relevant)

| Option | Default | Safety Impact | Recommendation |
|--------|---------|---------------|----------------|
| `SUM_TINY_ALLOW_SKIP_TIME_VALIDATION` | Disabled | **High** - allows expired certs | **NEVER enable in production** |
| Streaming buffer size | 1 KB | Low - affects memory only | Tune per ECU RAM availability |

---

## 8. Related Standards and Regulations

| Standard | Applicability | Compliance Status |
|----------|---------------|-------------------|
| **ISO 26262-8:2018** | Automotive functional safety (OTA) | ✅ Design follows recommendations |
| **ISO/SAE 21434:2021** | Automotive cybersecurity | ✅ Cryptographic requirements met |
| **UN R155** | Cybersecurity management | ✅ Software update security addressed |
| **UN R156** | Software update management | ⚠️ Requires workshop orchestration (out of scope) |
| **AUTOSAR Adaptive Platform** | Update Manager interface | ✅ Compatible with AUTOSAR UCM |

---

## 9. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-27 | libsum contributors | Initial item definition (SEooC) |

**Approval Required:**
- [ ] Project Safety Manager
- [ ] Chief Engineer (AUTOSAR integration)
- [ ] Cybersecurity Architect
- [ ] Quality Manager (ISO 26262 compliance)

**Next Steps:**
1. Hazard Analysis and Risk Assessment (HARA) → Document 02
2. Functional Safety Concept → Document 03
3. Technical Safety Concept → Document 04

---

**End of Item Definition**
