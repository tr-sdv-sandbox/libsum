# ISO 26262 Functional Safety Concept (FSC)
## libsum - Secure Update Verification Library (SEooC)

**Document ID:** LIBSUM-ISO26262-FSC-003
**Version:** 1.0
**Date:** 2025-11-27
**Status:** Draft for Review
**ASIL Target:** ASIL-D (SEooC)

---

## 1. Purpose

This document derives **Functional Safety Requirements (FSRs)** from the safety goals identified in the HARA (Document 02), defines safety mechanisms, and allocates requirements to libsum and the integrating system per ISO 26262-3:2018 Clause 8.

---

## 2. Scope

This FSC applies to:
- **libsum** (verification library - SEooC)
- **Integrating System** (AUTOSAR Update Manager or equivalent)

The FSC does **NOT** cover:
- Workshop server orchestration logic
- Backend key management infrastructure
- Vehicle-level integration (CAN/Ethernet communication)

---

## 3. Safety Goals Summary (from HARA)

| Safety Goal | ASIL | Description |
|-------------|------|-------------|
| **SG-001** | ASIL-D | Prevent execution of unverified firmware on safety-critical ECUs |
| **SG-002** | ASIL-D | Prevent execution of corrupted firmware on safety-critical ECUs |
| **SG-003** | ASIL-D | Prevent rollback to vulnerable firmware versions |
| **SG-004** | ASIL-C | Prevent acceptance of firmware from revoked certificate authorities |
| **SG-005** | ASIL-C | Prevent indefinite blocking of safety-critical ECU functions |
| **SG-006** | ASIL-C | Prevent installation of firmware intended for different devices |

---

## 4. Functional Safety Requirements

### 4.1 FSR-001: Cryptographic Signature Verification (SG-001, ASIL-D)

**Derived from:** SG-001 (Prevent unverified firmware execution)

**Requirement:**
libsum **SHALL** verify the X.509 certificate chain and Ed25519 signature of the manifest before returning `SUCCESS`.

**Functional Behavior:**

| Step | Action | Fault Handling |
|------|--------|----------------|
| 1 | Parse X.509 certificate chain from manifest | Return `CERT_INVALID` if parse fails |
| 2 | Verify Root CA → Intermediate CA signature | Return `CERT_INVALID` if verification fails |
| 3 | Verify Intermediate CA → Update Certificate signature | Return `CERT_INVALID` if verification fails |
| 4 | Extract Ed25519 public key from Update Certificate | Return `CERT_INVALID` if key extraction fails |
| 5 | Compute canonical manifest bytes (exclude signature field) | Return internal error if serialization fails |
| 6 | Verify Ed25519 signature over canonical manifest | Return `SIGNATURE_INVALID` if verification fails |

**Safe State:** Current firmware continues running (no update applied)

**FTTI (Fault Tolerance Time Interval):** Immediate (before firmware installation)

**Allocation:**
- **libsum:** Implements signature verification (ASIL-D)
- **Integrating System:** ONLY installs firmware if libsum returns `SUCCESS` (ASIL-D)

---

### 4.2 FSR-002: Hash Integrity Verification (SG-002, ASIL-D)

**Derived from:** SG-002 (Prevent corrupted firmware execution)

**Requirement:**
libsum **SHALL** verify the SHA-256 hash of each artifact payload before returning `SUCCESS`.

**Functional Behavior:**

| Step | Action | Fault Handling |
|------|--------|----------------|
| 1 | Decrypt artifact payload (if encrypted) | Return `DECRYPT_FAILED` if decryption fails |
| 2 | Compute SHA-256 hash of decrypted payload | Return internal error if hash computation fails |
| 3 | Compare computed hash with manifest's `payload_sha256` | Return `HASH_MISMATCH` if hashes differ |
| 4 | Repeat for all artifacts in manifest | Return error on first failure |

**Safe State:** Current firmware continues running (no update applied)

**FTTI:** Immediate (before firmware installation)

**Allocation:**
- **libsum:** Implements hash verification (ASIL-D)
- **Integrating System:** ONLY writes flash if all hashes verify (ASIL-D)

**Note:** Hash verification is **independent** of signature verification (defense in depth).

---

### 4.3 FSR-003: Anti-Rollback Protection (SG-003, ASIL-D)

**Derived from:** SG-003 (Prevent rollback to vulnerable firmware)

**Requirement:**
libsum **SHALL** enforce monotonic version increase by comparing manifest `security_version` with persistent `last_installed_version`.

**Functional Behavior:**

| Step | Action | Fault Handling |
|------|--------|----------------|
| 1 | Read `last_installed_version` from integrating system | Return `ROLLBACK_DETECTED` if read fails (fail-safe) |
| 2 | Compare `manifest.security_version > last_installed_version` | Return `ROLLBACK_DETECTED` if condition false |
| 3 | Check `manifest.timestamp > last_installed_timestamp` | Return `REPLAY_DETECTED` if condition false |

**Safe State:** Current firmware continues running (no downgrade)

**FTTI:** Immediate (before firmware installation)

**Allocation:**
- **libsum:** Implements version comparison logic (ASIL-D)
- **Integrating System:**
  - Provides persistent storage for `last_installed_version` (ASIL-D)
  - Updates stored version **AFTER** successful flash write (ASIL-D)
  - Ensures atomic write (version update fails → safe, rollback accepted → unsafe)

**Critical Integration Point:** Integrating system MUST use write-once or wear-leveling storage (e.g., EEPROM with CRC, NVM with redundant copies) to prevent version counter corruption.

---

### 4.4 FSR-004: Certificate Revocation Check (SG-004, ASIL-C)

**Derived from:** SG-004 (Prevent revoked CA acceptance)

**Requirement:**
libsum **SHALL** check if the Intermediate CA certificate was issued after the provided `reject_timestamp` (if provided by integrating system).

**Functional Behavior:**

| Step | Action | Fault Handling |
|------|--------|----------------|
| 1 | Check if integrating system provided `reject_timestamp` | Skip check if not provided (optional feature) |
| 2 | Extract Intermediate CA `notBefore` field | Return `CERT_INVALID` if field missing |
| 3 | Compare `notBefore > reject_timestamp` | Return `CERT_REVOKED` if condition false |

**Safe State:** Reject update from potentially compromised CA

**FTTI:** Immediate (before firmware decryption)

**Allocation:**
- **libsum:** Implements timestamp comparison (ASIL-C)
- **Integrating System:**
  - Provides trusted time source (RTC with battery backup or Roughtime) (ASIL-C)
  - Optionally provides `reject_timestamp` from backend (ASIL-C)

**Note:** This is a **simple revocation mechanism** (no CRL/OCSP). Assumes OEM can coordinate firmware signing to only use post-revocation Intermediate CAs.

---

### 4.5 FSR-005: Device Identity Verification (SG-006, ASIL-C)

**Derived from:** SG-006 (Prevent cross-device installation)

**Requirement:**
libsum **SHALL** verify the manifest's `device_id` matches the device's identifier before key unwrapping.

**Functional Behavior:**

| Step | Action | Fault Handling |
|------|--------|----------------|
| 1 | Read device ID from integrating system (e.g., VIN, ECU serial) | Return `WRONG_DEVICE` if read fails |
| 2 | Compare `manifest.device_id == device_id` (string match) | Return `WRONG_DEVICE` if mismatch |
| 3 | Proceed with X25519 key unwrapping only if match | Skip decryption if mismatch |

**Safe State:** Reject update intended for different device

**FTTI:** Immediate (before key unwrapping)

**Allocation:**
- **libsum:** Implements string comparison (ASIL-C)
- **Integrating System:** Provides device ID from secure storage (ASIL-C)

**Critical Integration Point:** Device ID MUST be immutable and integrity-protected (e.g., stored in OTP fuses, signed by Root CA).

---

### 4.6 FSR-006: Deterministic Execution (SG-005, ASIL-C)

**Derived from:** SG-005 (Prevent ECU function blocking)

**Requirement:**
libsum **SHALL** execute verification in bounded time with no infinite loops or blocking operations.

**Functional Behavior:**

| Aspect | Requirement | Rationale |
|--------|-------------|-----------|
| **Memory allocation** | All memory pre-allocated (no malloc during verification) | Prevents unbounded allocation loops |
| **Crypto operations** | Use constant-time algorithms (no data-dependent branches) | Prevents timing attacks and unbounded execution |
| **Protobuf parsing** | nanopb max_size limits enforced | Prevents malicious manifests from causing hangs |
| **Certificate parsing** | OpenSSL/mbedtls with size limits | Prevents ASN.1 parser exploits |

**Safe State:** Integrating system detects timeout and aborts verification

**FTTI:** Integrating system defines (e.g., 5 seconds for typical manifest)

**Allocation:**
- **libsum:** Implements deterministic algorithms (ASIL-B - reduced from C via decomposition)
- **Integrating System:**
  - Implements watchdog timer (ASIL-C)
  - Aborts verification if timeout exceeded (ASIL-C)
  - Logs timeout event for diagnostics (ASIL-C)

**Note:** libsum cannot guarantee bounded time (depends on crypto library performance), so integrating system MUST provide timeout protection.

---

### 4.7 FSR-007: Memory Safety (SG-001, SG-002, ASIL-D)

**Derived from:** All safety goals (memory corruption affects all verification logic)

**Requirement:**
libsum **SHALL** prevent buffer overflows, use-after-free, and memory leaks during verification.

**Functional Behavior:**

| Mechanism | Implementation | Verification |
|-----------|----------------|--------------|
| **Static analysis** | Clang-Tidy, Cppcheck, AddressSanitizer | CI/CD enforcement (required for ASIL-D) |
| **Dynamic analysis** | Valgrind, ASAN/UBSAN during testing | All tests run with sanitizers enabled |
| **Coding guidelines** | MISRA C++:2008 / AUTOSAR C++14 | Manual code review + automated checkers |
| **Fuzzing** | Protocol buffer fuzzing with libFuzzer | Continuous fuzzing with OSS-Fuzz (future work) |

**Safe State:** Return error code (do not crash, do not proceed with update)

**FTTI:** Immediate (before firmware installation)

**Allocation:**
- **libsum:** Implements memory-safe code (ASIL-D)
- **Integrating System:** Handles `OUT_OF_MEMORY` error gracefully (ASIL-D)

**Critical Safety Mechanism:** If libsum detects memory corruption (e.g., malloc fails, buffer overflow detected), it **MUST** return `OUT_OF_MEMORY` instead of proceeding with verification.

---

## 5. Safety Mechanisms Summary

### 5.1 Error Detection Mechanisms

| Mechanism | ASIL | Safety Goal | Implementation |
|-----------|------|-------------|----------------|
| **Cryptographic verification** | ASIL-D | SG-001 | Ed25519 signature check (FIPS 186-4) |
| **Hash verification** | ASIL-D | SG-002 | SHA-256 comparison (FIPS 180-4) |
| **Version comparison** | ASIL-D | SG-003 | Monotonic counter check |
| **Timestamp comparison** | ASIL-C | SG-004 | X.509 notBefore field check |
| **Device ID comparison** | ASIL-C | SG-006 | String match (constant-time) |
| **Timeout detection** | ASIL-C | SG-005 | Watchdog timer (integrating system) |
| **Memory corruption detection** | ASIL-D | All | ASAN/Valgrind, stack canaries |

### 5.2 Fault Tolerance Mechanisms

| Mechanism | ASIL | Description |
|-----------|------|-------------|
| **Fail-safe design** | ASIL-D | Any verification failure → return error, do NOT install |
| **Defensive return codes** | ASIL-D | 10 distinct error codes for diagnostics |
| **No silent failures** | ASIL-D | Every fault path returns explicit error code |
| **Atomic state updates** | ASIL-D | Integrating system updates version AFTER flash write |
| **Redundant checks** | ASIL-D | Signature AND hash verification (independent) |

### 5.3 Safe States

| Fault | Safe State | Action |
|-------|------------|--------|
| Signature invalid | Current firmware continues | Reject update, log security event |
| Hash mismatch | Current firmware continues | Reject update, log corruption event |
| Rollback detected | Current firmware continues | Reject update, log attack attempt |
| Timeout | ECU functions available | Abort verification, log timeout |
| Out of memory | ECU functions available | Abort verification, enter safe state |

---

## 6. Functional Safety Requirements Allocation

### 6.1 libsum Responsibilities (SEooC)

| FSR | ASIL | libsum Function | Return Value on Success | Return Value on Failure |
|-----|------|-----------------|-------------------------|-------------------------|
| **FSR-001** | ASIL-D | `sum_verify_manifest()` | `0` (SUCCESS) | `-1` (CERT_INVALID), `-2` (SIGNATURE_INVALID) |
| **FSR-002** | ASIL-D | `sum_verify_artifact_hash()` | `0` (SUCCESS) | `-3` (HASH_MISMATCH) |
| **FSR-003** | ASIL-D | `sum_check_version()` | `0` (SUCCESS) | `-4` (ROLLBACK_DETECTED), `-5` (REPLAY_DETECTED) |
| **FSR-004** | ASIL-C | `sum_check_revocation()` | `0` (SUCCESS) | `-6` (CERT_EXPIRED), `-7` (CERT_REVOKED) |
| **FSR-005** | ASIL-C | `sum_check_device_id()` | `0` (SUCCESS) | `-8` (WRONG_DEVICE) |
| **FSR-006** | ASIL-B | All functions | `0` (SUCCESS) | `-10` (OUT_OF_MEMORY) |
| **FSR-007** | ASIL-D | All functions | `0` (SUCCESS) | `-10` (OUT_OF_MEMORY) |

**Key Principle:** libsum returns `0` (SUCCESS) **IF AND ONLY IF** all checks pass. Any failure returns negative error code.

### 6.2 Integrating System Responsibilities (AUTOSAR Update Manager)

| FSR | ASIL | Integrating System Action |
|-----|------|---------------------------|
| **FSR-001** | ASIL-D | ONLY write firmware to flash if libsum returns `SUCCESS` |
| **FSR-002** | ASIL-D | Verify flash write success before updating version counter |
| **FSR-003** | ASIL-D | Provide persistent storage for `last_installed_version`, update AFTER flash write |
| **FSR-004** | ASIL-C | Provide trusted time source (RTC), optionally provide `reject_timestamp` |
| **FSR-005** | ASIL-C | Provide device ID from secure storage (VIN, ECU serial) |
| **FSR-006** | ASIL-C | Implement watchdog timer, abort verification on timeout |
| **FSR-007** | ASIL-D | Handle `OUT_OF_MEMORY` error, enter safe state if needed |

**Critical Integration Points:**
1. **Atomicity:** Version counter update MUST be atomic with flash write (both succeed or both fail)
2. **Time source:** RTC MUST have battery backup or use network time with authentication (Roughtime)
3. **Device ID:** MUST be immutable and integrity-protected (OTP fuses or signed by Root CA)

---

## 7. Dependent Failure Analysis

### 7.1 Common Cause Failures

| Common Cause | Affected FSRs | ASIL | Mitigation |
|--------------|---------------|------|------------|
| **OpenSSL/mbedtls crypto bug** | FSR-001, FSR-002 | ASIL-D | Use FIPS 140-2 validated libraries, monitor CVE database |
| **Protobuf parser bug** | FSR-003, FSR-005 | ASIL-D | Fuzzing (libFuzzer), size limits (nanopb max_size) |
| **Time source failure** | FSR-004 | ASIL-C | Battery-backed RTC + Roughtime fallback |
| **NVM corruption** | FSR-003 | ASIL-D | Redundant storage, CRC, wear-leveling |

### 7.2 Independent Implementation

To prevent dependent failures between FSR-001 and FSR-002, libsum ensures:
- Signature verification uses **Ed25519** (crypto library)
- Hash verification uses **SHA-256** (separate crypto primitive)
- Both checks implemented in separate functions with independent error paths

Even if Ed25519 is broken (quantum attack), SHA-256 still detects corruption. Even if SHA-256 collisions are found, signature verification still prevents malicious firmware.

---

## 8. Verification Strategy

### 8.1 FSR Verification Methods

| FSR | Verification Method | Evidence |
|-----|---------------------|----------|
| **FSR-001** | Unit tests with invalid signatures | tests/test_verify_signature.cpp |
| **FSR-002** | Unit tests with corrupted payloads | tests/test_hash_verification.cpp |
| **FSR-003** | Unit tests with old versions | tests/test_rollback.cpp |
| **FSR-004** | Unit tests with revoked CAs | tests/test_revocation.cpp |
| **FSR-005** | Unit tests with wrong device IDs | tests/test_device_id.cpp |
| **FSR-006** | Static analysis + timeout tests | Clang-Tidy, timeout integration tests |
| **FSR-007** | ASAN/Valgrind + fuzzing | All tests run with ASAN, fuzzing corpus |

### 8.2 Integration Testing

| Test Scenario | Expected Behavior | ASIL |
|---------------|-------------------|------|
| Valid manifest, all checks pass | Return `SUCCESS`, install firmware | ASIL-D |
| Invalid signature | Return `SIGNATURE_INVALID`, reject update | ASIL-D |
| Corrupted hash | Return `HASH_MISMATCH`, reject update | ASIL-D |
| Rollback attempt | Return `ROLLBACK_DETECTED`, reject update | ASIL-D |
| Revoked CA | Return `CERT_REVOKED`, reject update | ASIL-C |
| Wrong device ID | Return `WRONG_DEVICE`, reject update | ASIL-C |
| Timeout (malicious manifest) | Integrating system aborts, safe state | ASIL-C |
| Out of memory | Return `OUT_OF_MEMORY`, safe state | ASIL-D |

**All 61 tests currently pass (37 libsum + 24 libsum-tiny).**

---

## 9. FSC Validation

### 9.1 Completeness Check

| Validation Criteria | Status | Evidence |
|---------------------|--------|----------|
| All safety goals covered by FSRs | ✅ Complete | 6 safety goals → 7 FSRs |
| All FSRs allocated to libsum or integrating system | ✅ Complete | Tables 6.1 and 6.2 |
| Safe states defined for all faults | ✅ Complete | Section 5.3 |
| FTTI specified for all FSRs | ✅ Complete | Each FSR section |
| Error detection mechanisms defined | ✅ Complete | Section 5.1 |

### 9.2 Consistency Check

| Validation Criteria | Status | Evidence |
|---------------------|--------|----------|
| FSC consistent with HARA | ✅ Consistent | All safety goals from HARA addressed |
| ASIL levels preserved | ✅ Consistent | No ASIL reduction except FSR-006 (decomposition) |
| Safe states achievable | ✅ Achievable | All safe states = "current firmware continues" |

### 9.3 Pending Reviews

| Review Activity | Status | Reviewer |
|-----------------|--------|----------|
| Functional Safety Manager review | ⚠️ Pending | FSM |
| Independent Safety Assessor review | ⚠️ Pending | ISA |
| Integrating system compatibility check | ⚠️ Pending | AUTOSAR team |

---

## 10. Assumptions and Constraints

### 10.1 Assumptions (from Item Definition)

1. **Vehicle stationary during safety-critical ECU updates** (affects FTTI)
2. **Integrating system implements timeout watchdog** (FSR-006 mitigation)
3. **Root CA key is secure** (offline HSM, not compromised)
4. **Crypto libraries are FIPS-validated** (OpenSSL 3.0 FIPS, mbedtls)
5. **Time source is trusted** (RTC with battery backup or Roughtime)
6. **Device ID is immutable and integrity-protected** (OTP fuses or signed)
7. **NVM is reliable** (ECC-protected, wear-leveled for version counter)

### 10.2 Constraints

1. **libsum cannot detect time-of-check-to-time-of-use (TOCTOU) bugs in integrating system**
   - Mitigation: Integrating system MUST NOT modify manifest after verification
   - Recommended: Use file descriptors, not file paths (avoid race conditions)

2. **libsum cannot prevent integrating system from ignoring errors**
   - Mitigation: AUTOSAR Update Manager MUST be safety-qualified to ASIL-D
   - Recommended: Independent watchdog monitors flash writes vs. verification results

3. **libsum performance depends on crypto library performance**
   - Constraint: Integrating system MUST provide sufficient timeout margin
   - Recommended: Measure worst-case execution time (WCET) on target hardware

---

## 11. Traceability Matrix

| Safety Goal | ASIL | Derived FSRs | Allocated To |
|-------------|------|--------------|--------------|
| **SG-001** (Unverified FW) | ASIL-D | FSR-001, FSR-007 | libsum (ASIL-D) + Integrating System (ASIL-D) |
| **SG-002** (Corrupted FW) | ASIL-D | FSR-002, FSR-007 | libsum (ASIL-D) + Integrating System (ASIL-D) |
| **SG-003** (Rollback) | ASIL-D | FSR-003, FSR-007 | libsum (ASIL-D) + Integrating System (ASIL-D) |
| **SG-004** (Revoked CA) | ASIL-C | FSR-004 | libsum (ASIL-C) + Integrating System (ASIL-C) |
| **SG-005** (Blocking) | ASIL-C | FSR-006 | libsum (ASIL-B) + Integrating System (ASIL-C) |
| **SG-006** (Wrong device) | ASIL-C | FSR-005 | libsum (ASIL-C) + Integrating System (ASIL-C) |

**All safety goals covered. No orphaned requirements.**

---

## 12. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-27 | libsum contributors | Initial Functional Safety Concept |

**Next Document:** Technical Safety Concept (Document 04)

**Approval Required:**
- [ ] Functional Safety Manager
- [ ] Product Owner (OTA system)
- [ ] AUTOSAR Update Manager Team
- [ ] Independent Safety Assessor

---

**End of Functional Safety Concept**
