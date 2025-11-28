# ISO 26262 Safety Requirements Specification
## libsum - Secure Update Verification Library (SEooC)

**Document ID:** LIBSUM-ISO26262-SRS-005
**Version:** 1.0
**Date:** 2025-11-27
**Status:** Draft for Review
**ASIL Target:** ASIL-D (SEooC)

---

## 1. Purpose

This document consolidates all safety requirements (Functional Safety Requirements from Document 03 and Technical Safety Requirements from Document 04) into a formal specification with verification criteria per ISO 26262-4:2018 Clause 7 and ISO 26262-6:2018 Clause 6.

---

## 2. Scope

This specification covers:
- **Functional Safety Requirements (FSRs)** - System-level requirements
- **Technical Safety Requirements (TSRs)** - Implementation-level requirements
- **Software Safety Requirements (SSRs)** - Detailed software requirements
- **Hardware Safety Requirements (HSRs)** - Integrating system hardware requirements
- **Verification criteria** for each requirement

---

## 3. Requirement Hierarchy

```
Safety Goals (SG-001 to SG-006)
    │
    ├─▶ Functional Safety Requirements (FSR-001 to FSR-007)
    │       │
    │       ├─▶ Technical Safety Requirements (TSR-001 to TSR-008)
    │       │       │
    │       │       ├─▶ Software Safety Requirements (SSR-001 to SSR-050)
    │       │       └─▶ Hardware Safety Requirements (HSR-001 to HSR-020)
    │       │
    │       └─▶ Verification Test Cases (TC-001 to TC-100+)
```

---

## 4. Functional Safety Requirements (FSRs)

### 4.1 FSR-001: Cryptographic Signature Verification (ASIL-D)

| **Requirement ID** | FSR-001 |
| **ASIL** | ASIL-D |
| **Derived from** | SG-001 (Prevent unverified firmware execution) |
| **Description** | libsum SHALL verify the X.509 certificate chain and Ed25519 signature of the manifest before returning SUCCESS. |
| **Rationale** | Prevents execution of malicious or tampered firmware |
| **Safe State** | Current firmware continues running (no update applied) |
| **FTTI** | Immediate (before firmware installation) |
| **Acceptance Criteria** | - X.509 chain validated per RFC 5280<br>- Ed25519 signature verified per RFC 8032<br>- Returns SUCCESS only if all checks pass<br>- Returns CERT_INVALID or SIGNATURE_INVALID on failure |
| **Verification Method** | Unit test (TC-001 to TC-010), Static analysis, Code review |
| **Allocation** | libsum (ASIL-D) + Integrating system (ASIL-D) |
| **Derived TSRs** | TSR-001 (X.509), TSR-002 (Ed25519) |

---

### 4.2 FSR-002: Hash Integrity Verification (ASIL-D)

| **Requirement ID** | FSR-002 |
| **ASIL** | ASIL-D |
| **Derived from** | SG-002 (Prevent corrupted firmware execution) |
| **Description** | libsum SHALL verify the SHA-256 hash of each artifact payload before returning SUCCESS. |
| **Rationale** | Detects corruption, transmission errors, or partial tampering |
| **Safe State** | Current firmware continues running (no update applied) |
| **FTTI** | Immediate (before firmware installation) |
| **Acceptance Criteria** | - SHA-256 computed per FIPS 180-4<br>- Hash compared using constant-time memcmp<br>- Returns HASH_MISMATCH if any artifact fails<br>- All artifacts verified before SUCCESS |
| **Verification Method** | Unit test (TC-011 to TC-020), Fault injection (corrupt payloads) |
| **Allocation** | libsum (ASIL-D) + Integrating system (ASIL-D) |
| **Derived TSRs** | TSR-003 (SHA-256) |

---

### 4.3 FSR-003: Anti-Rollback Protection (ASIL-D)

| **Requirement ID** | FSR-003 |
| **ASIL** | ASIL-D |
| **Derived from** | SG-003 (Prevent rollback to vulnerable firmware) |
| **Description** | libsum SHALL enforce monotonic version increase by comparing manifest security_version with persistent last_installed_version. |
| **Rationale** | Prevents downgrade attacks to exploitable firmware versions |
| **Safe State** | Current firmware continues running (no downgrade) |
| **FTTI** | Immediate (before firmware installation) |
| **Acceptance Criteria** | - manifest.security_version > last_installed_version (strict)<br>- manifest.timestamp > last_installed_timestamp (strict)<br>- Returns ROLLBACK_DETECTED if version ≤ last<br>- Returns REPLAY_DETECTED if timestamp ≤ last |
| **Verification Method** | Unit test (TC-021 to TC-030), Integration test (NVM persistence) |
| **Allocation** | libsum (ASIL-D) + Integrating system (ASIL-D) |
| **Derived TSRs** | TSR-004 (Version check) |

---

### 4.4 FSR-004: Certificate Revocation Check (ASIL-C)

| **Requirement ID** | FSR-004 |
| **ASIL** | ASIL-C |
| **Derived from** | SG-004 (Prevent revoked CA acceptance) |
| **Description** | libsum SHALL check if the Intermediate CA certificate was issued after the provided reject_timestamp (if provided). |
| **Rationale** | Prevents use of compromised intermediate CA keys |
| **Safe State** | Reject update from potentially compromised CA |
| **FTTI** | Immediate (before firmware decryption) |
| **Acceptance Criteria** | - Extract Intermediate CA notBefore field<br>- Compare notBefore > reject_timestamp<br>- Returns CERT_REVOKED if notBefore ≤ reject_timestamp<br>- Skips check if reject_timestamp not provided |
| **Verification Method** | Unit test (TC-031 to TC-035), Time source validation |
| **Allocation** | libsum (ASIL-C) + Integrating system (ASIL-C) |
| **Derived TSRs** | TSR-005 (Revocation check) |

---

### 4.5 FSR-005: Device Identity Verification (ASIL-C)

| **Requirement ID** | FSR-005 |
| **ASIL** | ASIL-C |
| **Derived from** | SG-006 (Prevent cross-device installation) |
| **Description** | libsum SHALL verify the manifest's device_id matches the device's identifier before key unwrapping. |
| **Rationale** | Prevents firmware intended for different ECU from being installed |
| **Safe State** | Reject update intended for different device |
| **FTTI** | Immediate (before key unwrapping) |
| **Acceptance Criteria** | - Read device ID from integrating system<br>- Compare manifest.device_id == device_id (case-sensitive, constant-time)<br>- Returns WRONG_DEVICE on mismatch<br>- Prevents decryption if mismatch |
| **Verification Method** | Unit test (TC-036 to TC-040), Integration test (device ID source) |
| **Allocation** | libsum (ASIL-C) + Integrating system (ASIL-C) |
| **Derived TSRs** | TSR-006 (Device ID check) |

---

### 4.6 FSR-006: Deterministic Execution (ASIL-C)

| **Requirement ID** | FSR-006 |
| **ASIL** | ASIL-C |
| **Derived from** | SG-005 (Prevent ECU function blocking) |
| **Description** | libsum SHALL execute verification in bounded time with no infinite loops or blocking operations. |
| **Rationale** | Prevents denial-of-service via malicious manifests |
| **Safe State** | ECU functions remain available (update aborted) |
| **FTTI** | Watchdog timeout (integrating system responsibility) |
| **Acceptance Criteria** | - All memory pre-allocated (no malloc during verification)<br>- Constant-time crypto algorithms<br>- nanopb max_size limits enforced<br>- WCET ≤ 30 seconds on target hardware |
| **Verification Method** | WCET analysis, Integration test (timeout), Fuzzing |
| **Allocation** | libsum (ASIL-B) + Integrating system (ASIL-C) |
| **Derived TSRs** | TSR-007 (Deterministic execution) |

---

### 4.7 FSR-007: Memory Safety (ASIL-D)

| **Requirement ID** | FSR-007 |
| **ASIL** | ASIL-D |
| **Derived from** | All safety goals (affects all verification logic) |
| **Description** | libsum SHALL prevent buffer overflows, use-after-free, and memory leaks during verification. |
| **Rationale** | Memory corruption can bypass all security checks |
| **Safe State** | Return error code (do not crash, do not proceed) |
| **FTTI** | Immediate (before firmware installation) |
| **Acceptance Criteria** | - MISRA C++:2008 compliance<br>- 0 ASAN/UBSAN errors<br>- 0 Valgrind memory leaks<br>- Returns OUT_OF_MEMORY on allocation failure |
| **Verification Method** | Static analysis (Clang-Tidy, Cppcheck), Dynamic analysis (ASAN, Valgrind), Fuzzing |
| **Allocation** | libsum (ASIL-D) + Integrating system (ASIL-D) |
| **Derived TSRs** | TSR-008 (Memory safety) |

---

## 5. Software Safety Requirements (SSRs)

### 5.1 Certificate Verification (TSR-001, TSR-002)

| Req ID | ASIL | Requirement | Acceptance Criteria | Test Case |
|--------|------|-------------|---------------------|-----------|
| **SSR-001** | ASIL-D | libsum SHALL parse X.509 certificates using ASN.1 DER encoding per RFC 5280 | - Successfully parse valid DER certificates<br>- Reject invalid ASN.1 structures | TC-001 |
| **SSR-002** | ASIL-D | libsum SHALL verify Root CA self-signature using public key from trusted storage | - Extract Root CA public key<br>- Verify self-signature<br>- Return CERT_INVALID on failure | TC-002 |
| **SSR-003** | ASIL-D | libsum SHALL verify Intermediate CA signature using Root CA public key | - Extract Intermediate CA certificate<br>- Verify signature with Root CA key<br>- Return CERT_INVALID on failure | TC-003 |
| **SSR-004** | ASIL-D | libsum SHALL verify Update Certificate signature using Intermediate CA public key | - Extract Update Certificate<br>- Verify signature with Intermediate CA key<br>- Return CERT_INVALID on failure | TC-004 |
| **SSR-005** | ASIL-D | libsum SHALL extract Ed25519 public key from Update Certificate SubjectPublicKeyInfo | - Extract public key (32 bytes)<br>- Validate key format<br>- Return CERT_INVALID if extraction fails | TC-005 |
| **SSR-006** | ASIL-D | libsum SHALL reject certificates with invalid ASN.1 structure | - Detect malformed DER encoding<br>- Return CERT_INVALID<br>- No crash or hang | TC-006 |
| **SSR-007** | ASIL-D | libsum SHALL compute canonical manifest bytes by serializing protobuf with signature field = empty | - Serialize manifest deterministically<br>- Set signature field to empty bytes<br>- Produce identical output for same manifest | TC-007 |
| **SSR-008** | ASIL-D | libsum SHALL verify Ed25519 signature using Update Certificate public key per RFC 8032 | - Verify signature using Ed25519 algorithm<br>- Return SUCCESS if valid<br>- Return SIGNATURE_INVALID if invalid | TC-008 |
| **SSR-009** | ASIL-D | libsum SHALL use constant-time signature verification | - No data-dependent branches in signature verification<br>- Timing independent of signature validity<br>- Verified with timing analysis | TC-009 |
| **SSR-010** | ASIL-D | libsum SHALL reject manifests with signature length ≠ 64 bytes | - Check signature.size() == 64<br>- Return SIGNATURE_INVALID if size wrong | TC-010 |

### 5.2 Hash Verification (TSR-003)

| Req ID | ASIL | Requirement | Acceptance Criteria | Test Case |
|--------|------|-------------|---------------------|-----------|
| **SSR-011** | ASIL-D | libsum SHALL compute SHA-256 hash of decrypted payload using FIPS 180-4 algorithm | - Use FIPS-validated crypto library<br>- Compute 32-byte hash<br>- Support streaming for large payloads | TC-011 |
| **SSR-012** | ASIL-D | libsum SHALL compare computed hash with manifest's payload_sha256 using constant-time memcmp | - Use timing-safe comparison<br>- Compare all 32 bytes<br>- No early exit on mismatch | TC-012 |
| **SSR-013** | ASIL-D | libsum SHALL reject artifacts with hash mismatch | - Return HASH_MISMATCH if hashes differ<br>- Do not proceed with installation | TC-013 |
| **SSR-014** | ASIL-D | libsum SHALL verify ALL artifacts before returning SUCCESS | - Iterate through all artifacts<br>- Fail-fast on first error<br>- Return SUCCESS only if all pass | TC-014 |
| **SSR-015** | ASIL-D | libsum SHALL compute hash in ≤ 256 KB memory (streaming allowed) | - Use incremental hash API<br>- Memory usage ≤ 256 KB<br>- Measured with Valgrind massif | TC-015 |

### 5.3 Anti-Rollback (TSR-004)

| Req ID | ASIL | Requirement | Acceptance Criteria | Test Case |
|--------|------|-------------|---------------------|-----------|
| **SSR-016** | ASIL-D | libsum SHALL read last_installed_version from integrating system via callback | - Call get_version_callback()<br>- Handle callback errors<br>- Return ROLLBACK_DETECTED on read failure (fail-safe) | TC-016 |
| **SSR-017** | ASIL-D | libsum SHALL compare manifest.security_version > last_installed_version (strict inequality) | - Use `>` (not `>=`)<br>- Reject if equal or less<br>- Return ROLLBACK_DETECTED on violation | TC-017 |
| **SSR-018** | ASIL-D | libsum SHALL reject manifests with security_version ≤ last_installed_version | - Detect version downgrade<br>- Return ROLLBACK_DETECTED<br>- Log security event | TC-018 |
| **SSR-019** | ASIL-D | libsum SHALL compare manifest.timestamp > last_installed_timestamp (strict inequality) | - Use `>` (not `>=`)<br>- Reject if equal or less<br>- Return REPLAY_DETECTED on violation | TC-019 |
| **SSR-020** | ASIL-D | libsum SHALL reject manifests with timestamp ≤ last_installed_timestamp | - Detect timestamp replay<br>- Return REPLAY_DETECTED<br>- Log security event | TC-020 |

### 5.4 Revocation Check (TSR-005)

| Req ID | ASIL | Requirement | Acceptance Criteria | Test Case |
|--------|------|-------------|---------------------|-----------|
| **SSR-021** | ASIL-C | libsum SHALL check if integrating system provided reject_timestamp (optional parameter) | - Check if reject_timestamp > 0<br>- Skip check if not provided | TC-021 |
| **SSR-022** | ASIL-C | libsum SHALL extract Intermediate CA's notBefore field from X.509 certificate | - Parse X.509 Validity field<br>- Extract notBefore (GeneralizedTime or UTCTime)<br>- Return CERT_INVALID if parse fails | TC-022 |
| **SSR-023** | ASIL-C | libsum SHALL compare notBefore > reject_timestamp | - Convert notBefore to Unix timestamp<br>- Use `>` (not `>=`)<br>- Return CERT_REVOKED if notBefore ≤ reject_timestamp | TC-023 |
| **SSR-024** | ASIL-C | libsum SHALL reject manifests signed by revoked CA | - Return CERT_REVOKED<br>- Do not proceed with decryption | TC-024 |

### 5.5 Device Identity (TSR-006)

| Req ID | ASIL | Requirement | Acceptance Criteria | Test Case |
|--------|------|-------------|---------------------|-----------|
| **SSR-025** | ASIL-C | libsum SHALL read device ID from integrating system via callback | - Call get_device_id_callback()<br>- Handle callback errors<br>- Return WRONG_DEVICE on read failure (fail-safe) | TC-025 |
| **SSR-026** | ASIL-C | libsum SHALL compare manifest.device_id == device_id using constant-time string comparison | - Use timing-safe memcmp<br>- Compare entire strings<br>- Case-sensitive | TC-026 |
| **SSR-027** | ASIL-C | libsum SHALL reject manifests with mismatched device ID | - Return WRONG_DEVICE on mismatch<br>- Do not proceed with key unwrapping | TC-027 |
| **SSR-028** | ASIL-C | Device ID comparison SHALL be case-sensitive | - "VIN123" ≠ "vin123"<br>- Exact string match required | TC-028 |

### 5.6 Deterministic Execution (TSR-007)

| Req ID | ASIL | Requirement | Acceptance Criteria | Test Case |
|--------|------|-------------|---------------------|-----------|
| **SSR-029** | ASIL-B | libsum SHALL pre-allocate all memory at initialization (no malloc during verification) | - All buffers allocated in init()<br>- No heap allocation in verify()<br>- Measured with ASAN malloc hook | TC-029 |
| **SSR-030** | ASIL-B | libsum SHALL use constant-time crypto algorithms | - Ed25519 signature verification constant-time<br>- memcmp constant-time<br>- No data-dependent branches | TC-030 |
| **SSR-031** | ASIL-B | libsum SHALL enforce nanopb max_size limits for all protobuf fields | - manifest.pb.options defines max_size<br>- nanopb rejects oversized fields<br>- No buffer overflows | TC-031 |
| **SSR-032** | ASIL-B | libsum SHALL limit certificate chain depth to 3 levels | - Root → Intermediate → Update only<br>- Reject chains with > 3 levels<br>- Prevents infinite loops | TC-032 |

### 5.7 Memory Safety (TSR-008)

| Req ID | ASIL | Requirement | Acceptance Criteria | Test Case |
|--------|------|-------------|---------------------|-----------|
| **SSR-033** | ASIL-D | libsum SHALL use C++ RAII for automatic memory management | - Use std::vector, std::string<br>- No manual delete/free<br>- Destructors clean up resources | TC-033 |
| **SSR-034** | ASIL-D | libsum SHALL use bounds-checked containers (std::vector, std::string) | - No raw pointer arithmetic<br>- Use at() for checked access<br>- No strcpy/strcat | TC-034 |
| **SSR-035** | ASIL-D | libsum SHALL NOT use unsafe C functions (strcpy, sprintf) | - Use strncpy, snprintf alternatives<br>- Clang-Tidy enforces cert-err33-c<br>- Code review confirms | TC-035 |
| **SSR-036** | ASIL-D | libsum SHALL initialize all variables before use | - No uninitialized reads<br>- UBSAN detects violations<br>- Clang-Tidy cppcoreguidelines-init-variables | TC-036 |
| **SSR-037** | ASIL-D | libsum SHALL check malloc return values and return OUT_OF_MEMORY if allocation fails | - `if (!ptr) return OUT_OF_MEMORY;`<br>- Every allocation checked<br>- Fault injection test (malloc fail) | TC-037 |
| **SSR-038** | ASIL-D | libsum SHALL NOT leak memory | - All allocated memory freed<br>- Valgrind reports 0 leaks<br>- RAII ensures cleanup | TC-038 |
| **SSR-039** | ASIL-D | libsum SHALL comply with MISRA C++:2008 required rules | - Clang-Tidy enforces MISRA subset<br>- Manual code review<br>- 0 violations in safety-critical code | TC-039 |
| **SSR-040** | ASIL-D | libsum SHALL pass Clang-Tidy checks (cert-*, bugprone-*) | - 0 errors, 0 warnings<br>- CI/CD enforcement | TC-040 |
| **SSR-041** | ASIL-D | libsum SHALL pass Cppcheck static analysis | - 0 errors, 0 warnings<br>- CI/CD enforcement | TC-041 |
| **SSR-042** | ASIL-D | libsum SHALL compile with all warnings as errors (-Werror) | - -Wall -Wextra -Werror -Wconversion<br>- 0 compiler warnings | TC-042 |

### 5.8 Error Handling (All TSRs)

| Req ID | ASIL | Requirement | Acceptance Criteria | Test Case |
|--------|------|-------------|---------------------|-----------|
| **SSR-043** | ASIL-D | libsum SHALL return 0 (SUCCESS) if and only if all checks pass | - Single success path<br>- All error paths return negative code | TC-043 |
| **SSR-044** | ASIL-D | libsum SHALL return distinct error codes for each failure mode | - 10 unique error codes (-1 to -10)<br>- Error code maps to failure mode | TC-044 |
| **SSR-045** | ASIL-D | libsum SHALL NOT silently fail (every fault returns error code) | - No success return on error<br>- Code review confirms<br>- Fault injection tests all error paths | TC-045 |
| **SSR-046** | ASIL-D | libsum SHALL log errors via integrating system callback (optional) | - Call log_error_callback(code, msg)<br>- Logging optional (can be NULL)<br>- Does not affect verification logic | TC-046 |

### 5.9 Decryption (TSR-002, TSR-003)

| Req ID | ASIL | Requirement | Acceptance Criteria | Test Case |
|--------|------|-------------|---------------------|-----------|
| **SSR-047** | ASIL-D | libsum SHALL decrypt payload using X25519 + AES-128-GCM | - X25519 ECDH for key agreement<br>- AES-128-GCM for authenticated encryption<br>- Return DECRYPT_FAILED on failure | TC-047 |
| **SSR-048** | ASIL-D | libsum SHALL verify AES-GCM authentication tag | - GCM tag verification before decryption<br>- Return DECRYPT_FAILED if tag invalid<br>- No partial decryption | TC-048 |
| **SSR-049** | ASIL-D | libsum SHALL unwrap device-specific AES key using device private key | - Read device X25519 private key<br>- Perform ECDH with ephemeral public key<br>- Derive AES key from shared secret | TC-049 |
| **SSR-050** | ASIL-D | libsum SHALL verify device ID before key unwrapping | - Check device_id first<br>- Return WRONG_DEVICE before decryption attempt<br>- Prevents decryption oracle attacks | TC-050 |

---

## 6. Hardware Safety Requirements (HSRs) - Integrating System

### 6.1 Storage and Memory

| Req ID | ASIL | Requirement | Acceptance Criteria | Verification |
|--------|------|-------------|---------------------|--------------|
| **HSR-001** | ASIL-D | Integrating system SHALL provide integrity-protected storage for Root CA certificate | - Flash with CRC or signed by bootloader<br>- Immutable after manufacturing | Hardware review |
| **HSR-002** | ASIL-D | Integrating system SHALL store last_installed_version in NVM with ECC protection | - EEPROM with error correction<br>- Or flash with redundant copies + CRC | Hardware review |
| **HSR-003** | ASIL-D | Integrating system SHALL use redundant storage for version counter | - 2 copies with CRC<br>- Majority voting on read<br>- Detect corruption | Integration test |
| **HSR-004** | ASIL-D | Integrating system SHALL atomically update version counter after flash write | - Version update fails → reject next update (safe)<br>- Flash write fails → version not updated (safe) | Integration test |
| **HSR-005** | ASIL-D | Integrating system SHALL use wear-leveling for NVM | - Prevent NVM exhaustion<br>- EEPROM > 100k write cycles<br>- Flash > 10k write cycles | Datasheet review |
| **HSR-006** | ASIL-D | Integrating system SHALL provide ≥ 128 KB RAM for libsum | - Measured peak usage<br>- Includes manifest + crypto buffers | Performance test |
| **HSR-007** | ASIL-D | Integrating system SHALL provide ≥ 256 KB Flash for libsum library | - Code size measurement<br>- Includes crypto libraries | Build artifact |

### 6.2 Cryptographic Hardware

| Req ID | ASIL | Requirement | Acceptance Criteria | Verification |
|--------|------|-------------|---------------------|--------------|
| **HSR-008** | ASIL-C | Integrating system SHALL provide immutable device ID | - VIN, ECU serial, or hardware UID<br>- Stored in OTP fuses or signed by Root CA | Hardware review |
| **HSR-009** | N/A | Integrating system MAY provide HSM for device private key storage | - Optional (enhances security)<br>- Not required for ASIL-D | N/A |
| **HSR-010** | N/A | Integrating system MAY provide hardware crypto accelerator | - Optional (improves performance)<br>- Reduces WCET | Performance test |

### 6.3 Time Source

| Req ID | ASIL | Requirement | Acceptance Criteria | Verification |
|--------|------|-------------|---------------------|--------------|
| **HSR-011** | ASIL-C | Integrating system SHALL provide trusted time source | - Battery-backed RTC<br>- Or Roughtime/NTP with authentication<br>- Accuracy ≤ 1 hour | Time source test |
| **HSR-012** | ASIL-C | RTC SHALL maintain time during power loss | - Battery backup ≥ 5 years<br>- Or capacitor backup ≥ 1 week | Hardware review |

### 6.4 Watchdog and Fault Detection

| Req ID | ASIL | Requirement | Acceptance Criteria | Verification |
|--------|------|-------------|---------------------|--------------|
| **HSR-013** | ASIL-C | Integrating system SHALL implement hardware watchdog timer | - AUTOSAR Watchdog Manager<br>- Independent of CPU<br>- Cannot be disabled by software | Hardware review |
| **HSR-014** | ASIL-C | Watchdog timeout SHALL be 2× WCET of libsum | - WCET measured on target hardware<br>- Timeout = 2 × WCET (margin) | Performance test |
| **HSR-015** | ASIL-C | Integrating system SHALL abort verification on watchdog timeout | - Enter safe state<br>- Do not write flash<br>- Log timeout event | Integration test |

### 6.5 Flash Write Protection

| Req ID | ASIL | Requirement | Acceptance Criteria | Verification |
|--------|------|-------------|---------------------|--------------|
| **HSR-016** | ASIL-D | Integrating system SHALL ONLY write flash if libsum returns SUCCESS | - No flash write on any error code<br>- Verified by integration test | Integration test |
| **HSR-017** | ASIL-D | Integrating system SHALL verify flash write success (CRC check) | - Read-back verification<br>- CRC comparison<br>- Fail → abort update | Integration test |
| **HSR-018** | ASIL-D | Integrating system SHALL update version counter AFTER flash write | - Flash write first<br>- Version update second<br>- Atomic transaction | Integration test |
| **HSR-019** | N/A | Integrating system MAY use dual-bank flash for A/B updates | - Optional (improves availability)<br>- Not required for safety | N/A |
| **HSR-020** | N/A | Integrating system MAY use MPU for memory protection | - Optional (enhances security)<br>- Isolates libsum memory | N/A |

---

## 7. Verification Methods

### 7.1 Verification Techniques per ISO 26262-6 Table 10

| Verification Method | ASIL-D Requirement | Applied To | Evidence |
|---------------------|-------------------|------------|----------|
| **Requirements-based testing** | ++ (Highly recommended) | All SSRs | TC-001 to TC-050+ |
| **Interface testing** | ++ (Highly recommended) | API functions | Integration tests |
| **Fault injection testing** | ++ (Highly recommended) | All error paths | TC-037, TC-045 |
| **Resource usage testing** | ++ (Highly recommended) | Memory, CPU | TC-015, TC-029 |
| **Back-to-back comparison testing** | + (Recommended) | Not applicable (no reference model) | N/A |
| **Static code analysis** | ++ (Highly recommended) | All code | Clang-Tidy, Cppcheck |
| **Dynamic analysis** | + (Recommended) | All code | ASAN, UBSAN, Valgrind |
| **Control flow analysis** | + (Recommended) | Safety-critical functions | Manual review |
| **Data flow analysis** | + (Recommended) | Safety-critical functions | Manual review |

### 7.2 Code Coverage per ISO 26262-6 Table 13

| Coverage Metric | ASIL-D Requirement | Target | Measurement Tool |
|-----------------|-------------------|--------|------------------|
| **Statement coverage** | ++ (Highly recommended) | 100% | lcov/gcov |
| **Branch coverage** | ++ (Highly recommended) | 100% | lcov/gcov |
| **MC/DC coverage** | + (Recommended) | 100% (safety-critical functions) | Manual analysis |

**Current Status:** 61/61 tests pass, coverage measurement in progress (target: ≥ 95% statement, ≥ 95% branch).

---

## 8. Traceability Matrix

### 8.1 Safety Goal → FSR → SSR Traceability

| Safety Goal | ASIL | FSRs | SSRs | Test Cases |
|-------------|------|------|------|------------|
| **SG-001** (Unverified FW) | ASIL-D | FSR-001, FSR-007 | SSR-001 to SSR-010, SSR-033 to SSR-046 | TC-001 to TC-010, TC-033 to TC-046 |
| **SG-002** (Corrupted FW) | ASIL-D | FSR-002, FSR-007 | SSR-011 to SSR-015, SSR-033 to SSR-046 | TC-011 to TC-015, TC-033 to TC-046 |
| **SG-003** (Rollback) | ASIL-D | FSR-003, FSR-007 | SSR-016 to SSR-020, SSR-033 to SSR-046 | TC-016 to TC-020, TC-033 to TC-046 |
| **SG-004** (Revoked CA) | ASIL-C | FSR-004 | SSR-021 to SSR-024 | TC-021 to TC-024 |
| **SG-005** (Blocking) | ASIL-C | FSR-006 | SSR-029 to SSR-032 | TC-029 to TC-032 |
| **SG-006** (Wrong device) | ASIL-C | FSR-005 | SSR-025 to SSR-028 | TC-025 to TC-028 |

### 8.2 SSR → Implementation → Test Case Traceability

| SSR Range | Implementation Files | Test Files | Coverage |
|-----------|---------------------|------------|----------|
| SSR-001 to SSR-010 | `src/crypto/verify.cpp`, `src/crypto/cert.cpp` | `tests/test_verify_signature.cpp` | ≥ 95% |
| SSR-011 to SSR-015 | `src/crypto/hash.cpp` | `tests/test_hash_verification.cpp` | ≥ 95% |
| SSR-016 to SSR-020 | `src/manifest.cpp:487-531` | `tests/test_rollback.cpp` | ≥ 95% |
| SSR-021 to SSR-024 | `src/crypto/cert.cpp:298` | `tests/test_revocation.cpp` | ≥ 95% |
| SSR-025 to SSR-028 | `src/manifest.cpp:531` | `tests/test_device_id.cpp` | ≥ 95% |
| SSR-029 to SSR-032 | All files | `tests/integration/test_timeout.cpp` | ≥ 95% |
| SSR-033 to SSR-046 | All files | All tests (ASAN/Valgrind) | 100% |
| SSR-047 to SSR-050 | `src/crypto/decrypt.cpp` | `tests/test_decryption.cpp` | ≥ 95% |

---

## 9. Compliance Matrix

### 9.1 ISO 26262 Requirements

| ISO 26262 Clause | Requirement | Compliance Status | Evidence |
|------------------|-------------|-------------------|----------|
| **4-7.4.1** | Define FSRs from safety goals | ✅ Complete | Section 4 (FSR-001 to FSR-007) |
| **4-7.4.2** | Define safe states | ✅ Complete | Each FSR specifies safe state |
| **4-7.4.3** | Define FTTI | ✅ Complete | Each FSR specifies FTTI |
| **4-7.4.4** | Allocate FSRs to system elements | ✅ Complete | libsum vs. integrating system allocation |
| **5-6.4.1** | Derive TSRs from FSRs | ✅ Complete | Section 5 (SSR-001 to SSR-050) |
| **5-6.4.2** | Define hardware requirements | ✅ Complete | Section 6 (HSR-001 to HSR-020) |
| **5-6.4.3** | Define software requirements | ✅ Complete | Section 5 (SSR-001 to SSR-050) |
| **6-9.4.1** | Define verification strategy | ✅ Complete | Section 7 |
| **6-9.4.2** | Achieve code coverage targets | ⚠️ In progress | 61/61 tests pass, coverage measurement ongoing |
| **6-9.4.3** | Perform static analysis | ✅ Complete | Clang-Tidy, Cppcheck in CI/CD |

### 9.2 Coding Standards Compliance

| Standard | Compliance | Verification Method |
|----------|-----------|---------------------|
| **MISRA C++:2008** | Required rules enforced | Clang-Tidy + manual review |
| **AUTOSAR C++14** | Safety-critical subset | Clang-Tidy config |
| **CERT C++ Secure Coding** | All applicable rules | Clang-Tidy cert-* checks |

---

## 10. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-27 | libsum contributors | Initial Safety Requirements Specification |

**Next Document:** Verification and Validation Report (Document 06)

**Approval Required:**
- [ ] Functional Safety Manager
- [ ] Software Architect
- [ ] Test Manager
- [ ] Independent Safety Assessor

---

**End of Safety Requirements Specification**
