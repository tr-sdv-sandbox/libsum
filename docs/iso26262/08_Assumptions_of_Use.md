# ISO 26262 Assumptions of Use
## libsum - Secure Update Verification Library (SEooC)

**Document ID:** LIBSUM-ISO26262-AOU-008
**Version:** 1.0
**Date:** 2025-11-27
**Status:** Draft for Review
**ASIL Target:** ASIL-D (SEooC)

---

## 1. Purpose

This document specifies the **Assumptions of Use** for libsum as a Safety Element out of Context (SEooC) per ISO 26262-8:2018 Clause 5. It defines all constraints, prerequisites, and integration requirements that the **integrating system** (e.g., AUTOSAR Update Manager) **MUST** satisfy for the safety argument to remain valid.

---

## 2. Scope

This document is **mandatory reading** for:
- **Integrating System Developers** (AUTOSAR Update Manager team)
- **OEM Safety Engineers** (validating integration)
- **Hardware Architects** (ECU design)
- **Independent Safety Assessors** (verifying integration)

**WARNING:** Violation of any assumption in this document **INVALIDATES** the ASIL-D safety case for libsum. The integrating system MUST comply with ALL requirements specified herein.

---

## 3. Document Structure

This document is organized into:
- **Section 4:** Operational Constraints (how libsum MUST be used)
- **Section 5:** Hardware Requirements (minimum ECU capabilities)
- **Section 6:** Software Integration Requirements (API usage, error handling)
- **Section 7:** Safety-Critical Integration Points (atomic operations, safe states)
- **Section 8:** Security Assumptions (cryptographic infrastructure)
- **Section 9:** Validation Checklist (for integrating system)

---

## 4. Operational Constraints

### 4.1 OC-001: Vehicle Stationary During Safety-Critical ECU Updates

**Assumption:**
Updates to safety-critical ECUs (e.g., brake ECU, steering ECU, powertrain ECU) **MUST** only be performed when the vehicle is stationary (parking brake engaged, ignition off or "parked" mode).

**Rationale:**
- HARA Exposure ratings (E1, E2) assume low probability of update during vehicle operation
- If updates occur while driving, Exposure increases (E3 → E4), potentially raising ASIL levels

**Integrating System Requirement:**
- **AUTOSAR Update Manager MUST:** Check vehicle state before starting update
  - Verify parking brake engaged
  - Verify ignition in "parked" or "off" state
  - Verify vehicle speed = 0 for ≥ 10 seconds
- **AUTOSAR Update Manager MUST:** Abort update if vehicle state changes (driver starts engine, releases parking brake)

**Verification:**
- Integration test: Attempt update while vehicle moving (expected: rejected)
- Integration test: Abort update if vehicle state changes (expected: safe abort)

**Violation Impact:** ASIL ratings may increase (potentially more hazards rated ASIL-D)

---

### 4.2 OC-002: No Concurrent Updates to Same ECU

**Assumption:**
Only ONE update to a given ECU **MUST** be in progress at any time. Concurrent updates to the same ECU are **NOT** supported.

**Rationale:**
- libsum is single-threaded and not re-entrant
- Concurrent updates could lead to race conditions in version counter updates

**Integrating System Requirement:**
- **AUTOSAR Update Manager MUST:** Implement mutex/lock per ECU
- **AUTOSAR Update Manager MUST:** Reject new update request if update already in progress for same ECU

**Verification:**
- Integration test: Attempt concurrent updates to same ECU (expected: second request rejected)

**Violation Impact:** Undefined behavior (race conditions, version counter corruption)

---

### 4.3 OC-003: Updates Performed in Maintenance/Service Mode

**Assumption:**
OTA updates to safety-critical ECUs **SHOULD** be performed in a dedicated maintenance or service mode (dealer/workshop scenario preferred for ASIL-D ECUs).

**Rationale:**
- Reduces exposure (E-rating) for safety-critical ECUs
- Allows for controlled environment (power supply, diagnostics)

**Integrating System Requirement (Recommended, not required):**
- **OEM SHOULD:** Design update policy to prefer dealer/workshop for ASIL-D ECUs
- **OEM MAY:** Allow OTA for ASIL-D ECUs if vehicle stationary constraint strictly enforced

**Verification:**
- OEM policy review: Update policy documented and approved by safety team

**Violation Impact:** None (recommendation only, but improves safety margin)

---

## 5. Hardware Requirements

### 5.1 HR-001: Minimum CPU and Memory

**Requirement:**
The target ECU **MUST** provide:
- **CPU:** ARM Cortex-M4 or equivalent (≥ 50 MHz) for libsum-tiny, or x86/ARM Cortex-A for full libsum
- **RAM:** ≥ 128 KB (256 KB recommended) for libsum operation
- **Flash:** ≥ 256 KB for libsum library code

**Rationale:**
- Cryptographic operations (Ed25519, SHA-256, AES-GCM) require sufficient CPU performance
- Manifest parsing + crypto buffers require RAM
- Worst-case execution time (WCET) depends on CPU speed

**Integrating System Requirement:**
- **OEM MUST:** Verify target ECU meets minimum requirements
- **OEM MUST:** Measure WCET on actual target hardware (not estimates)

**Verification:**
- Hardware datasheet review
- WCET measurement on target ECU

**Violation Impact:** WCET may exceed timeout, update may fail or block ECU functions (SG-005 violated)

---

### 5.2 HR-002: Non-Volatile Memory (NVM) with ECC Protection

**Requirement:**
The target ECU **MUST** provide non-volatile memory (NVM) for storing version counters with:
- **Type:** EEPROM or Flash with wear-leveling
- **Size:** ≥ 256 bytes (for version counter + metadata)
- **Protection:** Error Correction Code (ECC) or redundant storage with CRC
- **Endurance:** ≥ 100,000 write cycles (EEPROM) or ≥ 10,000 write cycles (Flash with wear-leveling)

**Rationale:**
- Anti-rollback protection (SG-003) depends on persistent version counter
- NVM corruption could allow rollback attacks or reject valid updates

**Integrating System Requirement:**
- **AUTOSAR Update Manager MUST:** Use redundant NVM storage (2 copies with CRC or ECC)
- **AUTOSAR Update Manager MUST:** Implement wear-leveling if using Flash
- **AUTOSAR Update Manager MUST:** Detect NVM corruption and treat as rollback attack (fail-safe: reject update)

**Verification:**
- Hardware datasheet review (ECC, endurance)
- NVM corruption test: Inject bit flips, verify detection

**Violation Impact:** Rollback attacks may succeed (SG-003 violated) or valid updates rejected

---

### 5.3 HR-003: Real-Time Clock (RTC) with Battery Backup

**Requirement:**
The target ECU **MUST** provide a trusted time source with:
- **Type:** Battery-backed Real-Time Clock (RTC) or authenticated network time (Roughtime/NTP)
- **Accuracy:** ≤ 1 hour drift
- **Persistence:** RTC maintains time during power loss (battery backup ≥ 5 years or capacitor backup ≥ 1 week)

**Rationale:**
- Certificate revocation check (SG-004) depends on comparing timestamps
- Inaccurate time could reject valid certificates or accept revoked CAs

**Integrating System Requirement:**
- **OEM MUST:** Provide battery-backed RTC OR authenticated network time (Roughtime with signature verification)
- **AUTOSAR Update Manager MUST:** Verify time source is available before update
- **AUTOSAR Update Manager MUST:** Reject update if time source unavailable (fail-safe)

**Verification:**
- Hardware design review (RTC battery backup)
- Time source unavailability test (expected: update rejected)

**Violation Impact:** Revoked CAs may be accepted (SG-004 violated) or valid updates rejected

---

### 5.4 HR-004: Immutable Device Identifier Storage

**Requirement:**
The target ECU **MUST** provide an immutable device identifier (device ID) with:
- **Type:** VIN (Vehicle Identification Number), ECU serial number, or hardware UID
- **Storage:** One-Time Programmable (OTP) fuses, signed by Root CA, or hardware UID register
- **Properties:** Read-only after manufacturing, cannot be changed in field

**Rationale:**
- Cross-device protection (SG-006) depends on device ID authenticity
- If device ID can be spoofed, firmware intended for different ECU may be accepted

**Integrating System Requirement:**
- **OEM MUST:** Provision device ID during manufacturing in OTP fuses or sign with Root CA
- **AUTOSAR Update Manager MUST:** Read device ID from secure storage (not from user-modifiable file)
- **AUTOSAR Update Manager MUST:** Verify device ID integrity (CRC or signature) before providing to libsum

**Verification:**
- Hardware design review (OTP fuses or signed storage)
- Device ID tampering test (expected: libsum rejects update with WRONG_DEVICE)

**Violation Impact:** Wrong firmware may be installed (SG-006 violated)

---

### 5.5 HR-005: Integrity-Protected Root CA Certificate Storage

**Requirement:**
The target ECU **MUST** provide integrity-protected storage for the Root CA certificate with:
- **Type:** Flash with CRC, signed by bootloader, or stored in OTP fuses
- **Properties:** Immutable after manufacturing, cannot be modified without bootloader approval

**Rationale:**
- All security guarantees depend on Root CA authenticity
- If Root CA can be replaced, attacker can sign malicious firmware

**Integrating System Requirement:**
- **OEM MUST:** Provision Root CA certificate during manufacturing
- **Bootloader MUST:** Verify Root CA integrity (signature or CRC) before boot
- **AUTOSAR Update Manager MUST:** Read Root CA from integrity-protected storage

**Verification:**
- Bootloader design review (Root CA verification)
- Root CA tampering test (expected: bootloader rejects tampered Root CA)

**Violation Impact:** All security guarantees invalid (attacker can sign malicious firmware)

---

### 5.6 HR-006: Hardware Watchdog Timer

**Requirement:**
The target ECU **MUST** provide a hardware watchdog timer with:
- **Type:** Independent watchdog (not dependent on CPU)
- **Configuration:** Timeout = 2 × WCET (Worst-Case Execution Time) of libsum verification
- **Properties:** Cannot be disabled by software, triggers ECU reset on timeout

**Rationale:**
- Deterministic execution (SG-005) depends on timeout protection
- libsum cannot self-enforce timeout (external watchdog required)

**Integrating System Requirement:**
- **AUTOSAR Watchdog Manager MUST:** Configure watchdog timeout = 2 × WCET
- **AUTOSAR Update Manager MUST:** Trigger watchdog periodically during verification
- **AUTOSAR Update Manager MUST:** Abort verification and enter safe state if timeout occurs

**Verification:**
- WCET measurement on target hardware
- Timeout test: Inject malicious manifest causing long verification (expected: watchdog triggers, safe state)

**Violation Impact:** ECU functions may be blocked indefinitely (SG-005 violated)

---

### 5.7 HR-007: Flash Write Protection (Optional but Recommended)

**Requirement (Recommended):**
The target ECU **SHOULD** provide hardware flash write protection with:
- **Type:** Memory Protection Unit (MPU) or flash write-enable pin
- **Properties:** Flash write only enabled during update, disabled during normal operation

**Rationale:**
- Prevents accidental or malicious flash writes outside update process
- Improves defense-in-depth

**Integrating System Requirement (Recommended):**
- **AUTOSAR Update Manager SHOULD:** Enable flash write only during update, disable after completion
- **MPU SHOULD:** Isolate libsum memory from other applications (if ARM TrustZone or MPU available)

**Verification:**
- Hardware design review (MPU configuration)

**Violation Impact:** None (recommendation only, but improves security)

---

## 6. Software Integration Requirements

### 6.1 SI-001: API Usage (MANDATORY)

**Requirement:**
The integrating system **MUST** use the libsum API exactly as specified:

```c
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
```

**MANDATORY Requirements:**
1. **MUST** provide valid Root CA certificate (integrity-protected, DER format)
2. **MUST** provide device ID from secure storage (not user input)
3. **MUST** provide `last_installed_version` and `last_installed_timestamp` from NVM
4. **MAY** provide `reject_timestamp` (optional, set to 0 to disable revocation check)
5. **MUST** check return value (0 = SUCCESS, negative = error)
6. **MUST NOT** proceed with flash write if return value ≠ 0 (SUCCESS)

**Forbidden Actions:**
- **MUST NOT** ignore error codes
- **MUST NOT** proceed with update on any error (including OUT_OF_MEMORY)
- **MUST NOT** modify manifest after libsum verification (TOCTOU vulnerability)

**Verification:**
- Code review: Verify API usage complies with requirements
- Integration test: Verify error codes are handled correctly

**Violation Impact:** All safety guarantees invalid (attacker may exploit incorrect error handling)

---

### 6.2 SI-002: Error Handling (MANDATORY)

**Requirement:**
The integrating system **MUST** handle all libsum error codes correctly:

| Error Code | Name | Integrating System Action |
|------------|------|---------------------------|
| **0** | SUCCESS | Proceed with flash write |
| **-1** | CERT_INVALID | Reject update, log security event, do NOT write flash |
| **-2** | SIGNATURE_INVALID | Reject update, log security event, do NOT write flash |
| **-3** | HASH_MISMATCH | Reject update, log corruption event, do NOT write flash |
| **-4** | ROLLBACK_DETECTED | Reject update, log security event, do NOT write flash |
| **-5** | REPLAY_DETECTED | Reject update, log security event, do NOT write flash |
| **-6** | CERT_EXPIRED | Reject update, check time source, do NOT write flash |
| **-7** | CERT_REVOKED | Reject update, log security event, do NOT write flash |
| **-8** | WRONG_DEVICE | Reject update, log mismatch event, do NOT write flash |
| **-9** | DECRYPT_FAILED | Reject update, log crypto error, do NOT write flash |
| **-10** | OUT_OF_MEMORY | **Enter safe state**, do NOT write flash, may require ECU reset |

**CRITICAL:** Error code -10 (OUT_OF_MEMORY) indicates memory corruption or resource exhaustion. Integrating system **MUST** enter safe state and may need to reset ECU.

**Verification:**
- Integration test: Inject each error condition, verify correct handling
- Code review: Verify no error code is ignored

**Violation Impact:** Malicious or corrupted firmware may be installed (all safety goals violated)

---

### 6.3 SI-003: Version Counter Update (MANDATORY, ASIL-D)

**Requirement:**
The integrating system **MUST** update the version counter **AFTER** successful flash write, using atomic operation:

**Correct Sequence:**
1. libsum returns SUCCESS (0)
2. Write decrypted firmware to flash
3. **Verify flash write success** (CRC check or read-back verification)
4. **IF flash write verified:** Update NVM version counter (atomic write)
5. **IF flash write failed:** Do NOT update version counter, log error, enter safe state

**Atomic Operation:**
- Version counter update MUST be atomic (both NVM copies updated together, or transaction committed)
- If power loss occurs during version update, system MUST detect corruption on next boot and reject updates until version restored

**Forbidden Actions:**
- **MUST NOT** update version counter before flash write (allows rollback if flash write fails)
- **MUST NOT** update version counter if flash write fails (allows attacker to exhaust version counter)
- **MUST NOT** update only one NVM copy (allows version corruption)

**Verification:**
- Integration test: Inject power loss during version update, verify corruption detection
- Integration test: Flash write fails → version counter not updated

**Violation Impact:** Rollback attacks may succeed (SG-003 violated) or valid updates rejected

---

### 6.4 SI-004: Safe State Management (MANDATORY, ASIL-D)

**Requirement:**
The integrating system **MUST** define and enter safe states for all error conditions:

**Safe States:**

| Condition | Safe State | Action |
|-----------|------------|--------|
| **Verification error (codes -1 to -9)** | Current firmware continues | Reject update, log event, continue operation |
| **Out of memory (code -10)** | ECU functions available | Abort verification, free resources, may reset ECU |
| **Watchdog timeout** | ECU functions available | Abort verification, enter safe state, may reset ECU |
| **Flash write failure** | Current firmware continues | Abort update, log error, do NOT update version |

**Critical Requirement:** Safe state MUST ensure safety-critical ECU functions remain available (e.g., brake ECU can still brake, steering ECU can still steer).

**Verification:**
- Integration test: Inject each fault condition, verify safe state reached
- FMEA (Failure Modes and Effects Analysis): Verify all fault modes lead to safe states

**Violation Impact:** ECU may become unavailable during vehicle operation (SG-005 violated)

---

### 6.5 SI-005: No TOCTOU Vulnerabilities (MANDATORY, ASIL-D)

**Requirement:**
The integrating system **MUST NOT** modify the manifest or payload after libsum verification (Time-Of-Check to Time-Of-Use vulnerability).

**Correct Sequence:**
1. Read manifest and payload into memory
2. Call libsum to verify manifest
3. **IF SUCCESS:** Use the SAME manifest/payload buffers for flash write (do NOT re-read from storage)
4. **IF ERROR:** Discard manifest/payload buffers

**Forbidden Actions:**
- **MUST NOT** re-read manifest from file after verification (attacker may have modified file)
- **MUST NOT** pass file paths to libsum (use in-memory buffers only)

**Verification:**
- Code review: Verify buffers are not re-read after verification
- Security audit: Check for TOCTOU vulnerabilities

**Violation Impact:** Attacker may swap manifest/payload between verification and installation (all safety goals violated)

---

## 7. Safety-Critical Integration Points

### 7.1 SCI-001: Flash Write Control (ASIL-D)

**Requirement:**
**ONLY** write firmware to flash if libsum returns SUCCESS (0). **NO EXCEPTIONS.**

**Implementation:**
```c
int result = sum_verify_manifest(...);
if (result == 0) {  // SUCCESS
    // ONLY now is it safe to write flash
    write_flash(decrypted_firmware, size);
    verify_flash_write();  // CRC check
    update_version_counter();  // AFTER flash verified
} else {
    // ANY error: reject update, do NOT write flash
    log_error(result);
    reject_update();
}
```

**Verification:**
- Code review: Verify no flash write on error path
- Integration test: Inject error, verify no flash write

**Violation Impact:** ALL SAFETY GOALS VIOLATED

---

### 7.2 SCI-002: Watchdog Timeout Configuration (ASIL-C)

**Requirement:**
Configure watchdog timeout = **2 × WCET** (Worst-Case Execution Time) of libsum verification.

**Implementation:**
1. Measure WCET on target hardware (worst-case manifest: largest size, most artifacts)
2. Configure watchdog timeout = 2 × WCET (safety margin)
3. Trigger watchdog periodically during verification (e.g., after each artifact)

**Example:**
- WCET measured: 10 seconds (100 MB manifest, ARM Cortex-M4 @ 50 MHz)
- Watchdog timeout: 20 seconds

**Verification:**
- WCET measurement on target ECU
- Timeout test: Inject malicious manifest, verify watchdog triggers at 2 × WCET

**Violation Impact:** ECU functions may be blocked indefinitely (SG-005 violated)

---

### 7.3 SCI-003: Root CA Certificate Provisioning (ASIL-D)

**Requirement:**
Root CA certificate **MUST** be provisioned during manufacturing and protected from modification.

**Implementation:**
1. Generate Root CA key pair (offline, in Hardware Security Module)
2. Provision Root CA certificate to ECU during manufacturing (flash with CRC or OTP fuses)
3. Bootloader verifies Root CA integrity on every boot
4. AUTOSAR Update Manager reads Root CA from integrity-protected storage

**Verification:**
- Manufacturing process review
- Bootloader security audit
- Root CA tampering test (expected: bootloader detects tampering, refuses to boot)

**Violation Impact:** Attacker can sign malicious firmware (ALL SAFETY GOALS VIOLATED)

---

## 8. Security Assumptions

### 8.1 SA-001: Root CA Key is Secure

**Assumption:**
The Root CA private key is stored in an offline Hardware Security Module (HSM) with multi-person control and is **NOT** compromised.

**OEM Requirement:**
- **MUST** store Root CA key in offline HSM (not connected to network)
- **MUST** implement multi-person control (≥ 2 persons required for signing)
- **MUST** log all Root CA signing operations
- **MUST** audit Root CA access logs regularly

**Verification:**
- Security audit of Root CA key management
- HSM vendor documentation (FIPS 140-2 Level 2+ compliance)

**Violation Impact:** If Root CA compromised, ALL SECURITY GUARANTEES INVALID

---

### 8.2 SA-002: Crypto Libraries are FIPS-Validated

**Assumption:**
Cryptographic libraries (OpenSSL, mbedtls) used by libsum are FIPS 140-2 validated and have no known critical vulnerabilities.

**OEM Requirement:**
- **MUST** use FIPS 140-2 validated versions of OpenSSL (3.0 FIPS module) or mbedtls
- **MUST** monitor CVE databases for crypto library vulnerabilities
- **MUST** apply security patches within 90 days of disclosure

**Verification:**
- Crypto library vendor FIPS 140-2 certificate
- CVE monitoring process documentation

**Violation Impact:** Signature/hash verification may be bypassed (SG-001, SG-002 violated)

---

### 8.3 SA-003: Device Private Key is Secure

**Assumption:**
Each device's X25519 private key (for per-device encryption) is generated securely and stored in a way that prevents extraction.

**OEM Requirement:**
- **MUST** generate device private key using hardware random number generator (TRNG)
- **SHOULD** store device private key in HSM or secure element (if available)
- **MUST** prevent key extraction (key not readable by software, or encrypted in NVM)

**Verification:**
- Key generation process review (TRNG usage)
- Key storage security audit

**Violation Impact:** Per-device encryption may be bypassed (attacker can decrypt firmware for other devices)

---

## 9. Validation Checklist for Integrating System

### 9.1 Pre-Integration Checklist

**Hardware Validation:**
- [ ] HR-001: Target ECU meets minimum CPU/RAM requirements (ARM Cortex-M4 @ 50 MHz, 128 KB RAM)
- [ ] HR-002: NVM with ECC protection available (EEPROM or Flash with wear-leveling, ≥ 256 bytes)
- [ ] HR-003: RTC with battery backup available (≥ 5 years) OR authenticated network time (Roughtime)
- [ ] HR-004: Device ID stored in OTP fuses or signed storage (immutable)
- [ ] HR-005: Root CA certificate stored with integrity protection (flash with CRC, signed by bootloader)
- [ ] HR-006: Hardware watchdog timer available (independent, cannot be disabled)

**Software Validation:**
- [ ] SI-001: libsum API used correctly (all parameters provided, no parameter tampering)
- [ ] SI-002: All error codes handled correctly (no error ignored, safe state on OUT_OF_MEMORY)
- [ ] SI-003: Version counter updated AFTER flash write (atomic operation, both NVM copies)
- [ ] SI-004: Safe states defined for all fault conditions (ECU functions remain available)
- [ ] SI-005: No TOCTOU vulnerabilities (manifest/payload not re-read after verification)

**Safety-Critical Integration:**
- [ ] SCI-001: Flash write ONLY if libsum returns SUCCESS (verified by code review)
- [ ] SCI-002: Watchdog timeout = 2 × WCET (measured on target hardware)
- [ ] SCI-003: Root CA provisioned during manufacturing (verified by manufacturing process review)

**Security Assumptions:**
- [ ] SA-001: Root CA key in offline HSM with multi-person control
- [ ] SA-002: Crypto libraries are FIPS 140-2 validated
- [ ] SA-003: Device private keys generated securely (TRNG) and stored securely (HSM or encrypted NVM)

**Operational Constraints:**
- [ ] OC-001: Updates to safety-critical ECUs only when vehicle stationary (policy enforced)
- [ ] OC-002: No concurrent updates to same ECU (mutex/lock implemented)

### 9.2 Post-Integration Validation

**Integration Testing:**
- [ ] All 10 error codes tested (each error condition injected, correct handling verified)
- [ ] WCET measured on target hardware (watchdog timeout configured)
- [ ] NVM corruption test (bit flips injected, detection verified)
- [ ] Root CA tampering test (bootloader detects tampering)
- [ ] Device ID tampering test (libsum rejects update with WRONG_DEVICE)
- [ ] Flash write failure test (version counter not updated)
- [ ] Watchdog timeout test (malicious manifest triggers timeout, safe state reached)
- [ ] TOCTOU test (manifest modification between verification and installation detected)

**Safety Validation:**
- [ ] Independent Safety Assessor (ISA) review of integration
- [ ] OEM safety team validation of operational constraints (e.g., "vehicle stationary" policy)
- [ ] FMEA (Failure Modes and Effects Analysis) for integrated system
- [ ] Safe state verification for all fault modes

### 9.3 Production Readiness Checklist

- [ ] All hardware requirements met (HR-001 to HR-007)
- [ ] All software integration requirements met (SI-001 to SI-005)
- [ ] All safety-critical integration points verified (SCI-001 to SCI-003)
- [ ] All security assumptions validated (SA-001 to SA-003)
- [ ] All operational constraints enforced (OC-001 to OC-002)
- [ ] Integration testing complete (all tests pass)
- [ ] ISA approval obtained
- [ ] OEM safety team approval obtained

---

## 10. Consequences of Assumption Violation

### 10.1 Critical Violations (IMMEDIATE SAFETY IMPACT)

| Violation | Safety Impact | Consequence |
|-----------|---------------|-------------|
| **SCI-001:** Flash write without SUCCESS | ALL SAFETY GOALS VIOLATED | Malicious/corrupted firmware may be installed |
| **SA-001:** Root CA key compromised | ALL SECURITY GUARANTEES INVALID | Attacker can sign malicious firmware |
| **HR-005:** Root CA certificate tampered | ALL SECURITY GUARANTEES INVALID | Attacker can replace Root CA |
| **SI-003:** Version counter not updated atomically | SG-003 VIOLATED | Rollback attacks may succeed |

**Action Required:** IMMEDIATE HALT of production use, security incident response

### 10.2 High-Severity Violations (SAFETY GOAL VIOLATION)

| Violation | Safety Impact | Consequence |
|-----------|---------------|-------------|
| **SI-002:** Error codes ignored | SG-001, SG-002 MAY BE VIOLATED | Malicious/corrupted firmware may be installed |
| **HR-006:** Watchdog not configured | SG-005 VIOLATED | ECU functions may be blocked indefinitely |
| **HR-002:** NVM without ECC | SG-003 MAY BE VIOLATED | Version counter corruption → rollback or rejection |
| **HR-003:** Time source unavailable | SG-004 MAY BE VIOLATED | Revoked CAs may be accepted |

**Action Required:** Fix before production use, re-validation by ISA

### 10.3 Medium-Severity Violations (DEGRADED SAFETY)

| Violation | Safety Impact | Consequence |
|-----------|---------------|-------------|
| **OC-001:** Updates while vehicle moving | ASIL RATINGS MAY INCREASE | Exposure (E) increases, potentially raising ASIL levels |
| **HR-001:** Insufficient CPU/RAM | SG-005 MAY BE VIOLATED | WCET exceeds timeout, updates fail |
| **SA-002:** Non-FIPS crypto libraries | SG-001, SG-002 MAY BE VIOLATED | Crypto bugs may allow bypass |

**Action Required:** Fix before production use, risk assessment by safety team

---

## 11. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-27 | libsum contributors | Initial Assumptions of Use |

**Related Documents:**
- Document 01 (Item Definition) - Section 4 (Assumptions)
- Document 03 (Functional Safety Concept) - Section 6 (Allocation)
- Document 04 (Technical Safety Concept) - Section 6 (Hardware Requirements)
- Document 07 (Safety Case) - Section 7 (Assumptions and Limitations)

**Approval Required:**
- [ ] Functional Safety Manager
- [ ] Integrating System Architect (AUTOSAR team)
- [ ] Hardware Architect (OEM)
- [ ] Independent Safety Assessor

---

**End of Assumptions of Use**

**FINAL WARNING:**
This document is **MANDATORY** for safe integration of libsum. Violation of ANY requirement in this document **INVALIDATES** the ASIL-D safety case. The integrating system developer **MUST** validate compliance with ALL requirements using the checklist in Section 9 before production use.
