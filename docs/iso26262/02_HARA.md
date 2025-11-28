# ISO 26262 Hazard Analysis and Risk Assessment (HARA)
## libsum - Secure Update Verification Library (SEooC)

**Document ID:** LIBSUM-ISO26262-HARA-002
**Version:** 1.0
**Date:** 2025-11-27
**Status:** Draft for Review
**ASIL Target:** ASIL-D (SEooC)

---

## 1. Purpose

This document identifies hazards related to malfunctions of **libsum** when used in automotive OTA update systems, assesses their risks, and derives safety goals per ISO 26262-3:2018.

---

## 2. HARA Methodology

### 2.1 Risk Assessment Parameters

Per ISO 26262-3 Table 2:

**Severity (S):**
- S0: No injuries
- S1: Light and moderate injuries
- S2: Severe and life-threatening injuries
- S3: Life-threatening injuries (survival uncertain), fatal injuries

**Exposure (E):**
- E0: Incredibly unlikely
- E1: Very low probability
- E2: Low probability
- E3: Medium probability
- E4: High probability

**Controllability (C):**
- C0: Controllable in general
- C1: Simply controllable
- C2: Normally controllable
- C3: Difficult to control or uncontrollable

**ASIL Determination:**
- QM: Quality Management (no ASIL)
- ASIL-A, ASIL-B, ASIL-C, ASIL-D (increasing rigor)

---

## 3. Hazard Identification

### 3.1 Malfunctioning Behavior

libsum can malfunction in the following ways:

| ID | Malfunction | Immediate Effect |
|----|-------------|------------------|
| MF-001 | Accept invalid signature | Malicious firmware installed |
| MF-002 | Accept corrupted firmware | Corrupted firmware installed |
| MF-003 | Fail to detect rollback | Vulnerable firmware installed |
| MF-004 | Accept expired certificate | Revoked/compromised firmware installed |
| MF-005 | Infinite loop / hang | Update never completes |
| MF-006 | Memory corruption | Unpredictable behavior |
| MF-007 | Accept firmware for wrong device | Wrong firmware installed |
| MF-008 | False rejection of valid update | Valid update blocked |

---

## 4. Hazard Analysis

### 4.1 H-001: Acceptance of Malicious Firmware

**Malfunction:** libsum incorrectly verifies signature (MF-001)

**Hazardous Event:** Attacker-controlled firmware executes on safety-critical ECU

**Operational Situation:** Vehicle in motion

| Parameter | Rating | Justification |
|-----------|--------|---------------|
| **Severity** | **S3** | Malicious firmware could disable brakes, manipulate steering, or cause unintended acceleration → fatal injuries |
| **Exposure** | **E1** | Very low - requires cryptographic break or implementation bug AND attacker access AND vehicle operation |
| **Controllability** | **C3** | Driver cannot detect or control malicious firmware behavior (uncontrollable) |

**ASIL Determination:** **ASIL-D**

**Safety Goal:** **SG-001: Prevent execution of unverified firmware on safety-critical ECUs**

---

### 4.2 H-002: Acceptance of Corrupted Firmware

**Malfunction:** libsum fails hash verification (MF-002)

**Hazardous Event:** Corrupted firmware causes ECU malfunction (crash, random behavior)

**Operational Situation:** Vehicle in motion

| Parameter | Rating | Justification |
|-----------|--------|---------------|
| **Severity** | **S3** | ECU crash during braking/steering → fatal injuries |
| **Exposure** | **E2** | Low - requires hash collision or verification bug AND vehicle operation |
| **Controllability** | **C3** | Driver cannot detect corrupted firmware before failure (uncontrollable) |

**ASIL Determination:** **ASIL-D**

**Safety Goal:** **SG-002: Prevent execution of corrupted firmware on safety-critical ECUs**

---

### 4.3 H-003: Rollback to Vulnerable Firmware

**Malfunction:** libsum fails anti-rollback check (MF-003)

**Hazardous Event:** Attacker downgrades ECU to version with known vulnerability, then exploits

**Operational Situation:** Vehicle in motion (exploitation phase)

| Parameter | Rating | Justification |
|-----------|--------|---------------|
| **Severity** | **S3** | Known vulnerability exploitation → same as malicious firmware (S3) |
| **Exposure** | **E1** | Very low - requires rollback bypass AND exploitation AND vehicle operation |
| **Controllability** | **C3** | Driver unaware of rollback attack (uncontrollable) |

**ASIL Determination:** **ASIL-D**

**Safety Goal:** **SG-003: Prevent rollback to vulnerable firmware versions**

---

### 4.4 H-004: Acceptance of Firmware from Revoked CA

**Malfunction:** libsum fails revocation check (MF-004)

**Hazardous Event:** Firmware signed by compromised intermediate CA is accepted

**Operational Situation:** Vehicle in motion

| Parameter | Rating | Justification |
|-----------|--------|---------------|
| **Severity** | **S3** | Compromised CA → same risk as malicious firmware (S3) |
| **Exposure** | **E0** | Incredibly unlikely - requires CA key compromise AND timestamp bypass |
| **Controllability** | **C3** | Driver cannot detect compromised CA (uncontrollable) |

**ASIL Determination:** **ASIL-C** (E0 + S3 + C3 per ISO 26262-3 Table 4)

**Safety Goal:** **SG-004: Prevent acceptance of firmware from revoked certificate authorities**

---

### 4.5 H-005: Verification Hang / Infinite Loop

**Malfunction:** libsum enters infinite loop (MF-005)

**Hazardous Event:** Safety-critical ECU unavailable during update (e.g., brake ECU unresponsive)

**Operational Situation:** Vehicle in motion (if update attempted while driving - should be prevented by integrating system)

| Parameter | Rating | Justification |
|-----------|--------|---------------|
| **Severity** | **S3** | Brake ECU hang while driving → fatal injuries |
| **Exposure** | **E1** | Very low - assumes update during driving (violates assumptions of use) |
| **Controllability** | **C2** | Driver can brake using mechanical backup if available (normally controllable) |

**ASIL Determination:** **ASIL-C**

**Safety Goal:** **SG-005: Prevent indefinite blocking of safety-critical ECU functions**

**Note:** Integrating system MUST implement timeout and NOT update safety ECUs while vehicle operational.

---

### 4.6 H-006: Memory Corruption During Verification

**Malfunction:** Buffer overflow or memory corruption (MF-006)

**Hazardous Event:** Unpredictable ECU behavior (crash, data corruption)

**Operational Situation:** During update (vehicle stationary per assumptions of use)

| Parameter | Rating | Justification |
|-----------|--------|---------------|
| **Severity** | **S1** | ECU crash while stationary → restart required, no injuries (S1) |
| **Exposure** | **E1** | Very low - requires memory bug AND malformed input |
| **Controllability** | **C0** | Vehicle stationary, no safety impact (controllable) |

**ASIL Determination:** **QM** (E1 + S1 + C0)

**Safety Goal:** None (QM) - Handled by quality measures (fuzzing, code review)

---

### 4.7 H-007: Cross-Device Firmware Installation

**Malfunction:** libsum accepts firmware for different device (MF-007)

**Hazardous Event:** Incompatible firmware runs on ECU (wrong hardware configuration)

**Operational Situation:** Vehicle in motion (after update)

| Parameter | Rating | Justification |
|-----------|--------|---------------|
| **Severity** | **S3** | Wrong firmware configuration → ECU malfunction → fatal injuries |
| **Exposure** | **E0** | Incredibly unlikely - requires device_id check bypass AND wrong firmware available |
| **Controllability** | **C3** | Driver cannot detect wrong firmware (uncontrollable) |

**ASIL Determination:** **ASIL-C**

**Safety Goal:** **SG-006: Prevent installation of firmware intended for different devices**

---

### 4.8 H-008: False Rejection of Valid Updates

**Malfunction:** libsum incorrectly rejects valid firmware (MF-008)

**Hazardous Event:** Critical security patch cannot be installed, vehicle remains vulnerable

**Operational Situation:** Stationary (update blocked)

| Parameter | Rating | Justification |
|-----------|--------|---------------|
| **Severity** | **S0** | No immediate physical harm, but vulnerability persists (S0 for direct hazard) |
| **Exposure** | **E2** | Low - valid updates rejected occasionally |
| **Controllability** | **C0** | No safety impact, can retry update or use workshop (controllable) |

**ASIL Determination:** **QM**

**Safety Goal:** None (QM) - Availability concern, not safety hazard

**Note:** While false rejection is not a safety hazard per ISO 26262 definition, it IS a security concern (prevents patching vulnerabilities).

---

## 5. HARA Summary Table

| Hazard ID | Safety Goal | ASIL | Severity | Exposure | Controllability |
|-----------|-------------|------|----------|----------|-----------------|
| **H-001** | SG-001: Prevent unverified firmware execution | **ASIL-D** | S3 | E1 | C3 |
| **H-002** | SG-002: Prevent corrupted firmware execution | **ASIL-D** | S3 | E2 | C3 |
| **H-003** | SG-003: Prevent rollback attacks | **ASIL-D** | S3 | E1 | C3 |
| **H-004** | SG-004: Prevent revoked CA acceptance | **ASIL-C** | S3 | E0 | C3 |
| **H-005** | SG-005: Prevent ECU function blocking | **ASIL-C** | S3 | E1 | C2 |
| **H-006** | None (QM) | **QM** | S1 | E1 | C0 |
| **H-007** | SG-006: Prevent cross-device installation | **ASIL-C** | S3 | E0 | C3 |
| **H-008** | None (QM) | **QM** | S0 | E2 | C0 |

---

## 6. Safety Goals Consolidated

### SG-001: Prevent Unverified Firmware Execution (ASIL-D)

**Safe State:** ECU continues running verified firmware (no update applied)

**Fault Tolerance Time Interval (FTTI):** Before firmware execution (instant verification)

**Verification Method:** Cryptographic signature verification (Ed25519)

**Allocation:** libsum SHALL verify signatures before returning SUCCESS

---

### SG-002: Prevent Corrupted Firmware Execution (ASIL-D)

**Safe State:** ECU continues running verified firmware (no update applied)

**FTTI:** Before firmware execution (instant verification)

**Verification Method:** SHA-256 hash verification

**Allocation:** libsum SHALL verify hash before returning SUCCESS

---

### SG-003: Prevent Rollback to Vulnerable Firmware (ASIL-D)

**Safe State:** ECU continues running current firmware (no downgrade)

**FTTI:** Before firmware installation (instant check)

**Verification Method:** Version comparison (manifest_version > last_installed)

**Allocation:** libsum SHALL enforce monotonic version increase

---

### SG-004: Prevent Revoked CA Acceptance (ASIL-C)

**Safe State:** ECU rejects update from revoked CA

**FTTI:** Before firmware decryption (instant check)

**Verification Method:** Timestamp comparison (intermediate CA notBefore > reject_timestamp)

**Allocation:** libsum SHALL check revocation timestamp if provided

---

### SG-005: Prevent ECU Function Blocking (ASIL-C)

**Safe State:** ECU functions remain available (update aborted)

**FTTI:** Watchdog timeout (integrating system responsibility)

**Verification Method:** Timeout monitoring

**Allocation:** **Integrating system** SHALL implement timeout (libsum provides deterministic behavior)

---

### SG-006: Prevent Cross-Device Installation (ASIL-C)

**Safe State:** ECU rejects firmware for wrong device

**FTTI:** Before firmware decryption (instant check)

**Verification Method:** device_id string comparison

**Allocation:** libsum SHALL verify device_id matches before key unwrapping

---

## 7. Decomposition for SEooC

Since libsum is a **SEooC**, the following ASIL decomposition applies:

| Safety Goal | ASIL | Decomposed To libsum | Decomposed To Integrating System |
|-------------|------|----------------------|----------------------------------|
| **SG-001** (Unverified FW) | ASIL-D | ASIL-D (signature verification) | ASIL-D (only execute if SUCCESS) |
| **SG-002** (Corrupted FW) | ASIL-D | ASIL-D (hash verification) | ASIL-D (only execute if SUCCESS) |
| **SG-003** (Rollback) | ASIL-D | ASIL-D (version check) | ASIL-D (persist version after success) |
| **SG-004** (Revoked CA) | ASIL-C | ASIL-C (timestamp check) | ASIL-C (provide reject timestamp) |
| **SG-005** (Blocking) | ASIL-C | ASIL-B (deterministic code) | ASIL-C (timeout + watchdog) |
| **SG-006** (Wrong device) | ASIL-C | ASIL-C (device_id check) | ASIL-C (only execute if SUCCESS) |

**No decomposition** is applied (all remain at target ASIL). Integrating system must also achieve same ASIL for its portion.

---

## 8. Dependent Failures Analysis

### 8.1 Common Cause Failures

| Failure Mode | Affects | ASIL | Mitigation |
|--------------|---------|------|------------|
| **OpenSSL/mbedtls crypto bug** | SG-001, SG-002 | ASIL-D | Use FIPS 140-2 validated versions, monitor CVE database |
| **Protobuf parser bug** | SG-003, SG-006 | ASIL-D | Extensive fuzzing, size limits, static analysis |
| **Time source failure** | SG-004 | ASIL-C | Integrating system provides trusted time (RTC), libsum validates |

### 8.2 Systematic Capability

libsum targets **ISO 26262 SC3** (Systematic Capability Class 3) for ASIL-D:
- ✅ **SC3-1:** Requirements traceability (this document series)
- ✅ **SC3-2:** Design reviews (to be completed)
- ✅ **SC3-3:** Static code analysis (Clang-Tidy, Cppcheck)
- ✅ **SC3-4:** Comprehensive testing (61 tests, 100% pass)
- ⚠️ **SC3-5:** Fault injection testing (not yet performed)

---

## 9. Assumptions for ASIL Ratings

The ASIL ratings assume:

1. **Vehicle stationary during safety-critical ECU updates** (E-rating justification)
2. **Integrating system implements timeout** (SG-005 mitigation)
3. **Root CA key is secure** (offline HSM) - IF compromised, all ratings invalid
4. **Crypto libraries are FIPS-validated** (OpenSSL 3.0 FIPS, mbedtls)
5. **Time source is trusted** (RTC with battery backup or Roughtime)

**If assumptions violated, ASIL ratings may increase (e.g., update while driving → E3, higher ASIL).**

---

## 10. HARA Validation

| Validation Activity | Status | Evidence |
|---------------------|--------|----------|
| Hazard completeness review | ✅ Complete | Review of ISO 26262-8 Annex D (OTA hazards) |
| ASIL rating review | ⚠️ Pending | Requires OEM safety engineer review |
| Operational situation validation | ⚠️ Pending | Requires vehicle-specific analysis |
| Controllability assessment | ⚠️ Pending | Requires driver behavior analysis |

**Recommendation:** OEM safety team should validate E/C ratings based on:
- Specific vehicle architecture (brake backup systems, HMI warnings)
- Update policy (stationary only vs. while driving)
- Driver population (professional fleet vs. consumer)

---

## 11. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-27 | libsum contributors | Initial HARA |

**Next Document:** Functional Safety Concept (Document 03)

**Approval Required:**
- [ ] Functional Safety Manager
- [ ] Product Owner (OTA system)
- [ ] Risk Assessment Team
- [ ] Independent Safety Assessor

---

**End of HARA**
