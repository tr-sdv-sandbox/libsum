# Secure OTA Update Flow

## Security Issue: Writing Before Verification

### ⚠️ THE PROBLEM

**DO NOT** write firmware to storage before signature verification:

```
// INSECURE FLOW (DO NOT USE)
open_update_destination()
while downloading_firmware:
    chunk = download_chunk()
    decrypted = decrypt(chunk)
    update_hash(decrypted)
    write_to_storage(decrypted)        // ⚠️ WRITING BEFORE VERIFICATION!

computed_hash = finalize_hash()
if not verify_signature(computed_hash):
    // TOO LATE! Unverified firmware already written to storage
    abort_update()
```

### Why This Is Dangerous

1. **Attack Window**: Malicious firmware written to storage before verification fails
2. **Storage Exploitation**: Specially crafted data could exploit storage controller vulnerabilities
3. **Resource Exhaustion**: Repeated malicious updates can wear out flash or fill storage
4. **Partial Updates**: Even if not activated, malicious code exists in storage
5. **Side Channels**: Unverified data in storage may be accessible through other means

---

## ✅ SOLUTION: Use A/B Partitions + Verify Before Activation

### Recommended Architecture: A/B Partition Scheme

Most modern update systems use **A/B partitions** (also called dual-bank, dual-boot):

```
┌──────────────────────────────────────┐
│ Bootloader                           │
├──────────────────────────────────────┤
│ Partition Table / Metadata           │
├──────────────────────────────────────┤
│ Non-Volatile Storage (NVS)           │
├──────────────────────────────────────┤
│ Partition A (Active)    ◄────────────│ Currently running firmware
├──────────────────────────────────────┤
│ Partition B (Inactive)               │ Next update writes here
└──────────────────────────────────────┘
```

**Key Properties**:
- Device always boots from **active partition** (A or B)
- Updates write to **inactive partition**
- After successful verification, **atomically switch** active partition
- If verification fails, inactive partition is discarded (never becomes active)
- Running firmware is **never modified** during update

---

## Secure Update Flow (Pseudocode)

### Phase 1: Certificate and Manifest Validation

```python
# 1. Load root CA certificate (pre-installed trust anchor)
root_ca = load_root_ca_certificate()

# 2. Load and verify update certificate (atomic verification)
update_cert = UpdateCertificate.load_from_file(
    path="update.crt",              # PEM bundle (update cert + intermediate CA)
    root_ca=root_ca,
    trusted_time=get_trusted_time(), # From RTC, Roughtime, etc.
    reject_before=load_revocation_timestamp()
)
# ✅ Certificate is now VERIFIED - all extensions are cryptographically protected

# 3. Extract verified manifest and device metadata
manifest = update_cert.get_manifest()
device_metadata = update_cert.get_device_metadata()

# 4. Anti-rollback/replay protection
if manifest.manifest_version <= load_last_installed_version():
    LOG("Rollback/replay attack detected")
    abort_update()

# 5. Extract artifact info
artifact = manifest.artifacts[0]  # First artifact (e.g., firmware)
expected_hash = artifact.expected_hash
expected_size = artifact.size
firmware_url = artifact.sources[0].url
```

### Phase 2: Download and Write to INACTIVE Partition

```python
# 6. Prepare inactive partition for writing
inactive_partition = get_inactive_partition()  # Get partition that is NOT running
update_handle = begin_update(inactive_partition)

LOG(f"Writing to INACTIVE partition: {inactive_partition.name}")
LOG(f"Current running partition: {get_active_partition().name}")

# 7. Unwrap encryption key (if firmware is encrypted)
if artifact.encrypted:
    device_private_key = load_device_private_key()  # From secure storage
    encryption_params = get_encryption_params(manifest, artifact.name)
    aes_key = unwrap_key(
        wrapped_key=encryption_params.wrapped_key,
        device_key=device_private_key
    )
    decryptor = create_aes_gcm_decryptor(aes_key, encryption_params.iv, encryption_params.tag)
else:
    decryptor = None

# 8. Initialize hash computation
hasher = SHA256_init()

# 9. Stream firmware: download → decrypt → hash → write to INACTIVE partition
total_written = 0
while downloading:
    # Download chunk
    encrypted_chunk = download_chunk(firmware_url)

    # Decrypt chunk (if encrypted)
    if decryptor:
        plaintext_chunk = decryptor.update(encrypted_chunk)
    else:
        plaintext_chunk = encrypted_chunk

    # Update running hash
    hasher.update(plaintext_chunk)

    # Write to INACTIVE partition
    # SECURITY: Safe to write unverified data to inactive partition
    # because it will never become active without verification
    write_to_partition(update_handle, plaintext_chunk)

    total_written += len(plaintext_chunk)

    # Progress indication
    if total_written % (64 * 1024) == 0:
        LOG(f"Written: {total_written / 1024} KB")

# 10. Finalize decryption (verifies AEAD tag if encrypted)
if decryptor:
    final_plaintext = decryptor.finalize()  # Throws if AEAD tag invalid
    hasher.update(final_plaintext)
    write_to_partition(update_handle, final_plaintext)

# 11. Finalize hash computation
computed_hash = hasher.finalize()

LOG(f"✅ Download complete: {total_written} bytes written to INACTIVE partition")
```

### Phase 3: CRITICAL - Verify Before Activation

```python
# 12. SECURITY CRITICAL: Verify hash matches manifest
if computed_hash != expected_hash:
    LOG("❌ Hash mismatch - computed hash does not match manifest")
    abort_update(update_handle)  # Discard inactive partition
    exit(1)

LOG("✅ Hash verified")

# 13. SECURITY CRITICAL: Verify signature
signing_cert = manifest.signing_cert  # Certificate that signed the manifest
signature_valid = verify_signature(
    data=computed_hash,
    signature=artifact.signature,
    signing_cert=signing_cert
)

if not signature_valid:
    LOG("❌ Signature verification FAILED")
    abort_update(update_handle)  # Discard inactive partition
    exit(1)

LOG("✅ Signature verified")

# 14. Additional validation (optional but recommended)
if total_written != expected_size:
    LOG(f"❌ Size mismatch: expected {expected_size}, got {total_written}")
    abort_update(update_handle)
    exit(1)

# Verify device compatibility
if not check_device_compatibility(device_metadata):
    LOG("❌ Update not compatible with this device")
    abort_update(update_handle)
    exit(1)
```

### Phase 4: Activation (Only After Verification)

```python
# 15. ✅ All verification passed - finalize update
finalize_update(update_handle)  # Close handles, flush buffers

# 16. ONLY NOW: Atomically switch active partition
# This is the ONLY operation that makes the new firmware bootable
switch_active_partition(inactive_partition)

LOG("✅ Partition switched - new firmware will boot on next restart")

# 17. Persist anti-rollback/replay state
save_last_installed_version(manifest.manifest_version)
save_artifact_security_version(artifact.security_version)

# 18. Reboot to activate new firmware
LOG("Rebooting in 5 seconds...")
sleep(5)
reboot()
```

### Phase 5: First Boot Validation (Rollback Protection)

```python
# After reboot, new firmware runs this on first boot:

def app_main():
    LOG("Firmware started")

    # Check if this is first boot after update
    partition_state = get_partition_state(get_running_partition())

    if partition_state == PENDING_VERIFICATION:
        LOG("First boot after OTA - performing self-check...")

        # Perform validation (connectivity check, diagnostics, etc.)
        firmware_ok = perform_self_check()

        if firmware_ok:
            LOG("✅ Firmware validated - marking as permanent")
            mark_partition_valid()  # Make this partition permanent
        else:
            LOG("❌ Firmware validation failed")
            # Don't mark as valid - bootloader will revert on next boot
            reboot()  # Trigger automatic rollback

    # Continue with normal application logic
    run_application()
```

---

## Security Properties

### ✅ What This Achieves

1. **Unverified Code Never Runs**: Signature verification before activation
2. **Atomic Updates**: Either fully applied or fully discarded (no partial updates)
3. **Automatic Rollback**: Bootloader reverts to previous partition if new firmware fails
4. **Running System Protected**: Active partition never modified during update
5. **Replay/Rollback Protection**: Version checking prevents downgrade attacks
6. **Certificate Validation**: Full PKI verification before processing manifest
7. **Integrity Protection**: Hash verification detects any tampering

### 🔒 Attack Resistance

| Attack | Defense |
|--------|---------|
| **Modified Firmware** | Signature verification fails → update discarded |
| **Tampered Manifest** | Certificate signature protects manifest |
| **Downgrade Attack** | Version checking rejects old firmware |
| **Replay Attack** | Manifest version tracking prevents re-installation |
| **Man-in-the-Middle** | Certificate chain verification |
| **Corrupted Download** | Hash verification detects corruption |
| **Encrypted Firmware Tampering** | AEAD tag verification (GCM) |

---

## Implementation Requirements

### Required Platform Support

Your platform must provide:

1. **A/B Partitions**: Dual firmware storage (active + inactive)
2. **Atomic Switch**: Bootloader can atomically switch active partition
3. **Partition Metadata**: Track which partition is active/pending/invalid
4. **Rollback Support**: Bootloader can revert to previous partition on failure

### Platform-Specific Examples

**Linux/Embedded Linux** (RAUC, SWUpdate, Mender):
```python
inactive = "/dev/mmcblk0p2"  # Inactive rootfs partition
write_to_partition(inactive, firmware_data)
verify_signature()
mark_bootable(inactive)  # Update boot flags
reboot()
```

**ESP32** (ESP-IDF OTA):
```c
esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
esp_ota_begin(update_partition, ...);
esp_ota_write(...);  // Write to inactive partition
verify_signature();
esp_ota_set_boot_partition(update_partition);  // Atomic switch
esp_restart();
```

**Android**:
```python
inactive_slot = get_inactive_slot()  # "_a" or "_b"
write_update(inactive_slot, firmware)
verify_signature()
set_active_boot_slot(inactive_slot)
reboot()
```

**STM32/Microcontrollers** (Custom bootloader):
```c
#define BANK_A_ADDR 0x08000000
#define BANK_B_ADDR 0x08080000

write_to_flash(BANK_B_ADDR, firmware_data);  // Write to inactive bank
verify_signature();
set_active_bank(BANK_B);  // Update boot flag in EEPROM/flash
NVIC_SystemReset();
```

---

## Common Mistakes to Avoid

### ❌ Don't: Write to Active Partition

```python
# WRONG: Never modify running firmware
active = get_active_partition()
write_to_partition(active, firmware_data)  # ❌ DANGEROUS!
```

**Why**: Corrupts running system, can brick device.

### ❌ Don't: Activate Before Verification

```python
# WRONG: Don't activate before verification
write_to_partition(inactive, firmware_data)
switch_active_partition(inactive)  # ❌ TOO EARLY!

# Now verify...
if not verify_signature():
    # Too late! Partition already marked active
```

**Why**: Unverified firmware becomes bootable.

### ❌ Don't: Skip Rollback Validation

```python
# WRONG: Always validate on first boot
def app_main():
    LOG("App started")
    # ❌ Missing: mark_partition_valid()
    run_application()
```

**Why**: Broken firmware stays active, no automatic recovery.

### ❌ Don't: Trust manifest_version Without Certificate Validation

```python
# WRONG: Check version before certificate validation
manifest = parse_manifest_from_file()  # ⚠️ Not yet verified!
if manifest.version <= last_version:
    abort_update()
```

**Why**: Attacker can manipulate manifest_version before verification.

### ✅ Do: Validate Certificate First, Then Check Version

```python
# CORRECT: Verify certificate atomically, then check version
update_cert = UpdateCertificate.load(...)  # ✅ Atomic verification
manifest = update_cert.get_manifest()      # ✅ Now trusted
if manifest.version <= last_version:
    abort_update()
```

---

## Performance Considerations

### Streaming vs Buffering

**Streaming (Recommended)**:
```python
while downloading:
    chunk = download_chunk()      # Small chunk (4-16 KB)
    plaintext = decrypt(chunk)
    hash.update(plaintext)
    write(plaintext)              # Low memory usage
```
- **Memory**: ~4-16 KB buffer
- **Suitable for**: Any device (including RAM-constrained)

**Full Buffering (Not Recommended)**:
```python
firmware = download_entire_file()  # Load all into RAM
plaintext = decrypt(firmware)
hash = hash(plaintext)
write(plaintext)
```
- **Memory**: Full firmware size (MB)
- **Not practical**: For large firmware on constrained devices

### Write Performance

Modern flash storage:
- **Sequential writes**: Fast (MB/s)
- **Random writes**: Slow
- **Streaming writes**: Optimal for firmware updates

---

## Security Checklist

### ✅ Required Security Measures

- [x] Write to **inactive partition only**
- [x] **Atomically verify certificate** before accessing manifest
- [x] **Verify signature** before activation
- [x] **Verify hash** matches manifest
- [x] **Check rollback protection** (manifest_version > last_version)
- [x] **Validate device compatibility** (DeviceMetadata)
- [x] **Use trusted time** for certificate validation
- [x] **Atomic partition switch** (all-or-nothing)
- [x] **Mark firmware valid** on first boot (enables rollback)

### ✅ Recommended Additional Measures

- [ ] **Size check** before download (avoid filling storage)
- [ ] **Integrity of running firmware** (measured boot, secure boot)
- [ ] **Secure key storage** (TPM, secure element, HSM)
- [ ] **Audit logging** (record all update attempts)
- [ ] **Rate limiting** (prevent DoS via repeated update attempts)
- [ ] **Progress indication** to user
- [ ] **Retry logic** with exponential backoff

---

## Summary

**Key Security Principle: VERIFY, THEN ACTIVATE**

1. ✅ **Write to inactive partition** (safe - not bootable)
2. ✅ **Verify certificate** → extract manifest
3. ✅ **Download and hash** firmware to inactive partition
4. ✅ **Verify signature and hash** after download completes
5. ✅ **Only then activate** partition (atomic switch)
6. ✅ **Validate on first boot** (enables automatic rollback)

This ensures:
- **No unverified code ever runs**
- **Atomic updates**: Fully applied or fully discarded
- **Automatic recovery**: Bad updates don't brick device
- **Attack resistance**: Malicious firmware never becomes active
- **Running system protected**: Active partition never modified
