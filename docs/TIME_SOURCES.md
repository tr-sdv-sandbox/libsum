# Trusted Time Sources for Certificate Validation

## Overview

Certificate validation requires a **trusted time source** to verify that certificates are:
- Not yet expired (`notAfter` check)
- Already valid (`notBefore` check)
- Not revoked via timestamp-based revocation

**SECURITY CRITICAL**: Using an untrusted or manipulated time source completely undermines certificate security.

## Why Time Validation Matters

Skipping time validation or using an untrusted time source allows:

1. **Using Expired Certificates**: Attackers can use certificates that have been revoked or expired after a compromise
2. **Using Not-Yet-Valid Certificates**: Prevents proper pre-deployment validation processes
3. **Replay Attacks**: Old, revoked certificates can be reused
4. **Timestamp-Based Revocation Bypass**: Emergency revocation mechanisms become ineffective

## Recommended Time Sources

### 1. Battery-Backed Real-Time Clock (RTC) ⭐ **RECOMMENDED**

**Best for**: Offline systems, air-gapped devices, IoT devices

**Hardware Options**:
- DS3231: High-precision (±2ppm), temperature-compensated
- PCF8523: Low-power, I2C interface
- RV-3028-C7: Ultra-low power, TCXO

**Advantages**:
- Works offline
- Maintains time across power cycles
- No network dependency
- Immune to network attacks

**Implementation**:
```c
#include <time.h>

// Initialize RTC on boot
rtc_init();

// Get trusted time from RTC
int64_t trusted_time = rtc_get_unix_timestamp();

// Validate certificate
sum_tiny_validate_certificate(..., trusted_time, ...);
```

**Security Considerations**:
- RTC can be manipulated by physical access
- Battery can be removed to reset time
- Acceptable for most IoT/embedded use cases
- Not suitable if physical tampering is in threat model

---

### 2. Roughtime Protocol (RFC 9507) ⭐ **RECOMMENDED for Network-Connected Devices**

**Best for**: Internet-connected devices, devices with periodic network access

**What is Roughtime**:
- Modern network time protocol designed for security
- Cryptographic proof of time from multiple servers
- Resistant to time manipulation attacks
- Merkle-tree based time attestation

**Advantages**:
- Cryptographically secure
- Multiple-server verification prevents single point of failure
- Designed to prevent time manipulation
- Open standard (RFC 9507)

**Public Roughtime Servers**:
```
Cloudflare:   roughtime.cloudflare.com:2003
Google:       roughtime.googleapis.com:2002
```

**Implementation Example** (libsum-tiny ESP32):
```c
#include "esp_roughtime.h"

int64_t get_trusted_time(void) {
    int64_t roughtime = 0;

    // Try to get time from Roughtime
    esp_err_t err = esp_roughtime_get_time(
        "roughtime.cloudflare.com",
        2003,
        &roughtime
    );

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Got Roughtime: %lld", roughtime);
        return roughtime;
    }

    // Fallback: Use RTC or fail
    ESP_LOGW(TAG, "Roughtime failed, using RTC");
    return rtc_get_unix_timestamp();
}
```

**Security Considerations**:
- Requires network access
- Vulnerable to network outages (have fallback)
- Should query multiple servers and cross-check
- Store last-known-good time in RTC as fallback

**Resources**:
- RFC 9507: https://www.rfc-editor.org/rfc/rfc9507.html
- Roughtime Project: https://roughtime.googlesource.com/roughtime
- ESP-IDF Roughtime: https://github.com/trombik/esp_idf_lib_roughtime

---

### 3. GPS Time ⚠️ **USE WITH CAUTION**

**Best for**: Outdoor devices, navigation systems, devices where GPS spoofing is not in threat model

**Advantages**:
- Very accurate (microsecond precision)
- Works offline (no network needed)
- Global coverage

**Disadvantages**:
- **Vulnerable to GPS spoofing** (trivial with $200 hardware)
- Doesn't work indoors
- Requires GPS hardware and antenna
- Cold start can take 30+ seconds

**When GPS is Acceptable**:
- Device already uses GPS for primary function (navigation, tracking)
- GPS spoofing is explicitly out of scope for your threat model
- Used in combination with other time sources for cross-check

**Implementation**:
```c
#include <gps.h>

int64_t get_gps_time(void) {
    if (gps_has_fix()) {
        return gps_get_unix_timestamp();
    }
    return 0;  // No fix
}
```

**Security Considerations**:
- DO NOT use GPS time alone if GPS spoofing is in your threat model
- Use GPS time as one of multiple sources
- Cross-check with Roughtime or RTC
- Detect GPS spoofing: sudden jumps, impossible locations

---

### 4. Signed Bootstrap Time

**Best for**: Air-gapped systems receiving signed updates

**Approach**: Include current time in the signed update package itself

**Implementation**:
```c
// 1. Backend includes current time in DeviceMetadata
DeviceMetadata metadata;
metadata.bootstrap_time = time(nullptr);  // Current Unix timestamp

// 2. Sign the update certificate (includes metadata)
auto update_cert = CreateUpdateCertificate(..., metadata, ...);

// 3. Device extracts and uses bootstrap time
auto metadata = update_cert.GetDeviceMetadata();
int64_t trusted_time = metadata.bootstrap_time;

// Use as lower bound: certificate must be valid AFTER this time
if (trusted_time > 0) {
    // Certificate must not have expired before bootstrap time
    validate_certificate(..., trusted_time, ...);
}
```

**Security Considerations**:
- Only provides lower bound (certificates must be valid after bootstrap time)
- Cannot detect expired certificates
- Acceptable for initial time synchronization
- Must transition to RTC or Roughtime for long-term use

---

## Implementation Strategies

### Strategy 1: Hybrid Approach (RECOMMENDED)

Use multiple time sources with fallbacks:

```c
int64_t get_trusted_time(void) {
    int64_t time = 0;

    // 1. Try Roughtime (most secure if network available)
    time = roughtime_get_time();
    if (time > 0) {
        rtc_set_time(time);  // Update RTC
        return time;
    }

    // 2. Fall back to RTC (works offline)
    time = rtc_get_unix_timestamp();
    if (time > 0) {
        return time;
    }

    // 3. Last resort: Bootstrap time from last update
    time = nvs_get_i64("last_update_time");
    if (time > 0) {
        return time;
    }

    // 4. No time source available
    ESP_LOGE(TAG, "No trusted time source available");
    return 0;  // Will fail validation (unless SUM_TINY_ALLOW_SKIP_TIME_VALIDATION)
}
```

### Strategy 2: Time Attestation Chain

Store and verify time progression:

```c
// On each successful update, store the time
void update_completed(int64_t update_time) {
    int64_t last_time = nvs_get_i64("last_update_time");

    // Time should never go backwards
    if (update_time < last_time) {
        ESP_LOGW(TAG, "Time went backwards! Possible attack.");
        // Investigate or reject update
    }

    // Store new time
    nvs_set_i64("last_update_time", update_time);
}

int64_t get_trusted_time(void) {
    int64_t current_time = roughtime_get_time();
    int64_t last_known_time = nvs_get_i64("last_update_time");

    // Current time should be >= last known time
    if (current_time < last_known_time) {
        ESP_LOGW(TAG, "Time rollback detected!");
        // Use last_known_time as minimum
        return last_known_time;
    }

    return current_time;
}
```

### Strategy 3: Factory-Initialized RTC

For devices manufactured with RTC:

```c
// During manufacturing/first boot:
void factory_init(void) {
    if (!rtc_is_initialized()) {
        // Set RTC to manufacturing time
        rtc_set_time(FACTORY_INIT_TIME);

        // Mark as initialized
        nvs_set_u8("rtc_initialized", 1);
    }
}

// During updates:
void update_time_from_network(void) {
    int64_t roughtime = roughtime_get_time();
    if (roughtime > 0) {
        rtc_set_time(roughtime);
        ESP_LOGI(TAG, "RTC synchronized with Roughtime");
    }
}
```

---

## Configuration

### libsum-tiny (Embedded/C)

By default, time validation is **REQUIRED**. To allow skipping time validation (NOT RECOMMENDED):

```c
// CMakeLists.txt or build configuration
add_definitions(-DSUM_TINY_ALLOW_SKIP_TIME_VALIDATION)
```

This will trigger a compiler warning:
```
warning: SUM_TINY_ALLOW_SKIP_TIME_VALIDATION is enabled - time validation can be bypassed! This is NOT secure for production.
```

### libsum (C++)

Time validation is always required. The `trusted_time` parameter must be > 0.

---

## Testing Without Real Time Source

For development/testing only:

```c
// ⚠️ DEVELOPMENT ONLY - NOT FOR PRODUCTION
#ifdef DEVELOPMENT_BUILD
#define SUM_TINY_ALLOW_SKIP_TIME_VALIDATION
#endif

void test_certificate_loading(void) {
    #ifdef SUM_TINY_ALLOW_SKIP_TIME_VALIDATION
    // Skip time validation in tests
    int64_t trusted_time = 0;
    #else
    // Use fixed time for reproducible tests
    int64_t trusted_time = 1704067200;  // 2024-01-01 00:00:00 UTC
    #endif

    int ret = sum_tiny_validate_certificate(..., trusted_time, ...);
    assert(ret == SUM_TINY_OK);
}
```

---

## Best Practices

1. **Always Use RTC**: Even if you have network time, use RTC as fallback
2. **Validate Time Progression**: Time should never go backwards
3. **Cross-Check Multiple Sources**: Use Roughtime + RTC and compare
4. **Store Last Known Good Time**: Protect against time rollback
5. **Fail Secure**: If no time source is available, fail validation
6. **Monitor Time Jumps**: Log and alert on suspicious time changes
7. **Regular Synchronization**: Update RTC from Roughtime periodically

---

## FAQ

**Q: Can I use NTP instead of Roughtime?**

A: Not recommended. NTP is not designed for security and is easily spoofed. Roughtime provides cryptographic proof of time.

**Q: What if my device has no RTC and no network?**

A: Use bootstrap time from signed updates as a starting point, but plan to add RTC in next hardware revision. This is a security limitation.

**Q: How do I handle devices with incorrect RTC time from factory?**

A: On first network connection, synchronize RTC with Roughtime. Store a flag indicating RTC has been synchronized.

**Q: Is GPS time secure enough?**

A: Only if GPS spoofing is explicitly out of scope for your threat model. Otherwise, use it as one of multiple sources for cross-checking.

**Q: What about NTS (Network Time Security)?**

A: NTS is RFC 8915, more complex than Roughtime. Use Roughtime unless you have specific NTS requirements.
