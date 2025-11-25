/**
 * @file limits.h
 * @brief Size limits and constraints for libsum
 *
 * These limits match the nanopb options and protobuf definitions
 * to ensure consistency between C++ and C implementations.
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace sum {
namespace limits {

// ============================================================================
// Manifest limits
// ============================================================================

/**
 * @brief Maximum size of serialized protobuf manifest
 *
 * Prevents DoS from oversized manifests. Based on realistic use:
 * - 8 artifacts * (~500 bytes each) = 4KB
 * - 8 encryption params * (~200 bytes each) = 1.6KB
 * - Signing certificate: 2KB
 * - Metadata and overhead: 8KB
 * Total: ~16KB, round up to 32KB for safety margin
 */
constexpr size_t MAX_MANIFEST_SIZE = 32 * 1024;

/**
 * @brief Maximum number of artifacts in a manifest
 */
constexpr size_t MAX_ARTIFACTS = 8;

/**
 * @brief Maximum number of download sources per artifact
 */
constexpr size_t MAX_SOURCES_PER_ARTIFACT = 4;

// ============================================================================
// Field size limits (from nanopb options in proto/manifest.options)
// ============================================================================

// String fields
constexpr size_t MAX_ARTIFACT_NAME = 32;
constexpr size_t MAX_ARTIFACT_TYPE = 32;
constexpr size_t MAX_TARGET_ECU = 32;
constexpr size_t MAX_ALGORITHM_NAME = 16;
constexpr size_t MAX_DEVICE_ID = 64;
constexpr size_t MAX_KEY_WRAP_ALGORITHM = 64;
constexpr size_t MAX_SOURCE_URI = 256;
constexpr size_t MAX_SOURCE_TYPE = 16;

// DeviceMetadata fields
constexpr size_t MAX_DEVICE_TYPE = 64;
constexpr size_t MAX_HARDWARE_ID = 64;
constexpr size_t MAX_MANUFACTURER = 64;
constexpr size_t MAX_HARDWARE_VERSION = 32;

// Fixed-size byte arrays
constexpr size_t HASH_SIZE = 32;         // SHA-256
constexpr size_t SIGNATURE_SIZE = 64;    // Ed25519
constexpr size_t IV_SIZE = 12;           // AES-GCM
constexpr size_t TAG_SIZE = 16;          // AES-GCM
constexpr size_t MAX_WRAPPED_KEY = 128;  // X25519 wrapped key
constexpr size_t MAX_CERT_SIZE = 2048;   // DER-encoded signing certificate

}  // namespace limits
}  // namespace sum
