/**
 * @file x509_constants.h
 * @brief X.509 extension OIDs and constants for libsum
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SUM_X509_CONSTANTS_H
#define SUM_X509_CONSTANTS_H

namespace sum {
namespace crypto {
namespace internal {

// X.509 Extension OIDs for libsum
// Base OID: 1.3.6.1.3 (reserved for experimental use)
// Current assignments:
// - 1.3.6.1.3.1 - Device metadata extension
// - 1.3.6.1.3.2 - Secure update manifest extension
constexpr const char* DEVICE_METADATA_OID = "1.3.6.1.3.1";      // Device Metadata
constexpr const char* MANIFEST_EXTENSION_OID = "1.3.6.1.3.2";   // Software Update Manifest

} // namespace internal
} // namespace crypto
} // namespace sum

#endif // SUM_X509_CONSTANTS_H
