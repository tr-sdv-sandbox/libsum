/**
 * @file validator.h
 * @brief Manifest validation and software decryption
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SUM_VALIDATOR_H
#define SUM_VALIDATOR_H

#include "sum/common/manifest.h"
#include "sum/common/crypto.h"
#include <memory>
#include <vector>

namespace sum {

/**
 * @brief Validates manifests and decrypts software on device side
 */
class ManifestValidator {
public:
    /**
     * @brief Create validator with root CA and device private key
     *
     * Validates update certificates against the trusted root CA.
     * Update certificates loaded from PEM bundles internally contain intermediate certificates.
     *
     * Certificate chain verification: update cert (with embedded intermediates) → root CA
     *
     * @param root_ca Trusted root CA certificate (trust anchor)
     * @param device_key Device's private key (X25519) for key unwrapping
     */
    ManifestValidator(
        const crypto::Certificate& root_ca,
        const crypto::PrivateKey& device_key
    );

    ~ManifestValidator();

    /**
     * @brief Set last successfully installed version (anti-rollback protection)
     *
     * Once set, ValidateCertificate() will automatically reject any manifest
     * with version <= last_installed_version. This prevents both rollback
     * attacks AND replay attacks (re-installing the same version).
     *
     * Typical usage:
     * @code
     * // On boot - load persisted version
     * uint64_t last_version = LoadFromFlash("last_installed_version", 0);
     * validator.SetLastInstalledVersion(last_version);
     *
     * // After successful update installation
     * uint64_t new_version = manifest.GetManifestVersion();
     * validator.SetLastInstalledVersion(new_version);
     * PersistToFlash("last_installed_version", new_version);
     * @endcode
     *
     * @param version Last successfully installed manifest version
     */
    void SetLastInstalledVersion(uint64_t version);

    /**
     * @brief Reject certificates issued before timestamp (emergency revocation)
     *
     * Once set, ValidateCertificate() will reject any update certificate whose
     * embedded intermediate was issued before the reject timestamp. This provides
     * emergency revocation without CRL/OCSP infrastructure.
     *
     * When an intermediate CA is compromised:
     * 1. Backend issues new intermediate CA with notBefore = now
     * 2. Backend sends emergency update with reject_timestamp = now
     * 3. Devices reject all certificates with old intermediate
     *
     * Typical usage:
     * @code
     * // On boot - load persisted revocation timestamp
     * int64_t reject_before = LoadFromFlash("reject_certs_before", 0);
     * validator.SetRejectCertificatesBefore(reject_before);
     *
     * // Emergency revocation update received
     * validator.SetRejectCertificatesBefore(emergency_update.timestamp);
     * PersistToFlash("reject_certs_before", emergency_update.timestamp);
     * @endcode
     *
     * @param timestamp Unix epoch seconds - reject certs issued before this time
     */
    void SetRejectCertificatesBefore(int64_t timestamp);

    /**
     * @brief Validate update certificate and extract manifest (RECOMMENDED)
     *
     * This is the primary API for validating secure updates.
     * Verifies certificate signature and extracts verified manifest.
     *
     * Automatically enforces:
     * - Certificate chain validation
     * - Timestamp validation (expiry)
     * - Anti-rollback (if SetLastInstalledVersion called)
     * - Certificate revocation (if SetRejectCertificatesBefore called)
     *
     * @param certificate Update certificate containing manifest
     * @param trusted_time Trusted timestamp for validity check (Unix epoch seconds, REQUIRED - use time(nullptr) for current time)
     * @return Verified manifest
     * @throws CryptoError if certificate verification fails or security policy violated
     */
    Manifest ValidateCertificate(
        const crypto::Certificate& certificate,
        int64_t trusted_time
    );

    /**
     * @brief Verify manifest signature and certificate chain (internal use)
     * @param manifest Manifest to verify
     * @return true if manifest is valid
     */
    bool VerifyManifest(const Manifest& manifest);

    /**
     * @brief Unwrap encryption key for a specific artifact by index
     * @param manifest Manifest containing wrapped keys
     * @param artifact_index Index of the artifact (0-based)
     * @return Unwrapped AES key - automatically zeroized on destruction
     * @throws CryptoError on unwrap failure or invalid index
     */
    crypto::SecureVector<uint8_t> UnwrapEncryptionKey(
        const Manifest& manifest,
        size_t artifact_index
    );

    /**
     * @brief Create streaming decryptor for a specific artifact
     *
     * Use this for large firmware that doesn't fit in RAM.
     * Decrypt in chunks, writing directly to flash storage.
     * IMPORTANT: Tag verification happens in Finalize() - data is not authenticated until then!
     *
     * @param key Unwrapped AES key (from UnwrapEncryptionKey)
     * @param manifest Manifest containing encryption params (including GCM tag)
     * @param artifact_index Index of the artifact (0-based)
     * @return Streaming decryptor
     * @throws CryptoError if invalid index
     */
    std::unique_ptr<crypto::AES128GCM::Decryptor> CreateDecryptor(
        const crypto::SecureVector<uint8_t>& key,
        const Manifest& manifest,
        size_t artifact_index
    );

    /**
     * @brief Verify software signature for a specific artifact
     *
     * Call this after streaming decryption is complete.
     * You must compute the hash incrementally during streaming.
     *
     * @param computed_hash SHA-256 hash of decrypted software (from streaming)
     * @param manifest Manifest containing expected signature
     * @param artifact_index Index of the artifact to verify (0-based)
     * @return true if hash matches and signature is valid
     * @throws CryptoError if invalid index
     */
    bool VerifySignature(
        const std::vector<uint8_t>& computed_hash,
        const Manifest& manifest,
        size_t artifact_index
    );

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace sum

#endif // SUM_VALIDATOR_H
