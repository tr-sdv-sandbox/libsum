/**
 * @file generator.h
 * @brief Manifest generation and software encryption
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SUM_GENERATOR_H
#define SUM_GENERATOR_H

#include "sum/common/manifest.h"
#include "sum/common/crypto.h"
#include <memory>
#include <vector>
#include <utility>

namespace sum {

/**
 * @brief Generates signed manifests with encrypted software
 */
class ManifestGenerator {
public:
    /**
     * @brief Create generator with backend signing key and certificate
     *
     * For production PKI hierarchy, use intermediate CA credentials:
     * - backend_key: Intermediate CA private key (online HSM)
     * - backend_cert: Intermediate CA certificate (signed by root CA)
     *
     * The intermediate CA certificate will be bundled with update certificates
     * in PEM format for certificate chain validation.
     *
     * @param backend_key Backend's private key for signing (intermediate CA in production)
     * @param backend_cert Backend's signing certificate (intermediate CA in production)
     */
    ManifestGenerator(
        const crypto::PrivateKey& backend_key,
        const crypto::Certificate& backend_cert
    );

    ~ManifestGenerator();

    /**
     * @brief Create update certificate for software (RECOMMENDED)
     *
     * This is the primary API for creating secure update packages.
     * Returns a certificate containing the manifest and device metadata.
     *
     * @param software Software binary data
     * @param device_pubkey Device's public key for key wrapping and certificate
     * @param device_metadata Device identification (hardware_id is REQUIRED)
     * @param version Software version number (DEPRECATED - use SemVer overload)
     * @param use_encryption Enable encryption (default: true)
     * @param validity_days Certificate validity in days (default: 90)
     * @param artifact_url Optional URL for OTA streaming download
     * @return Pair of (update_certificate, encrypted_software)
     */
    std::pair<crypto::Certificate, std::vector<uint8_t>> CreateCertificate(
        const std::vector<uint8_t>& software,
        const crypto::PublicKey& device_pubkey,
        const DeviceMetadata& device_metadata,
        uint64_t version,
        bool use_encryption = true,
        int validity_days = 90,
        const std::string& artifact_url = ""
    );

    /**
     * @brief Create update certificate for software with semantic versioning
     *
     * @param software Software binary data
     * @param device_pubkey Device's public key for key wrapping and certificate
     * @param device_metadata Device identification (hardware_id is REQUIRED)
     * @param sw_version Semantic software version
     * @param use_encryption Enable encryption (default: true)
     * @param validity_days Certificate validity in days (default: 90)
     * @param artifact_url Optional URL for OTA streaming download
     * @return Pair of (update_certificate, encrypted_software)
     */
    std::pair<crypto::Certificate, std::vector<uint8_t>> CreateCertificate(
        const std::vector<uint8_t>& software,
        const crypto::PublicKey& device_pubkey,
        const DeviceMetadata& device_metadata,
        const SemVer& sw_version,
        bool use_encryption = true,
        int validity_days = 90,
        const std::string& artifact_url = ""
    );

    /**
     * @brief Create certificate chain PEM bundle (PRODUCTION BEST PRACTICE)
     *
     * Creates a PEM bundle containing both the update certificate and the
     * signing certificate (intermediate CA). This is standard PKI practice.
     * The PEM bundle can be distributed as a single file.
     *
     * @param software Software binary data
     * @param device_pubkey Device's public key for key wrapping
     * @param device_metadata Device identification (hardware_id is REQUIRED)
     * @param version Software version number (DEPRECATED - use SemVer overload)
     * @param use_encryption Enable encryption (default: true)
     * @param validity_days Certificate validity in days (default: 90)
     * @param artifact_url Optional URL for OTA streaming download
     * @return Pair of (PEM_chain_bundle, encrypted_software)
     */
    std::pair<std::string, std::vector<uint8_t>> CreateCertificateChainPEM(
        const std::vector<uint8_t>& software,
        const crypto::PublicKey& device_pubkey,
        const DeviceMetadata& device_metadata,
        uint64_t version,
        bool use_encryption = true,
        int validity_days = 90,
        const std::string& artifact_url = ""
    );

    /**
     * @brief Create certificate chain PEM bundle with semantic versioning
     *
     * @param software Software binary data
     * @param device_pubkey Device's public key for key wrapping
     * @param device_metadata Device identification (hardware_id is REQUIRED)
     * @param sw_version Semantic software version
     * @param use_encryption Enable encryption (default: true)
     * @param validity_days Certificate validity in days (default: 90)
     * @param artifact_url Optional URL for OTA streaming download
     * @return Pair of (PEM_chain_bundle, encrypted_software)
     */
    std::pair<std::string, std::vector<uint8_t>> CreateCertificateChainPEM(
        const std::vector<uint8_t>& software,
        const crypto::PublicKey& device_pubkey,
        const DeviceMetadata& device_metadata,
        const SemVer& sw_version,
        bool use_encryption = true,
        int validity_days = 90,
        const std::string& artifact_url = ""
    );

    /**
     * @brief Create manifest for software update (internal use)
     *
     * This method creates a manifest in memory without packaging into certificate.
     * Use CreateCertificate() instead for production deployments.
     *
     * @param software Software binary data
     * @param device_pubkey Device's public key for key wrapping
     * @param version Software version number
     * @param use_encryption Enable encryption (default: true)
     * @param artifact_url Optional URL for OTA streaming download
     * @return Pair of (manifest, encrypted_software)
     */
    std::pair<Manifest, std::vector<uint8_t>> Create(
        const std::vector<uint8_t>& software,
        const crypto::PublicKey& device_pubkey,
        uint64_t version,
        bool use_encryption = true,
        const std::string& artifact_url = ""
    );

    /**
     * @brief Encrypt software with AES-128-CTR
     * @param software Software data to encrypt
     * @param key AES key (generated if empty)
     * @param iv IV (generated if empty)
     * @return Encrypted software
     */
    std::vector<uint8_t> EncryptSoftware(
        const std::vector<uint8_t>& software,
        std::vector<uint8_t>& key,
        std::vector<uint8_t>& iv
    );

    /**
     * @brief Wrap AES key with device public key using ECIES
     * @param key AES key to wrap
     * @param device_pubkey Device's public key
     * @return ECIES-wrapped key
     */
    std::vector<uint8_t> WrapKey(
        const std::vector<uint8_t>& key,
        const crypto::PublicKey& device_pubkey
    );

    /**
     * @brief Sign manifest with backend private key
     * @param manifest Manifest to sign
     */
    void SignManifest(Manifest& manifest);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace sum

#endif // SUM_GENERATOR_H
