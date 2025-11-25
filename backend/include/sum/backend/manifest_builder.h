/**
 * @file manifest_builder.h
 * @brief Fluent API for building multi-artifact manifests
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SUM_MANIFEST_BUILDER_H
#define SUM_MANIFEST_BUILDER_H

#include "sum/common/manifest.h"
#include "sum/common/crypto.h"
#include <memory>
#include <vector>
#include <string>
#include <map>
#include <optional>

namespace sum {

/**
 * @brief Pre-encrypted artifact with all crypto parameters
 *
 * This structure holds the result of encrypting firmware once.
 * The same encrypted firmware can be reused for multiple devices
 * by wrapping the AES key differently for each device's public key.
 *
 * Typical workflow:
 * 1. Backend encrypts firmware once: EncryptedArtifact fw = EncryptSoftware(firmware_bin)
 * 2. Store fw.encrypted_data and metadata in database
 * 3. For each device, build manifest with AddArtifact("firmware", fw)
 * 4. BuildCertificate() wraps the AES key for that specific device
 */
struct EncryptedArtifact {
    // Encrypted firmware (store this file, reuse for all devices)
    std::vector<uint8_t> encrypted_data;

    // Encryption parameters (store in database, reuse for all devices)
    std::vector<uint8_t> aes_key;          ///< AES-128 key (16 bytes) - wrap per-device
    std::vector<uint8_t> iv;               ///< GCM IV/nonce (12 bytes)
    std::vector<uint8_t> tag;              ///< GCM authentication tag (16 bytes)

    // Plaintext verification
    std::vector<uint8_t> plaintext_hash;   ///< SHA-256 of plaintext (32 bytes)
    uint64_t plaintext_size;               ///< Size of plaintext in bytes

    // Ciphertext verification
    std::vector<uint8_t> ciphertext_hash;  ///< SHA-256 of encrypted_data (32 bytes)
    uint64_t ciphertext_size;              ///< Size of encrypted_data in bytes
};

/**
 * @brief Encrypt software and capture all crypto parameters
 *
 * Encrypts firmware once using AES-128-GCM and returns all parameters
 * needed for building manifests. The encrypted firmware can be stored
 * and reused for all devices.
 *
 * @param plaintext Software binary data
 * @return EncryptedArtifact with encrypted data and all crypto parameters
 * @throws CryptoError if encryption fails
 */
EncryptedArtifact EncryptSoftware(const std::vector<uint8_t>& plaintext);

/**
 * @brief Fluent API for building multi-artifact secure update manifests
 *
 * Example usage:
 * @code
 * // 1. Encrypt artifacts once (store in database)
 * EncryptedArtifact bootloader_enc = EncryptSoftware(bootloader_bin);
 * EncryptedArtifact firmware_enc = EncryptSoftware(firmware_bin);
 *
 * // 2. Build manifest for device
 * ManifestBuilder builder(backend_key, backend_cert);
 *
 * builder.AddArtifact("bootloader", bootloader_enc)
 *     .SetType("bootloader")
 *     .SetTargetECU("primary")
 *     .SetInstallOrder(0);
 *
 * builder.AddArtifact("firmware", firmware_enc)
 *     .SetType("firmware")
 *     .SetTargetECU("primary")
 *     .SetInstallOrder(1)
 *     .AddSource("http://example.com/firmware.enc", 0);
 *
 * // 3. Build certificate - wraps keys for this specific device
 * auto [cert_pem, encrypted_files] = builder.BuildCertificateChainPEM(
 *     device_pubkey, device_metadata, version
 * );
 * @endcode
 */
class ManifestBuilder {
public:
    /**
     * @brief Artifact builder for fluent API
     */
    class ArtifactBuilder {
    public:
        /**
         * @brief Set artifact type
         * @param type "firmware", "bootloader", "filesystem", "container", etc.
         */
        ArtifactBuilder& SetType(const std::string& type);

        /**
         * @brief Set target ECU/component
         * @param target_ecu "primary", "wifi-coprocessor", "camera", etc.
         */
        ArtifactBuilder& SetTargetECU(const std::string& target_ecu);

        /**
         * @brief Set installation order
         * @param order 0 = first, 1 = second, etc.
         */
        ArtifactBuilder& SetInstallOrder(uint32_t order);

        /**
         * @brief Add download source
         * @param uri Download URI (http://, https://, s3://, ipfs://, file://)
         * @param priority 0 = highest priority (try first), 1 = fallback, etc.
         * @param type Optional hint: "http", "s3", "ipfs", "file"
         */
        ArtifactBuilder& AddSource(
            const std::string& uri,
            uint32_t priority = 0,
            const std::string& type = ""
        );

        /**
         * @brief Enable content-addressable storage
         * @param enabled If true, device can auto-discover by ciphertext_hash
         */
        ArtifactBuilder& SetContentAddressable(bool enabled = true);

        /**
         * @brief Return to parent builder
         */
        ManifestBuilder& Done();

    private:
        friend class ManifestBuilder;
        ArtifactBuilder(ManifestBuilder* parent, const std::string& name, const EncryptedArtifact& encrypted);

        ManifestBuilder* parent_;
        std::string name_;
        EncryptedArtifact encrypted_;
        std::string type_;
        std::string target_ecu_;
        uint32_t install_order_ = 0;
        std::vector<Source> sources_;
        bool content_addressable_ = false;
    };

    /**
     * @brief Create builder with backend signing key and certificate
     * @param backend_key Backend's private key for signing (Ed25519)
     * @param backend_cert Backend's signing certificate (intermediate CA)
     */
    ManifestBuilder(
        const crypto::PrivateKey& backend_key,
        const crypto::Certificate& backend_cert
    );

    ~ManifestBuilder();

    /**
     * @brief Add pre-encrypted artifact to manifest
     *
     * Takes artifact encrypted by EncryptSoftware(). The AES key will be
     * wrapped for the target device when BuildCertificate() is called.
     *
     * @param name Unique identifier ("bootloader", "firmware", "filesystem", etc.)
     * @param encrypted Pre-encrypted artifact from EncryptSoftware()
     * @return Artifact builder for fluent configuration
     */
    ArtifactBuilder& AddArtifact(
        const std::string& name,
        const EncryptedArtifact& encrypted
    );

    /**
     * @brief Set manifest version (user-controlled, for display)
     * @param version Software version number
     */
    ManifestBuilder& SetManifestVersion(uint64_t version);

    /**
     * @brief Set release counter (monotonic, rollback protection)
     * @param counter Release counter (MUST increment, CANNOT skip)
     */
    ManifestBuilder& SetReleaseCounter(uint64_t counter);

    /**
     * @brief Add metadata key-value pair
     * @param key Metadata key
     * @param value Metadata value
     */
    ManifestBuilder& AddMetadata(const std::string& key, const std::string& value);

    /**
     * @brief Build manifest for specific device
     *
     * Wraps all artifact AES keys for the target device's public key.
     *
     * @param device_id Device identifier (for per-device encryption tracking)
     * @param device_pubkey Device's X25519 public key for key wrapping
     * @param version Manifest version (also used as release_counter if not set)
     * @return Pair of (manifest, map of artifact_name -> encrypted_data)
     */
    std::pair<Manifest, std::map<std::string, std::vector<uint8_t>>> Build(
        const std::string& device_id,
        const crypto::PublicKey& device_pubkey,
        uint64_t version
    );

    /**
     * @brief Build and package manifest into X.509 certificate
     *
     * Wraps all artifact AES keys for the target device's public key
     * and embeds manifest in certificate.
     *
     * @param device_pubkey Device's public key for certificate subject and key wrapping
     * @param device_metadata Device identification (hardware_id is REQUIRED)
     * @param version Manifest version (DEPRECATED - use SemVer overload)
     * @param validity_days Certificate validity in days
     * @return Pair of (certificate, map of artifact_name -> encrypted_data)
     */
    std::pair<crypto::Certificate, std::map<std::string, std::vector<uint8_t>>> BuildCertificate(
        const crypto::PublicKey& device_pubkey,
        const DeviceMetadata& device_metadata,
        uint64_t version,
        int validity_days = 90
    );

    /**
     * @brief Build and package manifest into X.509 certificate with semantic versioning
     *
     * @param device_pubkey Device's public key for certificate subject and key wrapping
     * @param device_metadata Device identification (hardware_id is REQUIRED)
     * @param sw_version Semantic software version
     * @param validity_days Certificate validity in days
     * @return Pair of (certificate, map of artifact_name -> encrypted_data)
     */
    std::pair<crypto::Certificate, std::map<std::string, std::vector<uint8_t>>> BuildCertificate(
        const crypto::PublicKey& device_pubkey,
        const DeviceMetadata& device_metadata,
        const SemVer& sw_version,
        int validity_days = 90
    );

    /**
     * @brief Build and package into PEM certificate chain
     *
     * Wraps all artifact AES keys for the target device's public key,
     * embeds manifest in certificate, and creates PEM bundle with intermediate CA.
     *
     * @param device_pubkey Device's public key for certificate subject and key wrapping
     * @param device_metadata Device identification (hardware_id is REQUIRED)
     * @param version Manifest version (DEPRECATED - use SemVer overload)
     * @param validity_days Certificate validity in days
     * @return Pair of (PEM bundle, map of artifact_name -> encrypted_data)
     */
    std::pair<std::string, std::map<std::string, std::vector<uint8_t>>> BuildCertificateChainPEM(
        const crypto::PublicKey& device_pubkey,
        const DeviceMetadata& device_metadata,
        uint64_t version,
        int validity_days = 90
    );

    /**
     * @brief Build and package into PEM certificate chain with semantic versioning
     *
     * @param device_pubkey Device's public key for certificate subject and key wrapping
     * @param device_metadata Device identification (hardware_id is REQUIRED)
     * @param sw_version Semantic software version
     * @param validity_days Certificate validity in days
     * @return Pair of (PEM bundle, map of artifact_name -> encrypted_data)
     */
    std::pair<std::string, std::map<std::string, std::vector<uint8_t>>> BuildCertificateChainPEM(
        const crypto::PublicKey& device_pubkey,
        const DeviceMetadata& device_metadata,
        const SemVer& sw_version,
        int validity_days = 90
    );

private:
    friend class ArtifactBuilder;

    void FinalizeArtifact(ArtifactBuilder&& artifact);

    class Impl;
    std::unique_ptr<Impl> impl_;
    std::optional<ArtifactBuilder> current_artifact_;
};

} // namespace sum

#endif // SUM_MANIFEST_BUILDER_H
