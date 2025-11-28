/**
 * @file manifest.h
 * @brief Secure Update Manifest data structures and operations (Protocol Buffer based)
 *
 * Uptane-inspired security model for embedded systems using Protocol Buffers.
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SUM_MANIFEST_H
#define SUM_MANIFEST_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <optional>

namespace sum {

// Forward declarations
namespace crypto {
    class Certificate;
    class UpdateCertificate;
    class PrivateKey;
    class PublicKey;
}

/**
 * @brief Semantic version (major.minor.patch)
 *
 * Used for compatibility checking:
 * - Major: Incompatible API changes
 * - Minor: Backward-compatible functionality additions
 * - Patch: Backward-compatible bug fixes
 */
struct SemVer {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
    std::string prerelease;      ///< Optional: "alpha", "beta.1", "rc.2"
    std::string build_metadata;  ///< Optional: "20250124", "git.abc123"

    /**
     * @brief Format as string "major.minor.patch[-prerelease][+build]"
     * @return Formatted version string (e.g., "1.2.3-beta.1+git.abc123")
     */
    std::string ToString() const;

    /**
     * @brief Compare with another version (ignoring prerelease/build metadata)
     * @return -1 if this < other, 0 if equal, 1 if this > other
     */
    int Compare(const SemVer& other) const;
};

/**
 * @brief Download source with priority-based fallback
 */
struct Source {
    std::string uri;           ///< URI to fetch artifact (http://, https://, s3://, ipfs://, file://, ca://)
    uint32_t priority;         ///< Priority (0 = highest, try first; 1 = fallback; etc.)
    std::string type;          ///< Optional hint: "http", "s3", "ipfs", "file", "ca"
};

/**
 * @brief Software artifact to be verified/updated
 *
 * Represents a single software component with Uptane-inspired security.
 */
struct SoftwareArtifact {
    // Identification
    std::string name;                      ///< Unique identifier (e.g., "bootloader", "application")
    std::string type;                      ///< Artifact type ("firmware", "bootloader", "filesystem", "container", etc.)
    std::string target_ecu;                ///< Target component ("primary", "wifi-coprocessor", etc.)
    uint32_t install_order;                ///< Installation order (0 = first, 1 = second, etc.)

    // Versioning
    SemVer version;                        ///< Feature version (semantic, can skip/go backwards)
    uint64_t security_version;             ///< Security version (monotonic per artifact, Uptane releaseCounter)

    // Plaintext verification (after decryption)
    std::string hash_algorithm;            ///< "SHA-256" (only supported algorithm)
    std::vector<uint8_t> expected_hash;    ///< Expected hash of decrypted artifact (32 bytes)
    uint64_t size;                         ///< Size of plaintext in bytes

    // Ciphertext verification (for download)
    std::vector<uint8_t> ciphertext_hash;  ///< SHA-256 of encrypted file (for content-addressable storage)
    uint64_t ciphertext_size;              ///< Size of encrypted file (for download progress)

    // Signature
    std::string signature_algorithm;       ///< "Ed25519" (only supported algorithm)
    std::vector<uint8_t> signature;        ///< Ed25519 signature over expected_hash (64 bytes)

    // Source discovery
    std::vector<Source> sources;           ///< Download sources (try in priority order, type determines fetch method)
};

/**
 * @brief Encryption parameters for software artifact
 *
 * Uses AES-128-GCM AEAD + X25519 key wrapping with MANDATORY per-device encryption
 */
struct EncryptionParams {
    std::string artifact_name;             ///< Which artifact this applies to (matches SoftwareArtifact::name)
    std::string device_id;                 ///< NEW: MANDATORY target device identifier (per-device encryption)

    // AES-GCM parameters
    std::string algorithm;                 ///< "AES-128-GCM" (only supported algorithm)
    std::vector<uint8_t> iv;               ///< GCM nonce/IV (12 bytes, stored in manifest NOT in .enc file)
    std::vector<uint8_t> tag;              ///< GCM authentication tag (16 bytes, stored in manifest)

    // Key wrapping (X25519)
    std::string key_wrapping_algorithm;    ///< "X25519-HKDF-SHA256-ChaCha20Poly1305"
    std::vector<uint8_t> wrapped_key;      ///< Wrapped AES-128 key (76 bytes: ephemeral_pubkey||nonce||ciphertext||auth_tag)
};

/**
 * @brief Manifest type (FULL vs PARTIAL/DELTA update)
 */
enum class ManifestType {
    FULL = 0,   ///< Complete system state - all artifacts device should have
    DELTA = 1   ///< Partial update - only changed artifacts
};

/**
 * @brief Secure Update Manifest (Protocol Buffer based)
 *
 * Uptane-inspired security model:
 * - Rollback protection via security_version
 * - Certificate-based integrity protection via X.509 PKI
 * - Per-device encryption
 * - Flexible artifact routing via type/target_ecu
 * - Deterministic installation order
 * - Content-addressable storage support
 */
class Manifest {
public:
    Manifest();
    ~Manifest();

    // Move-only (contains unique resources)
    Manifest(Manifest&&) noexcept;
    Manifest& operator=(Manifest&&) noexcept;
    Manifest(const Manifest&) = delete;
    Manifest& operator=(const Manifest&) = delete;

    // Serialization (Protocol Buffer)

    /**
     * @brief Load manifest from Protocol Buffer binary data
     *
     * This is used to parse manifest data extracted from certificate extensions.
     *
     * @param data Protobuf-encoded manifest
     * @return Loaded manifest
     * @throws std::runtime_error on parse error
     */
    static Manifest LoadFromProtobuf(const std::vector<uint8_t>& data);

    /**
     * @brief Export manifest to Protocol Buffer binary data
     *
     * This is used when creating certificates with CreateCertificateWithManifest().
     *
     * @return Protobuf-encoded manifest data
     */
    std::vector<uint8_t> ToProtobuf() const;

    /**
     * @brief Export manifest to Protocol Buffer for signing/verification
     *
     * Serializes manifest WITHOUT the signature field. This is used for
     * signature generation and verification to avoid circular logic.
     *
     * @return Protobuf-encoded manifest data (without signature)
     */
    std::vector<uint8_t> ToProtobufForSigning() const;

    /**
     * @brief Export manifest to JSON string (for debugging/inspection)
     *
     * Human-readable JSON export for development and debugging.
     * NOT used for wire format (protobuf is wire format).
     *
     * @return JSON string representation
     */
    std::string ToDebugJSON() const;

    // Accessors

    /**
     * @brief Get manifest schema version (protocol version)
     * @return Format version (currently always 1)
     */
    uint32_t GetVersion() const;

    /**
     * @brief Get metadata sequence number (ordering, replay protection)
     *
     * Monotonic counter tracking when manifest was issued (Uptane/TUF "version" field).
     * Used for manifest ordering and replay attack prevention.
     * MUST increment with each manifest (even A/B variants).
     *
     * @return Metadata sequence number
     */
    uint64_t GetManifestVersion() const;

    /**
     * @brief Get manifest type (FULL or PARTIAL/DELTA)
     *
     * Indicates whether this is a complete system state (FULL) or
     * a partial update containing only changed artifacts (DELTA).
     *
     * @return Manifest type
     */
    ManifestType GetType() const;

    const std::vector<SoftwareArtifact>& GetArtifacts() const;
    const std::vector<EncryptionParams>& GetEncryptionParams() const;
    const std::vector<uint8_t>& GetSignature() const;
    const std::vector<uint8_t>& GetSigningCertificate() const;
    std::optional<std::string> GetMetadata(const std::string& key) const;

    /**
     * @brief Find artifact by name
     * @param name Artifact name
     * @return Pointer to artifact, or nullptr if not found
     */
    const SoftwareArtifact* GetArtifactByName(const std::string& name) const;

    /**
     * @brief Find artifact index by name
     * @param name Artifact name
     * @return Artifact index, or nullopt if not found
     */
    std::optional<size_t> GetArtifactIndex(const std::string& name) const;

    /**
     * @brief Find encryption params for specific artifact and device
     * @param artifact_name Artifact name
     * @param device_id Device identifier
     * @return Pointer to encryption params, or nullptr if not found
     */
    const EncryptionParams* GetEncryptionParamsFor(
        const std::string& artifact_name,
        const std::string& device_id
    ) const;

    // Mutators (for building manifests)

    void SetManifestVersion(uint64_t version);
    void AddArtifact(SoftwareArtifact artifact);
    void AddEncryptionParams(EncryptionParams params);
    void SetSignature(const std::vector<uint8_t>& signature);
    void SetSigningCertificate(const std::vector<uint8_t>& cert);
    void SetMetadata(const std::string& key, const std::string& value);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Artifact information (what an update provides)
 *
 * Duplicates key fields from SoftwareArtifact for unverified filtering.
 * Used by workshop to see what will be installed without decryption.
 */
struct ArtifactInfo {
    std::string name;              ///< Artifact identifier
    std::string type;              ///< Artifact type
    std::string target_ecu;        ///< Target ECU
    uint64_t security_version;     ///< Security version this update provides
    SemVer version;                ///< Feature version (optional, for display)
};

/**
 * @brief Artifact constraint (what an update requires from device)
 *
 * Used by workshop to determine safe upgrade path without decryption.
 */
struct ArtifactConstraint {
    std::string name;              ///< Artifact identifier
    std::string type;              ///< Artifact type
    std::string target_ecu;        ///< Target ECU
    uint64_t min_security_version; ///< Minimum required on device (inclusive)
    uint64_t max_security_version; ///< Maximum supported (inclusive, 0 = no limit)
};

/**
 * @brief Device metadata for X.509 certificate
 *
 * This metadata is embedded in the certificate and is readable without
 * any encryption keys. It allows devices to quickly identify if an update
 * is intended for them before decrypting anything.
 *
 * The hardware_id is the critical field that links this update to a specific
 * device's public key in the backend database.
 *
 * SECURITY: This data is UNVERIFIED (readable without signature check).
 * Used for filtering and operational decisions only.
 * Device MUST use verified manifest data for security decisions.
 */
struct DeviceMetadata {
    std::string hardware_id;       ///< REQUIRED: Unique device identifier (serial/UUID) - backend uses this to lookup device public key
    std::string manufacturer;      ///< Manufacturer name (e.g., "Acme Corp")
    std::string device_type;       ///< Device model/type (e.g., "ESP32-Gateway")
    std::string hardware_version;  ///< Hardware revision (e.g., "v2.1", optional)

    // Artifact constraints (what device needs for safe installation)
    std::vector<ArtifactConstraint> requires;  ///< Device state requirements

    /**
     * @brief Load device metadata from Protocol Buffer binary data
     * @param data Protobuf-encoded device metadata
     * @return Loaded device metadata
     * @throws std::runtime_error on parse error
     */
    static DeviceMetadata FromProtobuf(const std::vector<uint8_t>& data);

    /**
     * @brief Export device metadata to Protocol Buffer binary data
     * @return Protobuf-encoded device metadata data
     */
    std::vector<uint8_t> ToProtobuf() const;
};

/**
 * @brief Create CA certificate (root or intermediate)
 *
 * Creates a Certificate Authority certificate for the 3-tier PKI architecture.
 * - If issuer_cert is nullptr: creates self-signed root CA
 * - If issuer_cert is provided: creates intermediate CA signed by issuer
 *
 * CA certificates have:
 * - keyUsage: keyCertSign, cRLSign (critical)
 * - basicConstraints: CA:TRUE (critical)
 * - No update-specific extensions (no manifest, no device metadata)
 *
 * @param signing_key Private key for signing (for root CA: same as subject key)
 * @param subject_pubkey Public key for the CA being created
 * @param subject_name Certificate subject CN (e.g., "Root CA", "Intermediate CA")
 * @param validity_days Certificate validity period in days (default: 10 years for CA)
 * @param issuer_cert Optional issuer certificate (nullptr = self-signed root CA)
 * @return CA certificate
 */
crypto::Certificate CreateCACertificate(
    const crypto::PrivateKey& signing_key,
    const crypto::PublicKey& subject_pubkey,
    const std::string& subject_name,
    int validity_days = 3650,
    const crypto::Certificate* issuer_cert = nullptr
);

/**
 * @brief Create end-entity certificate (for testing)
 *
 * Creates a simple end-entity certificate without update-specific extensions.
 * Primarily used for testing certificate chain validation logic.
 *
 * For production update certificates with manifest and device metadata,
 * use CreateUpdateCertificate() instead.
 *
 * End-entity certificates have:
 * - keyUsage: digitalSignature (critical)
 * - basicConstraints: CA:FALSE (critical)
 * - No update-specific extensions (no manifest, no device metadata)
 *
 * @param signing_key Issuer's private key for signing (typically intermediate CA, or same as subject key for self-signed)
 * @param subject_pubkey Public key for the end-entity certificate
 * @param subject_name Certificate subject CN (e.g., "End Entity", "Test Certificate")
 * @param validity_days Certificate validity period in days (default: 1 year)
 * @param issuer_cert Optional issuer certificate (CA that signs this certificate, nullptr for self-signed)
 * @return End-entity certificate
 */
crypto::Certificate CreateEndEntityCertificate(
    const crypto::PrivateKey& signing_key,
    const crypto::PublicKey& subject_pubkey,
    const std::string& subject_name,
    int validity_days = 365,
    const crypto::Certificate* issuer_cert = nullptr
);

/**
 * @brief Create update certificate with embedded manifest and device metadata
 *
 * Creates an UpdateCertificate (3-tier PKI) that embeds:
 * - Device metadata (readable without keys) - allows quick filtering
 * - Secure update manifest (signed, contains encrypted content)
 * - Intermediate CA certificate for chain verification
 *
 * The hardware_id in device_metadata must match the device's public key
 * in the backend database. This is how the backend knows which public key
 * to use for encrypting the update.
 *
 * This enables offline distribution: the certificate is the only file needed.
 *
 * Opinionated: This ALWAYS creates an update certificate with intermediate CA.
 * The intermediate_cert parameter is required and must not be self-signed.
 *
 * @param manifest Manifest to embed in certificate
 * @param signing_key Intermediate CA private key for signing
 * @param subject_pubkey Device public key for certificate subject
 * @param device_metadata Device identification (hardware_id is REQUIRED)
 * @param intermediate_cert Intermediate CA certificate (REQUIRED, must not be self-signed)
 * @param subject_name Certificate subject CN
 * @param validity_days Certificate validity in days
 * @return UpdateCertificate with embedded manifest, metadata, and intermediate
 * @throws CryptoError if intermediate_cert is self-signed
 */
crypto::UpdateCertificate CreateUpdateCertificate(
    const Manifest& manifest,
    const crypto::PrivateKey& signing_key,
    const crypto::PublicKey& subject_pubkey,
    const DeviceMetadata& device_metadata,
    const crypto::Certificate& intermediate_cert,
    const std::string& subject_name = "Secure Update Manifest",
    int validity_days = 365
);

/**
 * @brief Create certificate with embedded manifest (legacy/testing API)
 *
 * This is a lower-level API primarily used for testing. For production use,
 * prefer CreateCACertificate for CA certs or CreateUpdateCertificate for update certs.
 *
 * @param manifest Manifest to embed
 * @param signing_key Private key for signing
 * @param subject_pubkey Subject public key
 * @param device_metadata Device metadata
 * @param subject_name Certificate subject name
 * @param validity_days Validity period in days (default: 365)
 * @param issuer_cert Issuer certificate (nullptr for self-signed)
 * @return Certificate with embedded manifest and metadata
 */
crypto::Certificate CreateCertificateWithManifest(
    const Manifest& manifest,
    const crypto::PrivateKey& signing_key,
    const crypto::PublicKey& subject_pubkey,
    const DeviceMetadata& device_metadata,
    const std::string& subject_name = "Test Certificate",
    int validity_days = 365,
    const crypto::Certificate* issuer_cert = nullptr
);

} // namespace sum

#endif // SUM_MANIFEST_H
