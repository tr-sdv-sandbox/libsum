/**
 * @file manifest_builder.cpp
 * @brief Implementation of fluent API for building multi-artifact manifests
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum/backend/manifest_builder.h"
#include "sum/common/crypto.h"
#include "sum/common/limits.h"
#include <glog/logging.h>
#include <stdexcept>
#include <map>
#include <openssl/rand.h>

namespace sum {

// Standalone function: Encrypt software once
EncryptedArtifact EncryptSoftware(const std::vector<uint8_t>& plaintext) {
    EncryptedArtifact result;

    // Generate AES-GCM key and IV
    result.aes_key.resize(crypto::AES_128_KEY_SIZE);
    result.iv.resize(crypto::AES_GCM_IV_SIZE);

    if (RAND_bytes(result.aes_key.data(), result.aes_key.size()) != 1) {
        throw crypto::CryptoError("Failed to generate AES key");
    }
    if (RAND_bytes(result.iv.data(), result.iv.size()) != 1) {
        throw crypto::CryptoError("Failed to generate IV");
    }

    // Encrypt with AES-GCM
    auto gcm_result = crypto::AES128GCM::Encrypt(result.aes_key, result.iv, plaintext);
    result.encrypted_data = std::move(gcm_result.ciphertext);
    result.tag = std::move(gcm_result.tag);

    // Calculate hashes
    result.plaintext_hash = crypto::SHA256::Hash(plaintext);
    result.plaintext_size = plaintext.size();
    result.ciphertext_hash = crypto::SHA256::Hash(result.encrypted_data);
    result.ciphertext_size = result.encrypted_data.size();

    LOG(INFO) << "Encrypted software: " << plaintext.size() << " bytes -> "
              << result.encrypted_data.size() << " bytes";

    return result;
}

// Internal artifact representation
struct PendingArtifact {
    std::string name;
    EncryptedArtifact encrypted;
    std::string type;
    std::string target_ecu;
    uint32_t install_order;
    std::vector<Source> sources;

    // Versioning
    SemVer version;                  // Feature version
    uint64_t security_version = 0;   // Security/rollback protection
};

// ManifestBuilder implementation
class ManifestBuilder::Impl {
public:
    Impl(const crypto::PrivateKey& backend_key, const crypto::Certificate& backend_cert)
        : backend_key_(backend_key)
        , backend_cert_(backend_cert)
        , manifest_version_(0)
    {}

    const crypto::PrivateKey& backend_key_;
    const crypto::Certificate& backend_cert_;
    std::vector<PendingArtifact> artifacts_;
    uint64_t manifest_version_;
    std::map<std::string, std::string> metadata_;
};

ManifestBuilder::ManifestBuilder(
    const crypto::PrivateKey& backend_key,
    const crypto::Certificate& backend_cert
)
    : impl_(std::make_unique<Impl>(backend_key, backend_cert))
{}

ManifestBuilder::~ManifestBuilder() = default;

ManifestBuilder::ArtifactBuilder& ManifestBuilder::AddArtifact(
    const std::string& name,
    const EncryptedArtifact& encrypted
) {
    // Finalize previous artifact if exists
    if (current_artifact_) {
        FinalizeArtifact(std::move(*current_artifact_));
        current_artifact_ = std::nullopt;
    }

    current_artifact_ = ArtifactBuilder(this, name, encrypted);
    return *current_artifact_;
}

ManifestBuilder& ManifestBuilder::SetManifestVersion(uint64_t version) {
    impl_->manifest_version_ = version;
    return *this;
}

ManifestBuilder& ManifestBuilder::AddMetadata(const std::string& key, const std::string& value) {
    impl_->metadata_[key] = value;
    return *this;
}

void ManifestBuilder::FinalizeArtifact(ArtifactBuilder&& artifact) {
    // Validate artifact count
    if (impl_->artifacts_.size() >= limits::MAX_ARTIFACTS) {
        throw std::runtime_error("Too many artifacts (max " + std::to_string(limits::MAX_ARTIFACTS) + ")");
    }

    // Validate string lengths
    if (artifact.name_.size() > limits::MAX_ARTIFACT_NAME) {
        throw std::runtime_error("Artifact name too long (max " + std::to_string(limits::MAX_ARTIFACT_NAME) + ")");
    }
    if (artifact.type_.size() > limits::MAX_ARTIFACT_TYPE) {
        throw std::runtime_error("Artifact type too long (max " + std::to_string(limits::MAX_ARTIFACT_TYPE) + ")");
    }
    if (artifact.target_ecu_.size() > limits::MAX_TARGET_ECU) {
        throw std::runtime_error("Target ECU too long (max " + std::to_string(limits::MAX_TARGET_ECU) + ")");
    }

    // Validate source count and URIs
    if (artifact.sources_.size() > limits::MAX_SOURCES_PER_ARTIFACT) {
        throw std::runtime_error("Too many sources (max " + std::to_string(limits::MAX_SOURCES_PER_ARTIFACT) + ")");
    }
    for (const auto& source : artifact.sources_) {
        if (source.uri.size() > limits::MAX_SOURCE_URI) {
            throw std::runtime_error("Source URI too long (max " + std::to_string(limits::MAX_SOURCE_URI) + ")");
        }
    }

    PendingArtifact pending;
    pending.name = std::move(artifact.name_);
    pending.encrypted = std::move(artifact.encrypted_);
    pending.type = std::move(artifact.type_);
    pending.target_ecu = std::move(artifact.target_ecu_);
    pending.install_order = artifact.install_order_;
    pending.sources = std::move(artifact.sources_);
    pending.version = artifact.version_;
    pending.security_version = artifact.security_version_;

    impl_->artifacts_.push_back(std::move(pending));
}

std::pair<Manifest, std::map<std::string, std::vector<uint8_t>>>
ManifestBuilder::Build(
    const std::string& device_id,
    const crypto::PublicKey& device_pubkey,
    uint64_t manifest_version
) {
    // Finalize current artifact if exists
    if (current_artifact_) {
        FinalizeArtifact(std::move(*current_artifact_));
        current_artifact_ = std::nullopt;
    }

    // Validate device_id
    if (device_id.size() > limits::MAX_DEVICE_ID) {
        throw std::runtime_error("Device ID too long (max " + std::to_string(limits::MAX_DEVICE_ID) + ")");
    }

    if (impl_->artifacts_.empty()) {
        throw std::runtime_error("Cannot build manifest with no artifacts");
    }

    Manifest manifest;
    manifest.SetManifestVersion(manifest_version);

    // Add metadata
    for (const auto& [key, value] : impl_->metadata_) {
        manifest.SetMetadata(key, value);
    }

    // Map to store encrypted artifacts (reuse pre-encrypted data)
    std::map<std::string, std::vector<uint8_t>> encrypted_files;

    // Process each artifact
    for (const auto& pending : impl_->artifacts_) {
        LOG(INFO) << "Processing artifact: " << pending.name;

        // Create SoftwareArtifact from pre-encrypted data
        SoftwareArtifact artifact;
        artifact.name = pending.name;
        artifact.type = pending.type.empty() ? "firmware" : pending.type;
        artifact.target_ecu = pending.target_ecu.empty() ? "primary" : pending.target_ecu;
        artifact.install_order = pending.install_order;

        // Versioning
        artifact.version = pending.version;
        artifact.security_version = pending.security_version;

        artifact.hash_algorithm = "SHA-256";
        artifact.signature_algorithm = "Ed25519";
        artifact.sources = pending.sources;

        // Copy pre-calculated hashes and sizes
        artifact.expected_hash = pending.encrypted.plaintext_hash;
        artifact.size = pending.encrypted.plaintext_size;
        artifact.ciphertext_hash = pending.encrypted.ciphertext_hash;
        artifact.ciphertext_size = pending.encrypted.ciphertext_size;

        // Sign the plaintext hash
        artifact.signature = crypto::Ed25519::Sign(impl_->backend_key_, artifact.expected_hash);

        // Wrap AES key for this specific device
        LOG(INFO) << "  Wrapping key for device: " << device_id;
        std::vector<uint8_t> wrapped_key = crypto::X25519::WrapKey(pending.encrypted.aes_key, device_pubkey);

        // Create encryption params
        EncryptionParams enc_params;
        enc_params.artifact_name = pending.name;
        enc_params.device_id = device_id;
        enc_params.algorithm = "AES-128-GCM";
        enc_params.iv = pending.encrypted.iv;
        enc_params.tag = pending.encrypted.tag;
        enc_params.key_wrapping_algorithm = "X25519-HKDF-SHA256-ChaCha20Poly1305";
        enc_params.wrapped_key = wrapped_key;

        manifest.AddEncryptionParams(std::move(enc_params));
        manifest.AddArtifact(std::move(artifact));

        // Reuse pre-encrypted data (same for all devices!)
        encrypted_files[pending.name] = pending.encrypted.encrypted_data;
    }

    // Set signing certificate in manifest (required for verification)
    manifest.SetSigningCertificate(impl_->backend_cert_.ToDER());

    // Sign manifest: serialize WITHOUT signature field, then sign and set signature
    auto manifest_protobuf = manifest.ToProtobufForSigning();
    auto signature = crypto::Ed25519::Sign(impl_->backend_key_, manifest_protobuf);
    manifest.SetSignature(signature);

    LOG(INFO) << "Manifest built with " << impl_->artifacts_.size() << " artifacts for device: " << device_id;

    return {std::move(manifest), std::move(encrypted_files)};
}

std::pair<crypto::Certificate, std::map<std::string, std::vector<uint8_t>>>
ManifestBuilder::BuildCertificate(
    const crypto::PublicKey& device_pubkey,
    const DeviceMetadata& device_metadata,
    uint64_t manifest_version,
    int validity_days
) {
    // Use hardware_id as device_id
    auto [manifest, encrypted_files] = Build(device_metadata.hardware_id, device_pubkey, manifest_version);

    // Populate device metadata with operational fields for workshop filtering
    DeviceMetadata augmented_metadata = device_metadata;
    augmented_metadata.manifest_version = manifest_version;
    augmented_metadata.manifest_type = ManifestType::FULL;  // TODO: Support DELTA when implemented

    // Populate provides (what this update installs)
    for (const auto& pending : impl_->artifacts_) {
        ArtifactInfo info;
        info.name = pending.name;
        info.type = pending.type;
        info.target_ecu = pending.target_ecu;
        info.security_version = pending.security_version;
        info.version = pending.version;
        augmented_metadata.provides.push_back(info);
    }

    // TODO: Populate requires when prerequisites are implemented
    // For now, requires is empty (no constraints)

    // CreateCertificateWithManifest automatically embeds intermediate when issuer is not self-signed
    auto cert = CreateCertificateWithManifest(
        manifest,
        impl_->backend_key_,
        device_pubkey,
        augmented_metadata,
        "Secure Update Manifest",
        validity_days,
        &impl_->backend_cert_  // Intermediate CA - will be auto-embedded
    );

    return {std::move(cert), std::move(encrypted_files)};
}

std::pair<std::string, std::map<std::string, std::vector<uint8_t>>>
ManifestBuilder::BuildCertificateChainPEM(
    const crypto::PublicKey& device_pubkey,
    const DeviceMetadata& device_metadata,
    uint64_t manifest_version,
    int validity_days
) {
    auto [cert, encrypted_files] = BuildCertificate(device_pubkey, device_metadata, manifest_version, validity_days);

    // Convert to PEM and bundle with intermediate cert
    std::string update_pem = cert.ToPEM();
    std::string intermediate_pem = impl_->backend_cert_.ToPEM();
    std::string pem_bundle = update_pem + intermediate_pem;

    return {std::move(pem_bundle), std::move(encrypted_files)};
}

// ArtifactBuilder implementation
ManifestBuilder::ArtifactBuilder::ArtifactBuilder(
    ManifestBuilder* parent,
    const std::string& name,
    const EncryptedArtifact& encrypted
)
    : parent_(parent)
    , name_(name)
    , encrypted_(encrypted)
    , install_order_(0)
{}

ManifestBuilder::ArtifactBuilder&
ManifestBuilder::ArtifactBuilder::SetType(const std::string& type) {
    type_ = type;
    return *this;
}

ManifestBuilder::ArtifactBuilder&
ManifestBuilder::ArtifactBuilder::SetTargetECU(const std::string& target_ecu) {
    target_ecu_ = target_ecu;
    return *this;
}

ManifestBuilder::ArtifactBuilder&
ManifestBuilder::ArtifactBuilder::SetInstallOrder(uint32_t order) {
    install_order_ = order;
    return *this;
}

ManifestBuilder::ArtifactBuilder&
ManifestBuilder::ArtifactBuilder::AddSource(
    const std::string& uri,
    uint32_t priority,
    const std::string& type
) {
    Source source;
    source.uri = uri;
    source.priority = priority;
    source.type = type;
    sources_.push_back(std::move(source));
    return *this;
}

ManifestBuilder::ArtifactBuilder&
ManifestBuilder::ArtifactBuilder::SetVersion(const SemVer& version) {
    version_ = version;
    return *this;
}

ManifestBuilder::ArtifactBuilder&
ManifestBuilder::ArtifactBuilder::SetSecurityVersion(uint64_t security_version) {
    security_version_ = security_version;
    return *this;
}

ManifestBuilder& ManifestBuilder::ArtifactBuilder::Done() {
    return *parent_;
}

} // namespace sum
