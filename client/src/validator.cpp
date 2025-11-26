/**
 * @file validator.cpp
 * @brief Manifest validation and software decryption
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum/client/validator.h"
#include "sum/common/crypto.h"
#include <ctime>

namespace sum {

class ManifestValidator::Impl {
public:
    crypto::Certificate backend_ca;  // Root CA (trust anchor)
    crypto::PrivateKey device_key;

    // Security policies
    uint64_t last_installed_version = 0;  // Anti-rollback/replay protection
    int64_t reject_certs_before = 0;      // Timestamp-based revocation

    Impl(const crypto::Certificate& ca, const crypto::PrivateKey& key)
        : backend_ca(crypto::Certificate::LoadFromDER(ca.ToDER()))
        , device_key(crypto::PrivateKey::LoadFromPEM(key.ToPEM())) {}
};

ManifestValidator::ManifestValidator(
    const crypto::Certificate& root_ca,
    const crypto::PrivateKey& device_key
) : impl_(std::make_unique<Impl>(root_ca, device_key)) {}

ManifestValidator::~ManifestValidator() = default;

void ManifestValidator::SetLastInstalledVersion(uint64_t version) {
    impl_->last_installed_version = version;
}

void ManifestValidator::SetRejectCertificatesBefore(int64_t timestamp) {
    impl_->reject_certs_before = timestamp;
}

bool ManifestValidator::VerifyManifest(const Manifest& manifest) {
    // Get manifest signature
    const auto& signature = manifest.GetSignature();
    if (signature.empty()) {
        return false;
    }

    // Get signing certificate
    const auto& cert_der = manifest.GetSigningCertificate();
    if (cert_der.empty()) {
        return false;
    }

    // Load signing certificate
    crypto::Certificate signing_cert = crypto::Certificate::LoadFromDER(cert_der);

    // Verify certificate chain (signed by backend CA) using current time
    if (!signing_cert.VerifyChain(impl_->backend_ca, time(nullptr))) {
        return false;
    }

    // Get public key from signing certificate
    crypto::PublicKey signing_pubkey = signing_cert.GetPublicKey();

    // Verify manifest signature (serialize WITHOUT signature field)
    auto manifest_protobuf = manifest.ToProtobufForSigning();

    try {
        return crypto::Ed25519::Verify(signing_pubkey, manifest_protobuf, signature);
    } catch (const crypto::SignatureVerificationError&) {
        return false;
    }
}

Manifest ManifestValidator::ValidateCertificate(
    const crypto::Certificate& certificate,
    int64_t trusted_time
) {
    std::vector<uint8_t> manifest_data;

    // Step 1: Check intermediate certificate revocation (timestamp-based)
    // SECURITY: Check BEFORE validation to avoid wasting CPU on revoked certs
    if (impl_->reject_certs_before > 0) {
        try {
            int64_t intermediate_issuance = certificate.GetIntermediateIssuanceTime();
            if (intermediate_issuance < impl_->reject_certs_before) {
                throw crypto::CryptoError(
                    "Intermediate certificate revoked: issued at " + std::to_string(intermediate_issuance) +
                    " which is before revocation timestamp " + std::to_string(impl_->reject_certs_before)
                );
            }
        } catch (const crypto::CryptoError& e) {
            std::string msg = e.what();
            // Re-throw if this is the revocation error
            if (msg.find("revoked") != std::string::npos) {
                throw;
            }
            // Otherwise, it's "No intermediate certificate embedded" or "Expected exactly 1"
            // GetVerifiedManifest will handle validation (cert is likely invalid anyway)
        }
    }

    // Step 2: Verify certificate chain and extract verified manifest
    // Certificate uses internally stored intermediates from PEM bundle
    manifest_data = certificate.GetVerifiedManifest(impl_->backend_ca, trusted_time);

    // Step 3: Parse manifest from verified protobuf
    auto manifest = Manifest::LoadFromProtobuf(manifest_data);

    // Step 4: Anti-rollback/replay protection
    // SECURITY: Reject if version <= last installed (prevents both rollback AND replay)
    if (impl_->last_installed_version > 0) {
        uint64_t manifest_version = manifest.GetManifestVersion();
        if (manifest_version <= impl_->last_installed_version) {
            throw crypto::CryptoError(
                "Anti-rollback/replay: manifest version " + std::to_string(manifest_version) +
                " <= last installed version " + std::to_string(impl_->last_installed_version)
            );
        }
    }

    // Step 5: Return verified manifest
    return manifest;
}

crypto::SecureVector<uint8_t> ManifestValidator::UnwrapEncryptionKey(
    const Manifest& manifest,
    size_t artifact_index
) {
    auto artifacts = manifest.GetArtifacts();
    if (artifact_index >= artifacts.size()) {
        throw crypto::CryptoError("Invalid artifact index: " + std::to_string(artifact_index));
    }

    auto encryption_params = manifest.GetEncryptionParams();
    if (encryption_params.empty()) {
        throw crypto::CryptoError("No encryption parameters in manifest");
    }

    // Find encryption params matching this artifact's name
    const auto& artifact = artifacts[artifact_index];
    const EncryptionParams* matching_params = nullptr;

    for (const auto& params : encryption_params) {
        if (params.artifact_name == artifact.name) {
            matching_params = &params;
            break;
        }
    }

    if (!matching_params) {
        throw crypto::CryptoError("No encryption parameters found for artifact: " + artifact.name);
    }

    // Unwrap the key using X25519 key agreement
    return crypto::X25519::UnwrapKey(matching_params->wrapped_key, impl_->device_key);
}

std::unique_ptr<crypto::AES128GCM::Decryptor> ManifestValidator::CreateDecryptor(
    const crypto::SecureVector<uint8_t>& key,
    const Manifest& manifest,
    size_t artifact_index
) {
    auto artifacts = manifest.GetArtifacts();
    if (artifact_index >= artifacts.size()) {
        throw crypto::CryptoError("Invalid artifact index: " + std::to_string(artifact_index));
    }

    auto encryption_params = manifest.GetEncryptionParams();
    if (encryption_params.empty()) {
        throw crypto::CryptoError("No encryption parameters in manifest");
    }

    // Find encryption params matching this artifact's name
    const auto& artifact = artifacts[artifact_index];
    const EncryptionParams* matching_params = nullptr;

    for (const auto& params : encryption_params) {
        if (params.artifact_name == artifact.name) {
            matching_params = &params;
            break;
        }
    }

    if (!matching_params) {
        throw crypto::CryptoError("No encryption parameters found for artifact: " + artifact.name);
    }

    // Create streaming decryptor with GCM tag for authentication
    return std::make_unique<crypto::AES128GCM::Decryptor>(
        key,
        matching_params->iv,
        matching_params->tag
    );
}

bool ManifestValidator::VerifySignature(
    const std::vector<uint8_t>& computed_hash,
    const Manifest& manifest,
    size_t artifact_index
) {
    auto artifacts = manifest.GetArtifacts();
    if (artifact_index >= artifacts.size()) {
        throw crypto::CryptoError("Invalid artifact index: " + std::to_string(artifact_index));
    }

    const auto& artifact = artifacts[artifact_index];

    // Step 1: Verify hash matches expected hash from manifest
    if (computed_hash != artifact.expected_hash) {
        return false;
    }

    // Step 2: Verify Ed25519 signature over hash
    // SECURITY: Backend now signs SHA-256(plaintext) instead of plaintext itself
    // This allows devices to verify signature even in streaming mode
    const auto& cert_der = manifest.GetSigningCertificate();
    if (cert_der.empty()) {
        throw crypto::CryptoError("No signing certificate in manifest");
    }

    crypto::Certificate signing_cert = crypto::Certificate::LoadFromDER(cert_der);
    crypto::PublicKey signing_pubkey = signing_cert.GetPublicKey();

    // Verify Ed25519 signature over the hash
    try {
        return crypto::Ed25519::Verify(signing_pubkey, computed_hash, artifact.signature);
    } catch (const crypto::SignatureVerificationError&) {
        return false;
    }
}

} // namespace sum
