/**
 * @file validator.cpp
 * @brief Manifest validation and software decryption
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum/validator.h"
#include "sum/crypto.h"
#include <ctime>

namespace sum {

class ManifestValidator::Impl {
public:
    crypto::Certificate backend_ca;
    crypto::PrivateKey device_key;
    std::vector<crypto::Certificate> intermediates;
    bool use_chain = false;

    Impl(const crypto::Certificate& ca, const crypto::PrivateKey& key)
        : backend_ca(crypto::Certificate::LoadFromDER(ca.ToDER()))
        , device_key(crypto::PrivateKey::LoadFromPEM(key.ToPEM()))
        , use_chain(false) {}

    Impl(const crypto::Certificate& root,
         const std::vector<crypto::Certificate>& intermediate_certs,
         const crypto::PrivateKey& key)
        : backend_ca(crypto::Certificate::LoadFromDER(root.ToDER()))
        , device_key(crypto::PrivateKey::LoadFromPEM(key.ToPEM()))
        , use_chain(true) {
        // Clone intermediate certificates via DER roundtrip
        for (const auto& cert : intermediate_certs) {
            intermediates.push_back(crypto::Certificate::LoadFromDER(cert.ToDER()));
        }
    }
};

ManifestValidator::ManifestValidator(
    const crypto::Certificate& backend_ca,
    const crypto::PrivateKey& device_key
) : impl_(std::make_unique<Impl>(backend_ca, device_key)) {}

ManifestValidator::ManifestValidator(
    const crypto::Certificate& root_ca,
    const std::vector<crypto::Certificate>& intermediates,
    const crypto::PrivateKey& device_key
) : impl_(std::make_unique<Impl>(root_ca, intermediates, device_key)) {}

ManifestValidator::~ManifestValidator() = default;

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
    auto manifest_json = manifest.ToJSONForSigning();

    try {
        return crypto::Ed25519::Verify(signing_pubkey, manifest_json, signature);
    } catch (const crypto::SignatureVerificationError&) {
        return false;
    }
}

Manifest ManifestValidator::ValidateCertificate(
    const crypto::Certificate& certificate,
    int64_t trusted_time
) {
    std::vector<uint8_t> manifest_json;

    // Step 1: Verify certificate signature and extract verified manifest
    // Both paths verify against root CA - difference is chain length
    if (impl_->use_chain) {
        // Validate chain: update cert → intermediate(s) → root CA
        manifest_json = certificate.GetVerifiedManifestWithChain(
            impl_->intermediates,
            impl_->backend_ca,  // root CA
            trusted_time
        );
    } else {
        // Validate directly: update cert → root CA (no intermediates)
        manifest_json = certificate.GetVerifiedManifest(impl_->backend_ca, trusted_time);
    }

    // Step 2: Parse manifest from verified JSON
    auto manifest = Manifest::LoadFromJSON(manifest_json);

    // Step 3: Return verified manifest
    return manifest;
}

std::vector<uint8_t> ManifestValidator::UnwrapEncryptionKey(
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

std::vector<uint8_t> ManifestValidator::DecryptSoftware(
    const std::vector<uint8_t>& encrypted_software,
    const std::vector<uint8_t>& key,
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

    // Decrypt using AES-128-CTR
    return crypto::AES128CTR::Decrypt(key, matching_params->iv, encrypted_software);
}

bool ManifestValidator::VerifySoftware(
    const std::vector<uint8_t>& software,
    const Manifest& manifest,
    size_t artifact_index
) {
    auto artifacts = manifest.GetArtifacts();
    if (artifact_index >= artifacts.size()) {
        throw crypto::CryptoError("Invalid artifact index: " + std::to_string(artifact_index));
    }

    const auto& artifact = artifacts[artifact_index];

    // Verify hash
    auto computed_hash = crypto::SHA256::Hash(software);
    if (computed_hash != artifact.expected_hash) {
        return false;
    }

    // Verify signature
    // Get signing certificate and extract public key
    const auto& cert_der = manifest.GetSigningCertificate();
    if (cert_der.empty()) {
        return false;
    }

    crypto::Certificate signing_cert = crypto::Certificate::LoadFromDER(cert_der);
    crypto::PublicKey signing_pubkey = signing_cert.GetPublicKey();

    try {
        return crypto::Ed25519::Verify(signing_pubkey, software, artifact.signature);
    } catch (const crypto::SignatureVerificationError&) {
        return false;
    }
}

} // namespace sum
