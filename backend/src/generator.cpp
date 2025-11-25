/**
 * @file generator.cpp
 * @brief Manifest generation and software encryption
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum/backend/generator.h"
#include "sum/common/crypto.h"
#include <openssl/rand.h>

namespace sum {

class ManifestGenerator::Impl {
public:
    crypto::PrivateKey backend_key;
    crypto::Certificate backend_cert;

    Impl(const crypto::PrivateKey& key, const crypto::Certificate& cert)
        : backend_key(crypto::PrivateKey::LoadFromPEM(key.ToPEM()))
        , backend_cert(crypto::Certificate::LoadFromDER(cert.ToDER())) {}
};

ManifestGenerator::ManifestGenerator(
    const crypto::PrivateKey& backend_key,
    const crypto::Certificate& backend_cert
) : impl_(std::make_unique<Impl>(backend_key, backend_cert)) {}

ManifestGenerator::~ManifestGenerator() = default;

std::pair<Manifest, std::vector<uint8_t>> ManifestGenerator::Create(
    const std::vector<uint8_t>& software,
    const crypto::PublicKey& device_pubkey,
    uint64_t version,
    bool use_encryption,
    const std::string& artifact_url
) {
    Manifest manifest;
    manifest.SetManifestVersion(version);

    std::vector<uint8_t> output_software;

    if (use_encryption) {
        // SECURITY: Verify PRNG is properly seeded before generating encryption keys
        if (RAND_status() != 1) {
            throw crypto::CryptoError("OpenSSL PRNG not properly seeded - insufficient entropy");
        }

        // Generate random AES key and IV (nonce)
        std::vector<uint8_t> aes_key(crypto::AES_128_KEY_SIZE);
        std::vector<uint8_t> iv(crypto::AES_GCM_IV_SIZE);

        if (RAND_bytes(aes_key.data(), aes_key.size()) != 1) {
            throw crypto::CryptoError("Failed to generate AES key");
        }
        if (RAND_bytes(iv.data(), iv.size()) != 1) {
            throw crypto::CryptoError("Failed to generate IV");
        }

        // Encrypt software with AES-GCM (authenticated encryption)
        auto result = crypto::AES128GCM::Encrypt(aes_key, iv, software);
        output_software = result.ciphertext;

        // Wrap AES key with device public key using X25519
        auto wrapped_key = crypto::X25519::WrapKey(aes_key, device_pubkey);

        // Add encryption parameters to manifest
        // TODO: device_id should come from device registry/database
        // For now, use a placeholder (tests will override with actual device ID)
        std::string device_id = "device-test";

        EncryptionParams encryption;
        encryption.artifact_name = "application";
        encryption.device_id = device_id;
        encryption.algorithm = "AES-128-GCM";
        encryption.iv = iv;
        encryption.wrapped_key = wrapped_key;
        encryption.key_wrapping_algorithm = "X25519-HKDF-SHA256-ChaCha20Poly1305";
        encryption.tag = result.tag;
        manifest.AddEncryptionParams(encryption);
    } else {
        output_software = software;
    }

    // Compute software hash (of plaintext)
    auto software_hash = crypto::SHA256::Hash(software);

    // Compute ciphertext hash (for content-addressable storage)
    auto ciphertext_hash = crypto::SHA256::Hash(output_software);

    // SECURITY: Sign hash instead of plaintext to enable streaming verification
    // Device can compute hash incrementally during decryption, then verify signature
    auto software_signature = crypto::Ed25519::Sign(impl_->backend_key, software_hash);

    // Add software artifact to manifest
    SoftwareArtifact artifact;
    artifact.name = "application";
    artifact.type = "firmware";
    artifact.target_ecu = "primary";
    artifact.install_order = 0;
    artifact.hash_algorithm = "SHA-256";
    artifact.expected_hash = software_hash;
    artifact.signature_algorithm = "Ed25519";
    artifact.signature = software_signature;
    artifact.size = software.size();
    artifact.ciphertext_hash = ciphertext_hash;
    artifact.ciphertext_size = output_software.size();

    // Add source if provided
    if (!artifact_url.empty()) {
        Source src;
        src.uri = artifact_url;
        src.priority = 0;
        src.type = "http";
        artifact.sources.push_back(src);
    }

    manifest.AddArtifact(artifact);

    // Set signing certificate
    manifest.SetSigningCertificate(impl_->backend_cert.ToDER());

    return {std::move(manifest), std::move(output_software)};
}

std::pair<crypto::Certificate, std::vector<uint8_t>> ManifestGenerator::CreateCertificate(
    const std::vector<uint8_t>& software,
    const crypto::PublicKey& device_pubkey,
    const DeviceMetadata& device_metadata,
    uint64_t version,
    bool use_encryption,
    int validity_days,
    const std::string& artifact_url
) {
    // Create manifest using existing Create() method
    auto [manifest, encrypted_software] = Create(software, device_pubkey, version, use_encryption, artifact_url);

    // Create certificate with manifest and device metadata embedded
    // Pass backend_cert as issuer so the certificate has correct issuer DN
    auto certificate = CreateCertificateWithManifest(
        manifest,
        impl_->backend_key,
        device_pubkey,
        device_metadata,
        "Secure Update Certificate",
        validity_days,
        &impl_->backend_cert
    );

    return {std::move(certificate), std::move(encrypted_software)};
}

std::pair<std::string, std::vector<uint8_t>> ManifestGenerator::CreateCertificateChainPEM(
    const std::vector<uint8_t>& software,
    const crypto::PublicKey& device_pubkey,
    const DeviceMetadata& device_metadata,
    uint64_t version,
    bool use_encryption,
    int validity_days,
    const std::string& artifact_url
) {
    // Create update certificate
    auto [update_cert, encrypted_software] = CreateCertificate(
        software, device_pubkey, device_metadata, version, use_encryption, validity_days, artifact_url
    );

    // Build certificate chain: [update_cert, signing_cert (intermediate)]
    // Certificate is move-only, so clone backend_cert via DER for the chain
    std::vector<crypto::Certificate> chain;
    chain.push_back(std::move(update_cert));
    chain.push_back(crypto::Certificate::LoadFromDER(impl_->backend_cert.ToDER()));

    // Create PEM bundle
    std::string pem_bundle = crypto::Certificate::CreateChainPEM(chain);

    return {std::move(pem_bundle), std::move(encrypted_software)};
}

// SemVer overloads
std::pair<crypto::Certificate, std::vector<uint8_t>> ManifestGenerator::CreateCertificate(
    const std::vector<uint8_t>& software,
    const crypto::PublicKey& device_pubkey,
    const DeviceMetadata& device_metadata,
    const SemVer& sw_version,
    bool use_encryption,
    int validity_days,
    const std::string& artifact_url
) {
    // Create manifest (temporarily use 0 for old version field)
    auto [manifest, encrypted_software] = Create(software, device_pubkey, 0, use_encryption, artifact_url);

    // Set semantic version
    manifest.SetSoftwareVersion(sw_version);

    // Create certificate with manifest and device metadata embedded
    auto certificate = CreateCertificateWithManifest(
        manifest,
        impl_->backend_key,
        device_pubkey,
        device_metadata,
        "Secure Update Certificate",
        validity_days,
        &impl_->backend_cert
    );

    return {std::move(certificate), std::move(encrypted_software)};
}

std::pair<std::string, std::vector<uint8_t>> ManifestGenerator::CreateCertificateChainPEM(
    const std::vector<uint8_t>& software,
    const crypto::PublicKey& device_pubkey,
    const DeviceMetadata& device_metadata,
    const SemVer& sw_version,
    bool use_encryption,
    int validity_days,
    const std::string& artifact_url
) {
    // Create update certificate
    auto [update_cert, encrypted_software] = CreateCertificate(
        software, device_pubkey, device_metadata, sw_version, use_encryption, validity_days, artifact_url
    );

    // Build certificate chain: [update_cert, signing_cert (intermediate)]
    std::vector<crypto::Certificate> chain;
    chain.push_back(std::move(update_cert));
    chain.push_back(crypto::Certificate::LoadFromDER(impl_->backend_cert.ToDER()));

    // Create PEM bundle
    std::string pem_bundle = crypto::Certificate::CreateChainPEM(chain);

    return {std::move(pem_bundle), std::move(encrypted_software)};
}

std::vector<uint8_t> ManifestGenerator::EncryptSoftware(
    const std::vector<uint8_t>& software,
    std::vector<uint8_t>& key,
    std::vector<uint8_t>& iv
) {
    // Generate key and IV if not provided
    if (key.empty() || iv.empty()) {
        // SECURITY: Verify PRNG is properly seeded before generating keys/IVs
        if (RAND_status() != 1) {
            throw crypto::CryptoError("OpenSSL PRNG not properly seeded - insufficient entropy");
        }
    }

    if (key.empty()) {
        key.resize(crypto::AES_128_KEY_SIZE);
        if (RAND_bytes(key.data(), key.size()) != 1) {
            throw crypto::CryptoError("Failed to generate AES key");
        }
    }

    if (iv.empty()) {
        iv.resize(crypto::AES_GCM_IV_SIZE);
        if (RAND_bytes(iv.data(), iv.size()) != 1) {
            throw crypto::CryptoError("Failed to generate IV");
        }
    }

    auto result = crypto::AES128GCM::Encrypt(key, iv, software);
    // Note: This method only returns ciphertext, tag is discarded
    // Use the main Create() API instead for proper GCM with authentication
    return result.ciphertext;
}

std::vector<uint8_t> ManifestGenerator::WrapKey(
    const std::vector<uint8_t>& key,
    const crypto::PublicKey& device_pubkey
) {
    return crypto::X25519::WrapKey(key, device_pubkey);
}

void ManifestGenerator::SignManifest(Manifest& manifest) {
    // Get manifest protobuf WITHOUT signature field
    auto manifest_protobuf = manifest.ToProtobufForSigning();

    // Sign the manifest
    auto signature = crypto::Ed25519::Sign(impl_->backend_key, manifest_protobuf);

    // Set signature
    manifest.SetSignature(signature);
}

} // namespace sum
