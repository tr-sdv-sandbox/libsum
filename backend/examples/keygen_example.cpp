/**
 * @file keygen_example.cpp
 * @brief Example: Key generation and management
 *
 * This example demonstrates how to generate and manage cryptographic keys
 * for the libsum secure update system using Ed25519 and X25519.
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum/common/crypto.h"
#include "sum/common/manifest.h"
#include <glog/logging.h>
#include <fstream>
#include <iostream>

using namespace sum;

// Helper to write binary file
void WriteFile(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot write file: " + path);
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

// Helper to write string file
void WriteFile(const std::string& path, const std::string& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot write file: " + path);
    }
    file.write(data.data(), data.size());
}

int main(int argc, char* argv[]) {
    google::InitGoogleLogging(argv[0]);
    FLAGS_logtostderr = 1;

    try {
        LOG(INFO) << "=== Key Generation Example ===";
        LOG(INFO) << "";

        // ========================================
        // Part 1: Generate CA (Certificate Authority) Keys
        // ========================================
        LOG(INFO) << "Part 1: Generating CA keys...";
        LOG(INFO) << "";

        LOG(INFO) << "libsum uses modern Curve25519 cryptography:";
        LOG(INFO) << "  - Ed25519: For signing (fast, deterministic, secure)";
        LOG(INFO) << "  - X25519: For key wrapping (ECDH key agreement)";
        LOG(INFO) << "";

        LOG(INFO) << "Generating CA signing key (Ed25519)...";
        auto ca_key = crypto::PrivateKey::Generate(crypto::KeyType::Ed25519);
        auto ca_pub = crypto::PublicKey::FromPrivateKey(ca_key);

        LOG(INFO) << "  ✅ CA signing key generated";
        LOG(INFO) << "  ✅ CA public key extracted";
        LOG(INFO) << "";

        // Save CA keys
        LOG(INFO) << "Saving CA keys...";
        WriteFile("ca.key", ca_key.ToPEM());
        WriteFile("ca.pub", ca_pub.ToPEM());
        LOG(INFO) << "  ✅ Saved ca.key (KEEP SECURE!)";
        LOG(INFO) << "  ✅ Saved ca.pub";
        LOG(INFO) << "";

        // Create self-signed CA certificate
        LOG(INFO) << "Creating self-signed CA certificate...";
        Manifest ca_manifest;
        ca_manifest.SetManifestVersion(1);

        DeviceMetadata ca_meta;
        ca_meta.hardware_id = "CA-ROOT";
        ca_meta.manufacturer = "Example CA";
        ca_meta.device_type = "CA";

        auto ca_cert = CreateCertificateWithManifest(
            ca_manifest,
            ca_key,
            ca_pub,
            ca_meta,
            "Example CA",
            3650  // 10 years validity
        );

        WriteFile("ca.crt", ca_cert.ToDER());
        LOG(INFO) << "  ✅ Saved ca.crt";
        LOG(INFO) << "";

        LOG(INFO) << "⚠️  SECURITY NOTICE:";
        LOG(INFO) << "  - ca.key is your ROOT OF TRUST for signing";
        LOG(INFO) << "  - Store in Hardware Security Module (HSM) in production";
        LOG(INFO) << "  - Enable access logging and auditing";
        LOG(INFO) << "  - Never expose to untrusted systems";
        LOG(INFO) << "";

        // ========================================
        // Part 2: Generate Intermediate CA (PRODUCTION BEST PRACTICE)
        // ========================================
        LOG(INFO) << "Part 2: Generating intermediate CA...";
        LOG(INFO) << "";

        LOG(INFO) << "Production PKI uses intermediate CAs:";
        LOG(INFO) << "  - Root CA: Kept offline in HSM, only signs intermediate CAs";
        LOG(INFO) << "  - Intermediate CA: Online, signs update certificates";
        LOG(INFO) << "  - Benefits: Can revoke intermediate without re-deploying root";
        LOG(INFO) << "";

        LOG(INFO) << "Generating intermediate CA signing key (Ed25519)...";
        auto intermediate_key = crypto::PrivateKey::Generate(crypto::KeyType::Ed25519);
        auto intermediate_pub = crypto::PublicKey::FromPrivateKey(intermediate_key);

        LOG(INFO) << "  ✅ Intermediate CA signing key generated";
        LOG(INFO) << "";

        // Save intermediate keys
        LOG(INFO) << "Saving intermediate CA keys...";
        WriteFile("intermediate.key", intermediate_key.ToPEM());
        WriteFile("intermediate.pub", intermediate_pub.ToPEM());
        LOG(INFO) << "  ✅ Saved intermediate.key (secure storage!)";
        LOG(INFO) << "  ✅ Saved intermediate.pub";
        LOG(INFO) << "";

        // Create intermediate CA certificate (signed by root CA)
        LOG(INFO) << "Creating intermediate CA certificate (signed by root)...";
        Manifest intermediate_manifest;
        intermediate_manifest.SetManifestVersion(1);

        DeviceMetadata intermediate_meta;
        intermediate_meta.hardware_id = "INTERMEDIATE-CA";
        intermediate_meta.manufacturer = "Example CA";
        intermediate_meta.device_type = "Intermediate-CA";

        auto intermediate_cert = CreateCertificateWithManifest(
            intermediate_manifest,
            ca_key,              // Signed by root CA private key
            intermediate_pub,    // Intermediate's public key
            intermediate_meta,
            "Example Intermediate CA",
            1095,                // 3 years validity (shorter than root)
            &ca_cert             // Root CA as issuer (for proper DN chain)
        );

        WriteFile("intermediate.crt", intermediate_cert.ToDER());
        LOG(INFO) << "  ✅ Saved intermediate.crt (signed by root CA)";
        LOG(INFO) << "";

        LOG(INFO) << "Certificate chain: update.crt → intermediate.crt → ca.crt (root)";
        LOG(INFO) << "";

        // ========================================
        // Part 3: Generate Device Encryption Keys
        // ========================================
        LOG(INFO) << "Part 3: Generating device encryption keys...";
        LOG(INFO) << "";

        LOG(INFO) << "Devices need X25519 keys for receiving encrypted updates";
        LOG(INFO) << "Backend wraps AES keys with device's X25519 public key";
        LOG(INFO) << "";

        LOG(INFO) << "Generating device encryption key (X25519)...";
        auto device_key = crypto::PrivateKey::Generate(crypto::KeyType::X25519);
        auto device_pub = crypto::PublicKey::FromPrivateKey(device_key);

        LOG(INFO) << "  ✅ Device encryption key generated";
        LOG(INFO) << "  ✅ Device public key extracted";
        LOG(INFO) << "";

        // Save device keys
        LOG(INFO) << "Saving device keys...";
        WriteFile("device.key", device_key.ToPEM());
        WriteFile("device.pub", device_pub.ToPEM());
        LOG(INFO) << "  ✅ Saved device.key";
        LOG(INFO) << "  ✅ Saved device.pub";
        LOG(INFO) << "";

        LOG(INFO) << "Device Key Deployment:";
        LOG(INFO) << "  - device.key → Store in device secure element (ATECC608, TPM)";
        LOG(INFO) << "  - device.pub → Upload to backend database";
        LOG(INFO) << "  - Link device.pub to hardware_id in database";
        LOG(INFO) << "";

        // ========================================
        // Part 4: Generate Backend Signing Key
        // ========================================
        LOG(INFO) << "Part 4: Generating backend signing key...";
        LOG(INFO) << "";

        LOG(INFO) << "Backend needs Ed25519 key for signing update packages";
        LOG(INFO) << "";

        LOG(INFO) << "Generating backend signing key (Ed25519)...";
        auto backend_key = crypto::PrivateKey::Generate(crypto::KeyType::Ed25519);
        auto backend_pub = crypto::PublicKey::FromPrivateKey(backend_key);

        WriteFile("backend.key", backend_key.ToPEM());
        WriteFile("backend.pub", backend_pub.ToPEM());
        LOG(INFO) << "  ✅ Saved backend.key (KEEP SECURE!)";
        LOG(INFO) << "  ✅ Saved backend.pub";
        LOG(INFO) << "";

        // ========================================
        // Part 5: Key Information
        // ========================================
        LOG(INFO) << "Part 5: Key Information";
        LOG(INFO) << "";

        LOG(INFO) << "Key Types:";
        LOG(INFO) << "  - Ed25519 (Signing):";
        LOG(INFO) << "    ✓ Ultra-fast signing and verification";
        LOG(INFO) << "    ✓ Deterministic signatures (no RNG needed)";
        LOG(INFO) << "    ✓ Side-channel resistant";
        LOG(INFO) << "    ✓ 128-bit security level";
        LOG(INFO) << "    • Use for: CA certificates, backend signing";
        LOG(INFO) << "";
        LOG(INFO) << "  - X25519 (Key Wrapping):";
        LOG(INFO) << "    ✓ Fast ECDH key agreement";
        LOG(INFO) << "    ✓ Wraps AES keys for devices";
        LOG(INFO) << "    ✓ Modern, secure, widely used (Signal, WireGuard)";
        LOG(INFO) << "    ✓ 128-bit security level";
        LOG(INFO) << "    • Use for: Device encryption keys";
        LOG(INFO) << "";

        LOG(INFO) << "Key Formats:";
        LOG(INFO) << "  - Private keys: PEM format (PKCS#8)";
        LOG(INFO) << "  - Public keys: PEM format (X.509 SubjectPublicKeyInfo)";
        LOG(INFO) << "  - Certificates: DER format (binary X.509)";
        LOG(INFO) << "";

        LOG(INFO) << "Update Flow:";
        LOG(INFO) << "  1. Backend signs firmware with Ed25519 key";
        LOG(INFO) << "  2. Backend encrypts firmware with random AES key";
        LOG(INFO) << "  3. Backend wraps AES key with device's X25519 public key";
        LOG(INFO) << "  4. Device unwraps AES key with its X25519 private key";
        LOG(INFO) << "  5. Device decrypts firmware with AES key";
        LOG(INFO) << "  6. Device verifies signature with backend's Ed25519 public key";
        LOG(INFO) << "";

        // ========================================
        // Summary
        // ========================================
        LOG(INFO) << "=== Key Generation Summary ===";
        LOG(INFO) << "";
        LOG(INFO) << "Files created:";
        LOG(INFO) << "  Root CA Keys (Ed25519):";
        LOG(INFO) << "    - ca.key (private, signing) ⚠️  OFFLINE HSM STORAGE";
        LOG(INFO) << "    - ca.pub (public, verification)";
        LOG(INFO) << "    - ca.crt (self-signed root certificate)";
        LOG(INFO) << "";
        LOG(INFO) << "  Intermediate CA Keys (Ed25519):";
        LOG(INFO) << "    - intermediate.key (private, signing) ⚠️  SECURE STORAGE";
        LOG(INFO) << "    - intermediate.pub (public, verification)";
        LOG(INFO) << "    - intermediate.crt (signed by root CA)";
        LOG(INFO) << "";
        LOG(INFO) << "  Backend Keys (Ed25519):";
        LOG(INFO) << "    - backend.key (private, signing) ⚠️  SECURE STORAGE";
        LOG(INFO) << "    - backend.pub (public, verification)";
        LOG(INFO) << "";
        LOG(INFO) << "  Device Keys (X25519):";
        LOG(INFO) << "    - device.key (private, decryption) → Device secure element";
        LOG(INFO) << "    - device.pub (public, encryption) → Backend database";
        LOG(INFO) << "";
        LOG(INFO) << "Next Steps:";
        LOG(INFO) << "  1. Run backend_example to create encrypted update package";
        LOG(INFO) << "  2. Run device_example to verify and install update";
        LOG(INFO) << "";

        LOG(INFO) << "✅ Key generation example completed successfully!";
        return 0;

    } catch (const std::exception& e) {
        LOG(ERROR) << "Error: " << e.what();
        return 1;
    }
}
