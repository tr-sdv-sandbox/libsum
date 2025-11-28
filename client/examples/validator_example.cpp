/**
 * @file device_example.cpp
 * @brief Example: Device verifying and installing updates
 *
 * This example demonstrates how a device validates update certificates
 * and installs verified firmware.
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum/common/crypto.h"
#include "sum/common/manifest.h"
#include "sum/client/validator.h"
#include <glog/logging.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <vector>
#include <ctime>

using namespace sum;

// Helper to read file
std::vector<uint8_t> ReadFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + path);
    }
    return std::vector<uint8_t>(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
}

// Simulate persistent storage (in real device: read/write flash)
// These functions demonstrate anti-rollback and revocation persistence

uint64_t LoadLastInstalledVersion() {
    // In real device: LoadFromFlash("last_installed_version", 0)
    // Example: read from EEPROM, flash config partition, etc.
    return 41;  // Simulated: last successfully installed version
}

void SaveLastInstalledVersion(uint64_t version) {
    // In real device: SaveToFlash("last_installed_version", version)
    // Example: write to EEPROM, flash config partition, etc.
    LOG(INFO) << "  ✅ Persisted version " << version << " to flash";
}

int64_t LoadRevocationTimestamp() {
    // In real device: LoadFromFlash("reject_certs_before", 0)
    // Example: read from EEPROM, flash config partition, etc.
    return 0;  // Simulated: no revocation timestamp set (0 = disabled)
}

void SaveRevocationTimestamp(int64_t timestamp) {
    // In real device: SaveToFlash("reject_certs_before", timestamp)
    // Example: write to EEPROM, flash config partition, etc.
    LOG(INFO) << "  ✅ Persisted revocation timestamp " << timestamp << " to flash";
}

const std::string MY_HARDWARE_ID = "DEVICE-12345";

int main(int argc, char* argv[]) {
    google::InitGoogleLogging(argv[0]);
    FLAGS_logtostderr = 1;

    try {
        LOG(INFO) << "=== Device Example: Verifying and Installing Update ===";
        LOG(INFO) << "";

        // Step 1: Load update certificate and encrypted firmware
        LOG(INFO) << "Step 1: Loading update files...";
        LOG(INFO) << "  Loading certificate (PEM bundle with intermediates) from update.crt...";
        auto update_certificate = crypto::Certificate::LoadFromFile("update.crt");
        auto encrypted_firmware = ReadFile("firmware.enc");
        LOG(INFO) << "  ✅ Certificate loaded (intermediates embedded internally)";
        LOG(INFO) << "  ✅ Encrypted firmware loaded (" << encrypted_firmware.size() << " bytes)";
        LOG(INFO) << "";

        // Step 2: Load device credentials and root CA
        LOG(INFO) << "Step 2: Loading device credentials and root CA...";
        auto device_key = crypto::PrivateKey::LoadFromFile("device.key");
        auto root_ca_cert = crypto::Certificate::LoadFromFile("ca.crt");
        LOG(INFO) << "  ✅ Device private key loaded";
        LOG(INFO) << "  ✅ Root CA certificate loaded";
        LOG(INFO) << "";

        LOG(INFO) << "Certificate chain verification path:";
        LOG(INFO) << "  Update cert → intermediate CA (embedded) → root CA";
        LOG(INFO) << "";

        // Step 3: Load security policies from persistent storage
        LOG(INFO) << "Step 3: Loading security policies...";
        uint64_t last_installed_version = LoadLastInstalledVersion();
        int64_t revocation_timestamp = LoadRevocationTimestamp();
        LOG(INFO) << "  Last installed version: " << last_installed_version;
        LOG(INFO) << "  Revocation timestamp: " << revocation_timestamp << " (0 = disabled)";
        LOG(INFO) << "";

        // Step 4: Configure validator with security policies
        LOG(INFO) << "Step 4: Configuring validator with security policies...";

        ManifestValidator validator(root_ca_cert, device_key);

        // SECURITY: Set anti-rollback protection
        // Automatically rejects updates with version <= last_installed_version
        // This prevents BOTH rollback attacks (older version) AND replay attacks (same version)
        validator.SetLastInstalledVersion(last_installed_version);
        LOG(INFO) << "  ✅ Anti-rollback protection enabled (reject version <= " << last_installed_version << ")";

        // SECURITY: Set certificate revocation policy
        // Automatically rejects intermediate CAs issued before revocation timestamp
        // This enables emergency revocation without CRL/OCSP infrastructure
        if (revocation_timestamp > 0) {
            validator.SetRejectCertificatesBefore(revocation_timestamp);
            LOG(INFO) << "  ✅ Certificate revocation enabled (reject certs before " << revocation_timestamp << ")";
        } else {
            LOG(INFO) << "  ℹ️  Certificate revocation disabled (no timestamp set)";
        }
        LOG(INFO) << "";

        // Step 5: Validate certificate chain and extract VERIFIED manifest
        LOG(INFO) << "Step 5: Validating certificate chain...";
        LOG(INFO) << "  Verifying: update cert → intermediate CA → root CA";
        LOG(INFO) << "  Enforcing: anti-rollback + revocation policies";

        auto manifest = validator.ValidateCertificate(update_certificate, time(nullptr));
        // ✅ Throws CryptoError if:
        //    - Chain validation fails
        //    - Certificate expired
        //    - Version <= last_installed_version (anti-rollback/replay)
        //    - Intermediate CA issued before revocation timestamp

        LOG(INFO) << "  ✅ Certificate chain validated";
        LOG(INFO) << "  ✅ Update certificate signed by intermediate CA";
        LOG(INFO) << "  ✅ Intermediate CA signed by root CA";
        LOG(INFO) << "  ✅ Anti-rollback policy passed";
        LOG(INFO) << "  ✅ Certificate revocation policy passed";
        LOG(INFO) << "  ✅ Manifest extracted and verified";
        LOG(INFO) << "";

        // Step 6: Display update information
        LOG(INFO) << "Step 6: Update information...";
        uint64_t update_version = manifest.GetManifestVersion();
        LOG(INFO) << "  Update version: " << update_version;
        LOG(INFO) << "  Upgrade: " << last_installed_version << " → " << update_version;
        LOG(INFO) << "";

        // Step 7: Stream decrypt firmware to flash
        LOG(INFO) << "Step 7: Streaming decryption to flash...";
        size_t artifact_index = 0;  // Process first artifact
        auto aes_key = validator.UnwrapEncryptionKey(manifest, artifact_index);

        // Create streaming decryptor and hasher
        auto decryptor = validator.CreateDecryptor(aes_key, manifest, artifact_index);
        crypto::SHA256::Hasher hasher;

        // Simulate streaming decrypt/write to flash (in chunks)
        LOG(INFO) << "  Processing firmware in 4KB chunks (real device would write to flash)...";
        constexpr size_t CHUNK_SIZE = 4096;  // Typical flash page size
        size_t offset = 0;
        size_t total_bytes = 0;

        // In real device: open flash partition for writing
        std::vector<uint8_t> firmware_buffer;  // Simulated flash buffer

        while (offset < encrypted_firmware.size()) {
            size_t chunk_size = std::min(CHUNK_SIZE, encrypted_firmware.size() - offset);
            std::vector<uint8_t> encrypted_chunk(
                encrypted_firmware.begin() + offset,
                encrypted_firmware.begin() + offset + chunk_size
            );

            // Decrypt chunk
            auto decrypted_chunk = decryptor->Update(encrypted_chunk);

            // Update hash incrementally
            hasher.Update(decrypted_chunk);

            // In real device: write to flash page
            firmware_buffer.insert(firmware_buffer.end(), decrypted_chunk.begin(), decrypted_chunk.end());

            total_bytes += decrypted_chunk.size();
            offset += chunk_size;
        }

        // Finalize decryption
        auto final_chunk = decryptor->Finalize();
        if (!final_chunk.empty()) {
            hasher.Update(final_chunk);
            firmware_buffer.insert(firmware_buffer.end(), final_chunk.begin(), final_chunk.end());
            total_bytes += final_chunk.size();
        }

        LOG(INFO) << "  ✅ Decrypted " << total_bytes << " bytes to flash";
        LOG(INFO) << "";

        // Step 8: Verify firmware hash and signature
        LOG(INFO) << "Step 8: Verifying firmware integrity...";
        auto computed_hash = hasher.Finalize();
        if (!validator.VerifySignature(computed_hash, manifest, artifact_index)) {
            LOG(ERROR) << "Firmware verification failed!";
            LOG(ERROR) << "  ❌ Rolling back - erasing flash";
            return 1;
        }
        LOG(INFO) << "  ✅ Firmware hash verified";
        LOG(INFO) << "  ✅ Firmware signature verified";
        LOG(INFO) << "";

        // Step 9: Commit firmware update and persist new version
        LOG(INFO) << "Step 9: Committing firmware update...";
        LOG(INFO) << "  In real device: mark flash partition as valid";

        // CRITICAL: Persist new version AFTER successful installation
        // This enables anti-rollback protection for future updates
        SaveLastInstalledVersion(update_version);

        // Note: To emergency-revoke compromised intermediate CA:
        // 1. Backend issues new intermediate CA with notBefore = now
        // 2. Backend sends emergency update with revocation timestamp
        // 3. Device calls: SaveRevocationTimestamp(emergency_timestamp)
        // 4. Future updates signed by old intermediate CA will be rejected

        LOG(INFO) << "  ✅ Update committed";
        LOG(INFO) << "";

        LOG(INFO) << "✅ Update installed successfully!";
        LOG(INFO) << "Device ready to reboot with new firmware.";
        return 0;

    } catch (const crypto::CryptoError& e) {
        LOG(ERROR) << "Cryptographic error: " << e.what();
        LOG(ERROR) << "Update rejected!";
        return 1;
    } catch (const std::exception& e) {
        LOG(ERROR) << "Error: " << e.what();
        return 1;
    }
}
