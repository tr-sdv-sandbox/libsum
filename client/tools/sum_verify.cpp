/**
 * @file sum_verify.cpp
 * @brief Certificate verification utility for libsum
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum/common/crypto.h"
#include "sum/common/manifest.h"
#include "sum/client/validator.h"
#include "manifest.pb.h"
#include <glog/logging.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <ctime>

void PrintUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n"
              << "\n"
              << "Verify secure update certificates and decrypt software.\n"
              << "\n"
              << "Required Options:\n"
              << "  --certificate FILE        Update certificate chain (PEM bundle)\n"
              << "                            Contains: update cert + intermediate CA\n"
              << "  --encrypted-software FILE Encrypted software binary\n"
              << "  --device-key FILE         Device private key (X25519, PEM)\n"
              << "  --backend-ca FILE         Root CA certificate\n"
              << "  --output FILE             Output decrypted software\n"
              << "\n"
              << "Optional:\n"
              << "  --show-metadata           Display device metadata from certificate\n"
              << "  --help                    Show this help message\n"
              << "\n"
              << "Example:\n"
              << "  " << program_name << " \\\n"
              << "    --certificate update.crt \\\n"
              << "    --encrypted-software firmware.enc \\\n"
              << "    --device-key device.key \\\n"
              << "    --backend-ca ca.crt \\\n"
              << "    --output firmware.bin\n"
              << std::endl;
}

std::vector<uint8_t> ReadFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + path);
    }
    return std::vector<uint8_t>(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );
}

// Note: WriteFile removed - we now stream directly to output file during decryption

int main(int argc, char* argv[]) {
    google::InitGoogleLogging(argv[0]);
    FLAGS_logtostderr = 1;

    std::string certificate_file;
    std::string encrypted_software_file;
    std::string device_key_file;
    std::string backend_ca_file;
    std::string output_file;
    bool show_metadata = false;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            PrintUsage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--certificate") == 0 && i + 1 < argc) {
            certificate_file = argv[++i];
        } else if (strcmp(argv[i], "--encrypted-software") == 0 && i + 1 < argc) {
            encrypted_software_file = argv[++i];
        } else if (strcmp(argv[i], "--device-key") == 0 && i + 1 < argc) {
            device_key_file = argv[++i];
        } else if (strcmp(argv[i], "--backend-ca") == 0 && i + 1 < argc) {
            backend_ca_file = argv[++i];
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "--show-metadata") == 0) {
            show_metadata = true;
        } else {
            LOG(ERROR) << "Unknown argument: " << argv[i];
            PrintUsage(argv[0]);
            return 1;
        }
    }

    // Validate required arguments
    if (certificate_file.empty() || encrypted_software_file.empty() ||
        device_key_file.empty() || backend_ca_file.empty() ||
        output_file.empty()) {
        LOG(ERROR) << "Missing required arguments";
        PrintUsage(argv[0]);
        return 1;
    }

    try {
        LOG(INFO) << "Loading certificate chain (PEM bundle) from: " << certificate_file;
        auto cert_chain = sum::crypto::Certificate::LoadChainFromFile(certificate_file);
        LOG(INFO) << "Loaded " << cert_chain.size() << " certificate(s) from chain";

        // Extract update certificate (first in chain)
        const auto& update_certificate = cert_chain[0];

        // Step 1: Quick filtering - extract device metadata (UNVERIFIED)
        if (update_certificate.HasDeviceMetadata()) {
            try {
                auto metadata = update_certificate.GetDeviceMetadata();

                LOG(INFO) << "Device Metadata (UNVERIFIED - for filtering only):";
                LOG(INFO) << "  Hardware ID: " << metadata.hardware_id;
                LOG(INFO) << "  Manufacturer: " << metadata.manufacturer;
                LOG(INFO) << "  Device Type: " << metadata.device_type;
                if (!metadata.hardware_version.empty()) {
                    LOG(INFO) << "  Hardware Version: " << metadata.hardware_version;
                }

                if (show_metadata) {
                    std::cout << "\n=== Device Metadata ===\n";
                    std::cout << "  Device Type: " << metadata.device_type << "\n";
                    std::cout << "  Hardware ID: " << metadata.hardware_id << "\n";
                    std::cout << "  Manufacturer: " << metadata.manufacturer << "\n";
                    if (!metadata.hardware_version.empty()) {
                        std::cout << "  Hardware Version: " << metadata.hardware_version << "\n";
                    }
                    std::cout << std::endl;
                }

                // TODO: In real deployment, check if hardware_id matches this device
                // If not, skip update to save time
            } catch (const std::exception& e) {
                LOG(ERROR) << "❌ Fatal error: Failed to parse device metadata: " << e.what();
                return 1;
            }
        }

        LOG(INFO) << "Loading encrypted software from: " << encrypted_software_file;
        auto encrypted_software = ReadFile(encrypted_software_file);
        LOG(INFO) << "Encrypted software size: " << encrypted_software.size() << " bytes";

        LOG(INFO) << "Loading device private key from: " << device_key_file;
        auto device_key = sum::crypto::PrivateKey::LoadFromFile(device_key_file);

        LOG(INFO) << "Loading root CA certificate from: " << backend_ca_file;
        auto root_ca = sum::crypto::Certificate::LoadFromFile(backend_ca_file);

        // Build intermediates list from chain (skip first cert, which is the update cert)
        std::vector<sum::crypto::Certificate> intermediates;
        for (size_t i = 1; i < cert_chain.size(); ++i) {
            intermediates.push_back(std::move(cert_chain[i]));
        }

        LOG(INFO) << "Creating manifest validator with certificate chain:";
        if (!intermediates.empty()) {
            LOG(INFO) << "  Update cert → " << intermediates.size() << " intermediate(s) → root CA";
        } else {
            LOG(INFO) << "  Update cert → root CA (no intermediates)";
        }

        sum::ManifestValidator validator(root_ca, intermediates, device_key);

        // Step 2: Validate certificate chain and extract VERIFIED manifest
        LOG(INFO) << "Validating certificate chain and extracting manifest...";
        auto manifest = validator.ValidateCertificate(update_certificate, time(nullptr));
        LOG(INFO) << "✅ Certificate verified successfully";
        LOG(INFO) << "  Manifest version: " << manifest.GetManifestVersion();
        LOG(INFO) << "  Artifacts: " << manifest.GetArtifacts().size();

        // Step 3: Unwrap encryption key
        LOG(INFO) << "Unwrapping encryption key with device private key...";
        size_t artifact_index = 0;  // Process first artifact
        auto aes_key = validator.UnwrapEncryptionKey(manifest, artifact_index);

        // Step 4: Create streaming decryptor and hasher
        LOG(INFO) << "Creating streaming decryptor...";
        auto decryptor = validator.CreateDecryptor(aes_key, manifest, artifact_index);
        sum::crypto::SHA256::Hasher hasher;

        // Step 5: Stream decrypt and hash (process in chunks for large files)
        LOG(INFO) << "Streaming decryption and hashing...";
        std::ofstream output(output_file, std::ios::binary);
        if (!output) {
            throw std::runtime_error("Failed to create output file: " + output_file);
        }

        constexpr size_t CHUNK_SIZE = 4096;  // 4KB chunks
        size_t offset = 0;
        size_t total_decrypted = 0;

        while (offset < encrypted_software.size()) {
            size_t chunk_size = std::min(CHUNK_SIZE, encrypted_software.size() - offset);
            std::vector<uint8_t> encrypted_chunk(
                encrypted_software.begin() + offset,
                encrypted_software.begin() + offset + chunk_size
            );

            auto decrypted_chunk = decryptor->Update(encrypted_chunk);
            hasher.Update(decrypted_chunk);
            output.write(reinterpret_cast<const char*>(decrypted_chunk.data()), decrypted_chunk.size());

            total_decrypted += decrypted_chunk.size();
            offset += chunk_size;
        }

        // Finalize decryption
        auto final_chunk = decryptor->Finalize();
        if (!final_chunk.empty()) {
            hasher.Update(final_chunk);
            output.write(reinterpret_cast<const char*>(final_chunk.data()), final_chunk.size());
            total_decrypted += final_chunk.size();
        }

        output.close();
        LOG(INFO) << "Decrypted " << total_decrypted << " bytes";

        // Step 6: Finalize hash and verify signature
        LOG(INFO) << "Verifying hash and signature...";
        auto computed_hash = hasher.Finalize();
        if (!validator.VerifySignature(computed_hash, manifest, artifact_index)) {
            LOG(ERROR) << "❌ Signature verification failed!";
            return 1;
        }
        LOG(INFO) << "✅ Software verified successfully";

        LOG(INFO) << "✅ Verification complete - software is authentic and trusted";

        return 0;

    } catch (const sum::crypto::CryptoError& e) {
        LOG(ERROR) << "❌ Cryptographic verification failed: " << e.what();
        return 1;
    } catch (const std::exception& e) {
        LOG(ERROR) << "❌ Fatal error: " << e.what();
        return 1;
    }
}
