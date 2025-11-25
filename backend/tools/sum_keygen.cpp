/**
 * @file sum_keygen.cpp
 * @brief Key generation utility for libsum
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum/common/crypto.h"
#include <glog/logging.h>
#include <iostream>
#include <string>
#include <cstring>
#include <fstream>

void PrintUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n"
              << "\n"
              << "Generates Ed25519 or X25519 key pairs for libsum secure updates.\n"
              << "\n"
              << "Options:\n"
              << "  --type TYPE           Key type: 'ed25519' for signing, 'x25519' for encryption (default: ed25519)\n"
              << "  --output FILE         Output private key to FILE\n"
              << "  --public FILE         Extract public key from private key\n"
              << "  --help                Show this help message\n"
              << "\n"
              << "Examples:\n"
              << "  # Generate new Ed25519 key pair for backend signing\n"
              << "  " << program_name << " --type ed25519 --output backend_key.pem\n"
              << "\n"
              << "  # Generate new X25519 key pair for device encryption\n"
              << "  " << program_name << " --type x25519 --output device_key.pem\n"
              << "\n"
              << "  # Extract public key from private key\n"
              << "  " << program_name << " --public device_key.pem --output device_pubkey.pem\n"
              << std::endl;
}

int main(int argc, char* argv[]) {
    google::InitGoogleLogging(argv[0]);
    FLAGS_logtostderr = 1;

    std::string output_file;
    std::string public_key_input;
    std::string key_type_str = "ed25519";  // Default to ed25519

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]);
            return 0;
        } else if (std::strcmp(argv[i], "--type") == 0 && i + 1 < argc) {
            key_type_str = argv[++i];
        } else if (std::strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (std::strcmp(argv[i], "--public") == 0 && i + 1 < argc) {
            public_key_input = argv[++i];
        } else {
            LOG(ERROR) << "Unknown option: " << argv[i];
            PrintUsage(argv[0]);
            return 1;
        }
    }

    try {
        if (!public_key_input.empty()) {
            // Extract public key from private key
            LOG(INFO) << "Loading private key from: " << public_key_input;
            auto privkey = sum::crypto::PrivateKey::LoadFromFile(public_key_input);
            auto pubkey = sum::crypto::PublicKey::FromPrivateKey(privkey);

            if (output_file.empty()) {
                std::cout << pubkey.ToPEM();
            } else {
                std::ofstream out(output_file);
                out << pubkey.ToPEM();
                LOG(INFO) << "Public key written to: " << output_file;
            }
        } else {
            // Generate new key pair
            sum::crypto::KeyType key_type;
            if (key_type_str == "ed25519") {
                key_type = sum::crypto::KeyType::Ed25519;
                LOG(INFO) << "Generating new Ed25519 key pair for signing";
            } else if (key_type_str == "x25519") {
                key_type = sum::crypto::KeyType::X25519;
                LOG(INFO) << "Generating new X25519 key pair for encryption";
            } else {
                LOG(ERROR) << "Invalid key type: " << key_type_str;
                LOG(ERROR) << "Valid types: ed25519, x25519";
                return 1;
            }

            auto privkey = sum::crypto::PrivateKey::Generate(key_type);

            if (output_file.empty()) {
                std::cout << privkey.ToPEM();
            } else {
                std::ofstream out(output_file);
                out << privkey.ToPEM();
                LOG(INFO) << "Private key written to: " << output_file;
            }
        }

        return 0;

    } catch (const std::exception& e) {
        LOG(ERROR) << "Fatal error: " << e.what();
        return 1;
    }
}
