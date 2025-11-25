/**
 * @file sum_create_ca.cpp
 * @brief Tool for creating CA certificates (root and intermediate)
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum/common/crypto.h"
#include "sum/common/manifest.h"
#include <glog/logging.h>
#include <fstream>
#include <iostream>

void PrintUsage(const char* program_name) {
    std::cerr << "Usage: " << program_name << " [OPTIONS]\n"
              << "\n"
              << "Create CA certificates (root or intermediate)\n"
              << "\n"
              << "Required:\n"
              << "  --ca-key FILE          CA private key (Ed25519)\n"
              << "  --subject-key FILE     Subject public key (for intermediate CA)\n"
              << "  --hardware-id ID       Hardware identifier for CA\n"
              << "  --output FILE          Output certificate file (.crt or .pem)\n"
              << "\n"
              << "Optional:\n"
              << "  --sign-with FILE       Sign with this CA cert (creates intermediate)\n"
              << "  --common-name NAME     Certificate common name (default: hardware-id)\n"
              << "  --manufacturer NAME    Manufacturer name\n"
              << "  --device-type TYPE     Device type (default: Root-CA or Intermediate-CA)\n"
              << "  --validity-days DAYS   Validity period in days (default: 3650 for root, 1095 for intermediate)\n"
              << "  --help                 Show this help\n"
              << "\n"
              << "Examples:\n"
              << "  # Create self-signed root CA\n"
              << "  sum-create-ca --ca-key root.key --subject-key root.pub \\\n"
              << "                --hardware-id ROOT-CA --output root.crt\n"
              << "\n"
              << "  # Create intermediate CA signed by root\n"
              << "  sum-create-ca --ca-key root.key --subject-key intermediate.pub \\\n"
              << "                --hardware-id INTERMEDIATE-CA --output intermediate.crt \\\n"
              << "                --sign-with root.crt\n";
}

int main(int argc, char** argv) {
    google::InitGoogleLogging(argv[0]);
    FLAGS_logtostderr = 1;
    FLAGS_minloglevel = 2;  // ERROR level by default

    std::string ca_key_path;
    std::string subject_key_path;
    std::string hardware_id;
    std::string output_path;
    std::string sign_with_path;
    std::string common_name;
    std::string manufacturer;
    std::string device_type;
    int validity_days = 0;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            PrintUsage(argv[0]);
            return 0;
        } else if (arg == "--ca-key" && i + 1 < argc) {
            ca_key_path = argv[++i];
        } else if (arg == "--subject-key" && i + 1 < argc) {
            subject_key_path = argv[++i];
        } else if (arg == "--hardware-id" && i + 1 < argc) {
            hardware_id = argv[++i];
        } else if (arg == "--output" && i + 1 < argc) {
            output_path = argv[++i];
        } else if (arg == "--sign-with" && i + 1 < argc) {
            sign_with_path = argv[++i];
        } else if (arg == "--common-name" && i + 1 < argc) {
            common_name = argv[++i];
        } else if (arg == "--manufacturer" && i + 1 < argc) {
            manufacturer = argv[++i];
        } else if (arg == "--device-type" && i + 1 < argc) {
            device_type = argv[++i];
        } else if (arg == "--validity-days" && i + 1 < argc) {
            validity_days = std::stoi(argv[++i]);
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            PrintUsage(argv[0]);
            return 1;
        }
    }

    // Validate required arguments
    if (ca_key_path.empty() || subject_key_path.empty() ||
        hardware_id.empty() || output_path.empty()) {
        std::cerr << "Error: Missing required arguments\n\n";
        PrintUsage(argv[0]);
        return 1;
    }

    bool is_intermediate = !sign_with_path.empty();

    // Set defaults
    if (common_name.empty()) {
        common_name = hardware_id;
    }
    if (device_type.empty()) {
        device_type = is_intermediate ? "Intermediate-CA" : "Root-CA";
    }
    if (validity_days == 0) {
        validity_days = is_intermediate ? 1095 : 3650;  // 3 years for intermediate, 10 for root
    }

    try {
        // Load keys
        auto ca_key = sum::crypto::PrivateKey::LoadFromFile(ca_key_path);
        auto subject_pub = sum::crypto::PublicKey::LoadFromFile(subject_key_path);

        // Create manifest for CA
        sum::Manifest manifest;
        manifest.SetManifestVersion(1);

        sum::DeviceMetadata ca_metadata;
        ca_metadata.hardware_id = hardware_id;
        if (!manufacturer.empty()) {
            ca_metadata.manufacturer = manufacturer;
        }
        ca_metadata.device_type = device_type;

        // Create certificate
        sum::crypto::Certificate ca_cert;
        if (is_intermediate) {
            // Load parent CA certificate
            auto parent_cert = sum::crypto::Certificate::LoadFromFile(sign_with_path);
            ca_cert = sum::CreateCertificateWithManifest(
                manifest, ca_key, subject_pub, ca_metadata,
                common_name, validity_days, &parent_cert
            );
            std::cout << "Created intermediate CA certificate:\n";
        } else {
            // Self-signed root CA
            ca_cert = sum::CreateCertificateWithManifest(
                manifest, ca_key, subject_pub, ca_metadata,
                common_name, validity_days
            );
            std::cout << "Created self-signed root CA certificate:\n";
        }

        // Write output
        std::ofstream out(output_path, std::ios::binary);
        if (!out) {
            std::cerr << "Error: Cannot write to " << output_path << "\n";
            return 1;
        }

        auto der = ca_cert.ToDER();
        out.write(reinterpret_cast<const char*>(der.data()), der.size());

        std::cout << "  Hardware ID: " << hardware_id << "\n"
                  << "  Common Name: " << common_name << "\n"
                  << "  Validity: " << validity_days << " days\n"
                  << "  Output: " << output_path << "\n";

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
