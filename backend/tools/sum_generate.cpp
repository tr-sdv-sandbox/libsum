/**
 * @file sum_generate.cpp
 * @brief Certificate generation utility for libsum
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum/common/crypto.h"
#include "sum/common/manifest.h"
#include "sum/backend/generator.h"
#include <glog/logging.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>

void PrintUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n"
              << "\n"
              << "Generate secure update certificates with embedded manifests.\n"
              << "\n"
              << "Required Options:\n"
              << "  --software FILE           Input software binary\n"
              << "  --device-pubkey FILE      Device public key (PEM)\n"
              << "  --backend-key FILE        Backend signing private key (PEM)\n"
              << "                            (Use intermediate CA key in production PKI)\n"
              << "  --backend-cert FILE       Backend CA certificate (PEM/DER)\n"
              << "                            (Use intermediate CA cert in production PKI)\n"
              << "  --hardware-id ID          Device hardware ID (REQUIRED - links to device public key)\n"
              << "  --manufacturer NAME       Device manufacturer\n"
              << "  --device-type TYPE        Device type/model\n"
              << "  --output FILE             Output certificate file (.crt)\n"
              << "  --encrypted-output FILE   Output encrypted software\n"
              << "\n"
              << "Version Options (at least one required):\n"
              << "  --sw-version VERSION      Semantic version (e.g., \"1.2.3\" or \"1.2.3-beta.1+git.abc\")\n"
              << "  --version VERSION         Simple version number (DEPRECATED, use --sw-version)\n"
              << "\n"
              << "Optional:\n"
              << "  --hardware-version VER    Hardware version (optional)\n"
              << "  --no-encryption           Do not encrypt software\n"
              << "  --validity-days DAYS      Certificate validity in days (default: 90)\n"
              << "  --help                    Show this help message\n"
              << "\n"
              << "Example (Production PKI with Intermediate CA):\n"
              << "  " << program_name << " \\\n"
              << "    --software firmware.bin \\\n"
              << "    --device-pubkey device_12345.pub \\\n"
              << "    --backend-key intermediate.key \\\n"
              << "    --backend-cert intermediate.crt \\\n"
              << "    --hardware-id DEVICE-12345 \\\n"
              << "    --manufacturer \"Acme Corp\" \\\n"
              << "    --device-type \"ESP32-Gateway\" \\\n"
              << "    --hardware-version \"v2.1\" \\\n"
              << "    --sw-version \"1.2.3-rc.1+git.abc123\" \\\n"
              << "    --output update.crt \\\n"
              << "    --encrypted-output firmware.enc\n"
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

sum::SemVer ParseSemVer(const std::string& version_str) {
    sum::SemVer ver{};

    // Parse "major.minor.patch[-prerelease][+build]"
    size_t pos = 0;
    size_t dot1 = version_str.find('.');
    if (dot1 == std::string::npos) {
        throw std::runtime_error("Invalid semantic version format. Expected: major.minor.patch");
    }

    ver.major = std::stoul(version_str.substr(pos, dot1 - pos));
    pos = dot1 + 1;

    size_t dot2 = version_str.find('.', pos);
    if (dot2 == std::string::npos) {
        throw std::runtime_error("Invalid semantic version format. Expected: major.minor.patch");
    }

    ver.minor = std::stoul(version_str.substr(pos, dot2 - pos));
    pos = dot2 + 1;

    // Find patch (stops at - or +)
    size_t end_patch = version_str.find_first_of("-+", pos);
    if (end_patch == std::string::npos) {
        ver.patch = std::stoul(version_str.substr(pos));
        return ver;
    }

    ver.patch = std::stoul(version_str.substr(pos, end_patch - pos));
    pos = end_patch;

    // Parse prerelease (if present)
    if (version_str[pos] == '-') {
        ++pos;
        size_t plus_pos = version_str.find('+', pos);
        if (plus_pos == std::string::npos) {
            ver.prerelease = version_str.substr(pos);
            return ver;
        }
        ver.prerelease = version_str.substr(pos, plus_pos - pos);
        pos = plus_pos;
    }

    // Parse build metadata (if present)
    if (pos < version_str.length() && version_str[pos] == '+') {
        ++pos;
        ver.build_metadata = version_str.substr(pos);
    }

    return ver;
}

void WriteFile(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to create file: " + path);
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

int main(int argc, char* argv[]) {
    google::InitGoogleLogging(argv[0]);
    FLAGS_logtostderr = 1;

    std::string software_file;
    std::string device_pubkey_file;
    std::string backend_key_file;
    std::string backend_cert_file;
    std::string hardware_id;
    std::string manufacturer;
    std::string device_type;
    std::string hardware_version;
    std::string artifact_url;  // Optional artifact URL for manifest
    uint64_t version = 0;
    std::string sw_version_str;  // Semantic version string
    std::string output_file;
    std::string encrypted_output_file;
    bool use_encryption = true;
    int validity_days = 90;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            PrintUsage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--software") == 0 && i + 1 < argc) {
            software_file = argv[++i];
        } else if (strcmp(argv[i], "--device-pubkey") == 0 && i + 1 < argc) {
            device_pubkey_file = argv[++i];
        } else if (strcmp(argv[i], "--backend-key") == 0 && i + 1 < argc) {
            backend_key_file = argv[++i];
        } else if (strcmp(argv[i], "--backend-cert") == 0 && i + 1 < argc) {
            backend_cert_file = argv[++i];
        } else if (strcmp(argv[i], "--hardware-id") == 0 && i + 1 < argc) {
            hardware_id = argv[++i];
        } else if (strcmp(argv[i], "--manufacturer") == 0 && i + 1 < argc) {
            manufacturer = argv[++i];
        } else if (strcmp(argv[i], "--device-type") == 0 && i + 1 < argc) {
            device_type = argv[++i];
        } else if (strcmp(argv[i], "--hardware-version") == 0 && i + 1 < argc) {
            hardware_version = argv[++i];
        } else if (strcmp(argv[i], "--artifact-url") == 0 && i + 1 < argc) {
            artifact_url = argv[++i];
        } else if (strcmp(argv[i], "--sw-version") == 0 && i + 1 < argc) {
            sw_version_str = argv[++i];
        } else if (strcmp(argv[i], "--version") == 0 && i + 1 < argc) {
            version = std::stoull(argv[++i]);
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "--encrypted-output") == 0 && i + 1 < argc) {
            encrypted_output_file = argv[++i];
        } else if (strcmp(argv[i], "--validity-days") == 0 && i + 1 < argc) {
            validity_days = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "--no-encryption") == 0) {
            use_encryption = false;
        } else {
            LOG(ERROR) << "Unknown argument: " << argv[i];
            PrintUsage(argv[0]);
            return 1;
        }
    }

    // Validate required arguments
    if (software_file.empty() || device_pubkey_file.empty() ||
        backend_key_file.empty() || backend_cert_file.empty() ||
        hardware_id.empty() || manufacturer.empty() || device_type.empty() ||
        output_file.empty()) {
        LOG(ERROR) << "Missing required arguments";
        PrintUsage(argv[0]);
        return 1;
    }

    if (use_encryption && encrypted_output_file.empty()) {
        LOG(ERROR) << "--encrypted-output required when encryption is enabled";
        PrintUsage(argv[0]);
        return 1;
    }

    // Validate version (at least one required)
    if (sw_version_str.empty() && version == 0) {
        LOG(ERROR) << "Either --sw-version or --version required";
        PrintUsage(argv[0]);
        return 1;
    }

    try {
        LOG(INFO) << "Loading software from: " << software_file;
        auto software = ReadFile(software_file);
        LOG(INFO) << "Software size: " << software.size() << " bytes";

        LOG(INFO) << "Loading device public key from: " << device_pubkey_file;
        auto device_pubkey = sum::crypto::PublicKey::LoadFromFile(device_pubkey_file);

        LOG(INFO) << "Loading backend signing key from: " << backend_key_file;
        auto backend_key = sum::crypto::PrivateKey::LoadFromFile(backend_key_file);

        LOG(INFO) << "Loading backend CA certificate from: " << backend_cert_file;
        auto backend_cert = sum::crypto::Certificate::LoadFromFile(backend_cert_file);

        LOG(INFO) << "Creating manifest generator";
        sum::ManifestGenerator generator(backend_key, backend_cert);

        // Create device metadata
        sum::DeviceMetadata device_metadata;
        device_metadata.hardware_id = hardware_id;
        device_metadata.manufacturer = manufacturer;
        device_metadata.device_type = device_type;
        device_metadata.hardware_version = hardware_version;

        LOG(INFO) << "Generating update certificate chain (PEM bundle):";
        LOG(INFO) << "  Hardware ID: " << hardware_id;
        LOG(INFO) << "  Manufacturer: " << manufacturer;
        LOG(INFO) << "  Device Type: " << device_type;
        if (!hardware_version.empty()) {
            LOG(INFO) << "  Hardware Version: " << hardware_version;
        }
        LOG(INFO) << "  Encryption: " << (use_encryption ? "enabled" : "disabled");
        LOG(INFO) << "  Validity: " << validity_days << " days";

        std::string pem_chain;
        std::vector<uint8_t> output_software;

        if (!sw_version_str.empty()) {
            // Use semantic version (preferred)
            auto sw_version = ParseSemVer(sw_version_str);
            LOG(INFO) << "  Software Version: " << sw_version.ToString();

            auto result = generator.CreateCertificateChainPEM(
                software, device_pubkey, device_metadata, sw_version, use_encryption, validity_days, artifact_url
            );
            pem_chain = std::move(result.first);
            output_software = std::move(result.second);
        } else {
            // Use old version number (deprecated path)
            LOG(INFO) << "  Software Version: " << version << " (DEPRECATED: use --sw-version)";

            auto result = generator.CreateCertificateChainPEM(
                software, device_pubkey, device_metadata, version, use_encryption, validity_days, artifact_url
            );
            pem_chain = std::move(result.first);
            output_software = std::move(result.second);
        }

        LOG(INFO) << "Writing certificate chain (PEM bundle) to: " << output_file;
        std::ofstream pem_file(output_file);
        if (!pem_file) {
            throw std::runtime_error("Failed to open output file: " + output_file);
        }
        pem_file << pem_chain;
        pem_file.close();

        if (use_encryption) {
            LOG(INFO) << "Writing encrypted software to: " << encrypted_output_file;
            WriteFile(encrypted_output_file, output_software);
        }

        LOG(INFO) << "✅ Certificate chain generation complete";
        LOG(INFO) << "Distribution format: PEM certificate bundle (.crt)";
        LOG(INFO) << "Certificate chain file: " << output_file;
        LOG(INFO) << "  Contains: Update certificate + Intermediate CA certificate";
        if (use_encryption) {
            LOG(INFO) << "Encrypted software: " << encrypted_output_file;
            LOG(INFO) << "Encrypted size: " << output_software.size() << " bytes";
        }
        LOG(INFO) << "";
        LOG(INFO) << "Distribution: " << output_file << " + " << encrypted_output_file << " + ca.crt (root)";

        return 0;

    } catch (const std::exception& e) {
        LOG(ERROR) << "Fatal error: " << e.what();
        return 1;
    }
}
