/**
 * @file sum_build_manifest.cpp
 * @brief Multi-artifact manifest builder with JSON metadata
 *
 * Production workflow:
 * 1. sum-build-manifest encrypt firmware.bin firmware.enc firmware.json
 * 2. Store firmware.enc + firmware.json in database
 * 3. sum-build-manifest build --artifacts firmware.json,bootloader.json ...
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum/backend/manifest_builder.h"
#include "sum/common/crypto.h"
#include <glog/logging.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

using json = nlohmann::json;

// Helper functions for encoding
std::string Base64Encode(const std::vector<uint8_t>& data) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);

    return result;
}

std::vector<uint8_t> Base64Decode(const std::string& encoded) {
    BIO *bio, *b64;

    bio = BIO_new_mem_buf(encoded.data(), encoded.length());
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    std::vector<uint8_t> result(encoded.length());
    int decoded_len = BIO_read(bio, result.data(), encoded.length());
    BIO_free_all(bio);

    result.resize(decoded_len);
    return result;
}

std::string HexEncode(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : data) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
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

void PrintUsageEncrypt(const char* program_name) {
    std::cout << "Usage: " << program_name << " encrypt [OPTIONS]\n"
              << "\n"
              << "Encrypt software artifact and generate JSON metadata.\n"
              << "The encrypted file and metadata can be stored in a database\n"
              << "and reused for all devices (only wrap keys per-device).\n"
              << "\n"
              << "Required:\n"
              << "  --input FILE              Input software binary\n"
              << "  --output FILE             Output encrypted file (.enc)\n"
              << "  --metadata FILE           Output JSON metadata file\n"
              << "\n"
              << "Example:\n"
              << "  " << program_name << " encrypt \\\n"
              << "    --input firmware.bin \\\n"
              << "    --output firmware.enc \\\n"
              << "    --metadata firmware.json\n"
              << std::endl;
}

void PrintUsageBuild(const char* program_name) {
    std::cout << "Usage: " << program_name << " build [OPTIONS]\n"
              << "\n"
              << "Build multi-artifact manifest from pre-encrypted artifacts.\n"
              << "\n"
              << "Required:\n"
              << "  --artifact NAME:METADATA  Add artifact (can be repeated)\n"
              << "                            NAME: artifact identifier (e.g., 'firmware')\n"
              << "                            METADATA: JSON file from encrypt command\n"
              << "  --device-pubkey FILE      Device X25519 public key (PEM)\n"
              << "  --hardware-id ID          Device hardware ID\n"
              << "  --manufacturer NAME       Device manufacturer\n"
              << "  --device-type TYPE        Device type/model\n"
              << "  --backend-key FILE        Backend signing key (intermediate CA)\n"
              << "  --backend-cert FILE       Backend certificate (intermediate CA)\n"
              << "  --output FILE             Output certificate file (.crt)\n"
              << "\n"
              << "Version Options:\n"
              << "  --manifest-version NUM    Manifest version (monotonic counter, per-manifest) [required]\n"
              << "                            Used for replay protection (must increase per manifest)\n"
              << "\n"
              << "Optional:\n"
              << "  --hardware-version VER    Hardware version\n"
              << "  --validity-days DAYS      Certificate validity (default: 90)\n"
              << "  --type NAME:TYPE          Set artifact type (default: firmware)\n"
              << "  --target NAME:ECU         Set target ECU (default: primary)\n"
              << "  --order NAME:ORDER        Set install order (default: 0)\n"
              << "  --source NAME:URI:PRIO    Add download source\n"
              << "\n"
              << "Example:\n"
              << "  " << program_name << " build \\\n"
              << "    --artifact bootloader:bootloader.json \\\n"
              << "    --artifact firmware:firmware.json \\\n"
              << "    --type bootloader:bootloader \\\n"
              << "    --type firmware:firmware \\\n"
              << "    --order bootloader:0 \\\n"
              << "    --order firmware:1 \\\n"
              << "    --device-pubkey device.pub \\\n"
              << "    --hardware-id ESP32-001 \\\n"
              << "    --manufacturer \"Acme Corp\" \\\n"
              << "    --device-type \"ESP32-Gateway\" \\\n"
              << "    --backend-key intermediate.key \\\n"
              << "    --backend-cert intermediate.crt \\\n"
              << "    --manifest-version 1 \\\n"
              << "    --output update.crt\n"
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

void WriteFile(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to create file: " + path);
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

json EncryptedArtifactToJSON(const sum::EncryptedArtifact& artifact) {
    json j;
    j["aes_key"] = Base64Encode(artifact.aes_key);
    j["iv"] = Base64Encode(artifact.iv);
    j["tag"] = Base64Encode(artifact.tag);
    j["plaintext_hash"] = Base64Encode(artifact.plaintext_hash);
    j["plaintext_size"] = artifact.plaintext_size;
    j["ciphertext_hash"] = Base64Encode(artifact.ciphertext_hash);
    j["ciphertext_size"] = artifact.ciphertext_size;
    return j;
}

sum::EncryptedArtifact JSONToEncryptedArtifact(const json& j, const std::string& encrypted_file) {
    sum::EncryptedArtifact artifact;
    artifact.encrypted_data = ReadFile(encrypted_file);
    artifact.aes_key = Base64Decode(j["aes_key"]);
    artifact.iv = Base64Decode(j["iv"]);
    artifact.tag = Base64Decode(j["tag"]);
    artifact.plaintext_hash = Base64Decode(j["plaintext_hash"]);
    artifact.plaintext_size = j["plaintext_size"];
    artifact.ciphertext_hash = Base64Decode(j["ciphertext_hash"]);
    artifact.ciphertext_size = j["ciphertext_size"];
    return artifact;
}

int CommandEncrypt(int argc, char* argv[]) {
    std::string input_file;
    std::string output_file;
    std::string metadata_file;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--input") == 0 && i + 1 < argc) {
            input_file = argv[++i];
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "--metadata") == 0 && i + 1 < argc) {
            metadata_file = argv[++i];
        } else {
            LOG(ERROR) << "Unknown argument: " << argv[i];
            PrintUsageEncrypt(argv[0]);
            return 1;
        }
    }

    if (input_file.empty() || output_file.empty() || metadata_file.empty()) {
        LOG(ERROR) << "Missing required arguments";
        PrintUsageEncrypt(argv[0]);
        return 1;
    }

    try {
        LOG(INFO) << "Reading software from: " << input_file;
        auto plaintext = ReadFile(input_file);
        LOG(INFO) << "Software size: " << plaintext.size() << " bytes";

        LOG(INFO) << "Encrypting with AES-128-GCM...";
        auto encrypted = sum::EncryptSoftware(plaintext);

        LOG(INFO) << "Writing encrypted file: " << output_file;
        WriteFile(output_file, encrypted.encrypted_data);

        LOG(INFO) << "Writing metadata: " << metadata_file;
        json metadata = EncryptedArtifactToJSON(encrypted);
        metadata["encrypted_file"] = output_file;  // Store reference
        std::ofstream meta_out(metadata_file);
        meta_out << metadata.dump(2);

        LOG(INFO) << "✅ Encryption complete";
        LOG(INFO) << "   Encrypted file: " << output_file << " (" << encrypted.ciphertext_size << " bytes)";
        LOG(INFO) << "   Metadata: " << metadata_file;
        LOG(INFO) << "   Plaintext hash: " << HexEncode(encrypted.plaintext_hash);
        LOG(INFO) << "   Ciphertext hash: " << HexEncode(encrypted.ciphertext_hash);

        return 0;
    } catch (const std::exception& e) {
        LOG(ERROR) << "Error: " << e.what();
        return 1;
    }
}

int CommandBuild(int argc, char* argv[]) {
    struct ArtifactConfig {
        std::string name;
        std::string metadata_file;
        std::string type;
        std::string target_ecu;
        uint32_t install_order = 0;
        std::vector<sum::Source> sources;
    };

    std::vector<ArtifactConfig> artifacts;
    std::string device_pubkey_file;
    std::string hardware_id;
    std::string manufacturer;
    std::string device_type;
    std::string hardware_version;
    std::string backend_key_file;
    std::string backend_cert_file;
    uint64_t manifest_version = 0;
    std::string output_file;
    int validity_days = 90;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--artifact") == 0 && i + 1 < argc) {
            std::string arg = argv[++i];
            size_t colon = arg.find(':');
            if (colon == std::string::npos) {
                LOG(ERROR) << "Invalid --artifact format: " << arg;
                return 1;
            }
            ArtifactConfig config;
            config.name = arg.substr(0, colon);
            config.metadata_file = arg.substr(colon + 1);
            artifacts.push_back(config);
        } else if (strcmp(argv[i], "--type") == 0 && i + 1 < argc) {
            std::string arg = argv[++i];
            size_t colon = arg.find(':');
            if (colon == std::string::npos) continue;
            std::string name = arg.substr(0, colon);
            std::string type = arg.substr(colon + 1);
            for (auto& a : artifacts) {
                if (a.name == name) a.type = type;
            }
        } else if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) {
            std::string arg = argv[++i];
            size_t colon = arg.find(':');
            if (colon == std::string::npos) continue;
            std::string name = arg.substr(0, colon);
            std::string target = arg.substr(colon + 1);
            for (auto& a : artifacts) {
                if (a.name == name) a.target_ecu = target;
            }
        } else if (strcmp(argv[i], "--order") == 0 && i + 1 < argc) {
            std::string arg = argv[++i];
            size_t colon = arg.find(':');
            if (colon == std::string::npos) continue;
            std::string name = arg.substr(0, colon);
            uint32_t order = std::stoul(arg.substr(colon + 1));
            for (auto& a : artifacts) {
                if (a.name == name) a.install_order = order;
            }
        } else if (strcmp(argv[i], "--source") == 0 && i + 1 < argc) {
            std::string arg = argv[++i];
            // Format: name:uri:priority
            size_t colon1 = arg.find(':');
            size_t colon2 = arg.rfind(':');  // Find LAST colon (before priority)
            if (colon1 == std::string::npos || colon2 == std::string::npos || colon1 == colon2) continue;
            std::string name = arg.substr(0, colon1);
            std::string uri = arg.substr(colon1 + 1, colon2 - colon1 - 1);
            uint32_t priority = std::stoul(arg.substr(colon2 + 1));
            sum::Source source{uri, priority, ""};
            for (auto& a : artifacts) {
                if (a.name == name) a.sources.push_back(source);
            }
        } else if (strcmp(argv[i], "--device-pubkey") == 0 && i + 1 < argc) {
            device_pubkey_file = argv[++i];
        } else if (strcmp(argv[i], "--hardware-id") == 0 && i + 1 < argc) {
            hardware_id = argv[++i];
        } else if (strcmp(argv[i], "--manufacturer") == 0 && i + 1 < argc) {
            manufacturer = argv[++i];
        } else if (strcmp(argv[i], "--device-type") == 0 && i + 1 < argc) {
            device_type = argv[++i];
        } else if (strcmp(argv[i], "--hardware-version") == 0 && i + 1 < argc) {
            hardware_version = argv[++i];
        } else if (strcmp(argv[i], "--backend-key") == 0 && i + 1 < argc) {
            backend_key_file = argv[++i];
        } else if (strcmp(argv[i], "--backend-cert") == 0 && i + 1 < argc) {
            backend_cert_file = argv[++i];
        } else if (strcmp(argv[i], "--manifest-version") == 0 && i + 1 < argc) {
            manifest_version = std::stoull(argv[++i]);
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "--validity-days") == 0 && i + 1 < argc) {
            validity_days = std::stoi(argv[++i]);
        }
    }

    if (artifacts.empty() || device_pubkey_file.empty() || hardware_id.empty() ||
        manufacturer.empty() || device_type.empty() || backend_key_file.empty() ||
        backend_cert_file.empty() || output_file.empty()) {
        LOG(ERROR) << "Missing required arguments";
        PrintUsageBuild(argv[0]);
        return 1;
    }

    try {
        LOG(INFO) << "Loading backend credentials...";
        auto backend_key = sum::crypto::PrivateKey::LoadFromFile(backend_key_file);
        auto backend_cert = sum::crypto::Certificate::LoadFromFile(backend_cert_file);
        auto device_pubkey = sum::crypto::PublicKey::LoadFromFile(device_pubkey_file);

        sum::DeviceMetadata device_metadata;
        device_metadata.hardware_id = hardware_id;
        device_metadata.manufacturer = manufacturer;
        device_metadata.device_type = device_type;
        device_metadata.hardware_version = hardware_version;

        LOG(INFO) << "Building manifest for device: " << hardware_id;
        sum::ManifestBuilder builder(backend_key, backend_cert);

        for (const auto& config : artifacts) {
            LOG(INFO) << "Loading artifact: " << config.name;
            std::ifstream meta_in(config.metadata_file);
            json metadata;
            meta_in >> metadata;

            std::string encrypted_file = metadata["encrypted_file"];
            auto encrypted = JSONToEncryptedArtifact(metadata, encrypted_file);

            auto& artifact_builder = builder.AddArtifact(config.name, encrypted);
            if (!config.type.empty()) {
                artifact_builder.SetType(config.type);
            }
            if (!config.target_ecu.empty()) {
                artifact_builder.SetTargetECU(config.target_ecu);
            }
            artifact_builder.SetInstallOrder(config.install_order);
            for (const auto& source : config.sources) {
                artifact_builder.AddSource(source.uri, source.priority);
            }
        }

        LOG(INFO) << "Building certificate chain...";

        // Validate manifest version
        if (manifest_version == 0) {
            LOG(ERROR) << "Missing required argument: --manifest-version (must be > 0)";
            return 1;
        }
        auto [pem_bundle, encrypted_files] = builder.BuildCertificateChainPEM(
            device_pubkey, device_metadata, manifest_version, validity_days
        );

        LOG(INFO) << "Writing certificate: " << output_file;
        std::ofstream cert_out(output_file);
        cert_out << pem_bundle;

        LOG(INFO) << "✅ Manifest generation complete";
        LOG(INFO) << "   Certificate: " << output_file;
        LOG(INFO) << "   Artifacts: " << artifacts.size();
        LOG(INFO) << "   Device: " << hardware_id;
        LOG(INFO) << "   Manifest Version: " << manifest_version;

        return 0;
    } catch (const std::exception& e) {
        LOG(ERROR) << "Error: " << e.what();
        return 1;
    }
}

int main(int argc, char* argv[]) {
    google::InitGoogleLogging(argv[0]);
    FLAGS_logtostderr = 1;

    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <command> [OPTIONS]\n"
                  << "\n"
                  << "Commands:\n"
                  << "  encrypt    Encrypt software and generate JSON metadata\n"
                  << "  build      Build multi-artifact manifest from JSON metadata\n"
                  << "\n"
                  << "Use '" << argv[0] << " <command> --help' for more information\n"
                  << std::endl;
        return 1;
    }

    std::string command = argv[1];

    if (command == "encrypt") {
        if (argc > 2 && strcmp(argv[2], "--help") == 0) {
            PrintUsageEncrypt(argv[0]);
            return 0;
        }
        return CommandEncrypt(argc, argv);
    } else if (command == "build") {
        if (argc > 2 && strcmp(argv[2], "--help") == 0) {
            PrintUsageBuild(argv[0]);
            return 0;
        }
        return CommandBuild(argc, argv);
    } else {
        LOG(ERROR) << "Unknown command: " << command;
        return 1;
    }
}
