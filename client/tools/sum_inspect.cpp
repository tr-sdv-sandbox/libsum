/**
 * @file sum_inspect.cpp
 * @brief Certificate inspection tool - dumps all fields including embedded manifests
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum/common/manifest.h"
#include "sum/common/crypto.h"
#include "manifest.pb.h"
#include <glog/logging.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <openssl/x509.h>
#include <openssl/obj_mac.h>
#include <openssl/bio.h>

#define MANIFEST_EXTENSION_OID "1.3.6.1.3.2"
#define DEVICE_METADATA_OID "1.3.6.1.3.1"

void PrintUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n"
              << "\n"
              << "Inspect libsum certificates and dump all fields including embedded manifests.\n"
              << "\n"
              << "Options:\n"
              << "  --cert FILE           Certificate file (PEM or DER format)\n"
              << "  --verbose             Show raw hex dumps of binary fields\n"
              << "  --json                Output manifest as JSON\n"
              << "\n"
              << "Examples:\n"
              << "  # Inspect update certificate\n"
              << "  " << program_name << " --cert update.crt\n"
              << "\n"
              << "  # Inspect with verbose hex dumps\n"
              << "  " << program_name << " --cert update.crt --verbose\n"
              << "\n"
              << "  # Show manifest as JSON\n"
              << "  " << program_name << " --cert update.crt --json\n"
              << std::endl;
}

std::string HexDump(const std::vector<uint8_t>& data, size_t max_bytes = 32) {
    std::ostringstream ss;
    size_t limit = std::min(data.size(), max_bytes);
    for (size_t i = 0; i < limit; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    if (data.size() > max_bytes) {
        ss << "... (" << data.size() << " bytes total)";
    }
    return ss.str();
}

std::string FormatTime(const ASN1_TIME* time) {
    BIO* bio = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio, time);

    char* data;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);

    return result;
}

void InspectX509Certificate(X509* x509, bool verbose) {
    std::cout << "\n=== X.509 Certificate Structure ===\n\n";

    // Version
    std::cout << "Version: " << (X509_get_version(x509) + 1) << "\n";

    // Serial number
    ASN1_INTEGER* serial = X509_get_serialNumber(x509);
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
    char* serial_str = BN_bn2hex(bn);
    std::cout << "Serial Number: " << serial_str << "\n";
    OPENSSL_free(serial_str);
    BN_free(bn);

    // Subject
    char subject[256];
    X509_NAME_oneline(X509_get_subject_name(x509), subject, sizeof(subject));
    std::cout << "Subject: " << subject << "\n";

    // Issuer
    char issuer[256];
    X509_NAME_oneline(X509_get_issuer_name(x509), issuer, sizeof(issuer));
    std::cout << "Issuer: " << issuer << "\n";

    // Validity
    std::cout << "Valid From: " << FormatTime(X509_get0_notBefore(x509)) << "\n";
    std::cout << "Valid Until: " << FormatTime(X509_get0_notAfter(x509)) << "\n";

    // Public key
    EVP_PKEY* pkey = X509_get_pubkey(x509);
    int key_type = EVP_PKEY_id(pkey);
    std::cout << "Public Key Algorithm: ";
    if (key_type == EVP_PKEY_ED25519) {
        std::cout << "Ed25519\n";
    } else if (key_type == EVP_PKEY_X25519) {
        std::cout << "X25519\n";
    } else {
        std::cout << "Other (" << key_type << ")\n";
    }
    EVP_PKEY_free(pkey);

    // Extensions
    int ext_count = X509_get_ext_count(x509);
    std::cout << "\nExtensions (" << ext_count << "):\n";

    for (int i = 0; i < ext_count; i++) {
        X509_EXTENSION* ext = X509_get_ext(x509, i);
        ASN1_OBJECT* obj = X509_EXTENSION_get_object(ext);

        char oid_buf[128];
        OBJ_obj2txt(oid_buf, sizeof(oid_buf), obj, 1);

        const char* name = OBJ_nid2ln(OBJ_obj2nid(obj));
        if (!name) name = "Unknown";

        std::cout << "  [" << (i+1) << "] " << name << " (" << oid_buf << ")\n";
        std::cout << "      Critical: " << (X509_EXTENSION_get_critical(ext) ? "Yes" : "No") << "\n";

        ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(ext);
        std::cout << "      Data: " << ASN1_STRING_length(data) << " bytes\n";

        if (verbose) {
            const unsigned char* p = ASN1_STRING_get0_data(data);
            std::vector<uint8_t> ext_data(p, p + ASN1_STRING_length(data));
            std::cout << "      Hex: " << HexDump(ext_data, 64) << "\n";
        }
    }
}

void InspectDeviceMetadata(const sum::crypto::Certificate& cert) {
    if (!cert.HasDeviceMetadata()) {
        std::cout << "\n⚠️  No device metadata extension found\n";
        return;
    }

    std::cout << "\n=== Device Metadata ===\n\n";

    try {
        auto metadata = cert.GetDeviceMetadata();
        std::cout << "Device Type:       " << metadata.device_type << "\n";
        std::cout << "Hardware ID:       " << metadata.hardware_id << "\n";
        std::cout << "Manufacturer:      " << metadata.manufacturer << "\n";
        if (!metadata.hardware_version.empty()) {
            std::cout << "Hardware Version:  " << metadata.hardware_version << "\n";
        }
    } catch (const std::exception& e) {
        std::cout << "⚠️  Failed to parse device metadata: " << e.what() << "\n";
    }
}

void InspectManifest(X509* x509, bool verbose, bool json_output) {
    ASN1_OBJECT* manifest_oid = OBJ_txt2obj(MANIFEST_EXTENSION_OID, 1);
    int ext_idx = X509_get_ext_by_OBJ(x509, manifest_oid, -1);
    ASN1_OBJECT_free(manifest_oid);

    if (ext_idx < 0) {
        std::cout << "\n⚠️  No manifest extension found\n";
        return;
    }

    X509_EXTENSION* ext = X509_get_ext(x509, ext_idx);
    ASN1_OCTET_STRING* ext_data = X509_EXTENSION_get_data(ext);

    std::vector<uint8_t> manifest_data(
        ASN1_STRING_get0_data(ext_data),
        ASN1_STRING_get0_data(ext_data) + ASN1_STRING_length(ext_data)
    );

    std::cout << "\n=== Embedded Manifest ===\n\n";
    std::cout << "Manifest size: " << manifest_data.size() << " bytes\n";

    if (verbose) {
        std::cout << "Raw hex (first 128 bytes): " << HexDump(manifest_data, 128) << "\n";
    }

    // Parse manifest
    try {
        auto manifest = sum::Manifest::LoadFromProtobuf(manifest_data);

        std::cout << "\n--- Manifest Fields ---\n\n";
        std::cout << "Schema version: " << manifest.GetVersion() << "\n";
        std::cout << "Manifest version: " << manifest.GetManifestVersion() << "\n";
        std::cout << "Release counter: " << manifest.GetReleaseCounter() << "\n";

        // Display semantic version if present
        auto sw_version = manifest.GetSoftwareVersion();
        if (sw_version.has_value()) {
            std::cout << "Software version: " << sw_version->ToString() << "\n";
        }

        // Signature
        auto signature = manifest.GetSignature();
        std::cout << "\nSignature: " << signature.size() << " bytes";
        if (verbose && !signature.empty()) {
            std::cout << "\n  Hex: " << HexDump(signature);
        }
        std::cout << "\n";

        // Signing certificate
        auto signing_cert = manifest.GetSigningCertificate();
        std::cout << "Signing Certificate: " << signing_cert.size() << " bytes";
        if (verbose && !signing_cert.empty()) {
            std::cout << "\n  Hex: " << HexDump(signing_cert, 64);
        }
        std::cout << "\n";

        // Artifacts
        auto artifacts = manifest.GetArtifacts();
        std::cout << "\nArtifacts (" << artifacts.size() << "):\n";
        for (size_t i = 0; i < artifacts.size(); i++) {
            const auto& a = artifacts[i];
            std::cout << "\n  [" << (i+1) << "] " << a.name << "\n";
            std::cout << "      Type: " << a.type << "\n";
            std::cout << "      Target ECU: " << a.target_ecu << "\n";
            std::cout << "      Install Order: " << a.install_order << "\n";
            std::cout << "      Hash Algorithm: " << a.hash_algorithm << "\n";
            std::cout << "      Expected Hash: " << HexDump(a.expected_hash) << "\n";
            std::cout << "      Plaintext Size: " << a.size << " bytes\n";
            std::cout << "      Ciphertext Hash: " << HexDump(a.ciphertext_hash) << "\n";
            std::cout << "      Ciphertext Size: " << a.ciphertext_size << " bytes\n";
            std::cout << "      Signature Algorithm: " << a.signature_algorithm << "\n";
            std::cout << "      Signature: " << HexDump(a.signature) << "\n";
            std::cout << "      Content Addressable: " << (a.content_addressable ? "Yes" : "No") << "\n";

            if (!a.sources.empty()) {
                std::cout << "      Sources:\n";
                for (const auto& src : a.sources) {
                    std::cout << "        - URI: " << src.uri << " (priority: " << src.priority << ")\n";
                }
            }
        }

        // Encryption params
        auto encryption = manifest.GetEncryptionParams();
        std::cout << "\nEncryption Parameters (" << encryption.size() << "):\n";
        for (size_t i = 0; i < encryption.size(); i++) {
            const auto& e = encryption[i];
            std::cout << "\n  [" << (i+1) << "] Artifact: " << e.artifact_name << "\n";
            std::cout << "      Device ID: " << e.device_id << "\n";
            std::cout << "      Algorithm: " << e.algorithm << "\n";
            std::cout << "      IV: " << HexDump(e.iv) << "\n";
            std::cout << "      Tag: " << HexDump(e.tag) << "\n";
            std::cout << "      Key Wrapping: " << e.key_wrapping_algorithm << "\n";
            std::cout << "      Wrapped Key: " << HexDump(e.wrapped_key, 64) << "\n";
        }

        // JSON output
        if (json_output) {
            std::cout << "\n=== Manifest as JSON ===\n\n";
            std::cout << manifest.ToDebugJSON() << "\n";
        }

    } catch (const std::exception& e) {
        std::cout << "\n❌ Failed to parse manifest: " << e.what() << "\n";
    }
}

int main(int argc, char* argv[]) {
    google::InitGoogleLogging(argv[0]);

    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    std::string cert_file;
    bool verbose = false;
    bool json_output = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--cert" && i + 1 < argc) {
            cert_file = argv[++i];
        } else if (arg == "--verbose") {
            verbose = true;
        } else if (arg == "--json") {
            json_output = true;
        } else if (arg == "--help" || arg == "-h") {
            PrintUsage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown option: " << arg << "\n\n";
            PrintUsage(argv[0]);
            return 1;
        }
    }

    if (cert_file.empty()) {
        std::cerr << "Error: --cert is required\n\n";
        PrintUsage(argv[0]);
        return 1;
    }

    try {
        LOG(INFO) << "Loading certificate: " << cert_file;

        // Load certificate (handles both PEM and DER)
        auto cert = sum::crypto::Certificate::LoadFromFile(cert_file);
        auto der = cert.ToDER();

        std::cout << "\n╔════════════════════════════════════════════════════════════╗\n";
        std::cout << "║  libsum Certificate Inspector                             ║\n";
        std::cout << "╚════════════════════════════════════════════════════════════╝\n";
        std::cout << "\nCertificate: " << cert_file << "\n";
        std::cout << "Size: " << der.size() << " bytes\n";

        // Parse with OpenSSL
        const unsigned char* der_ptr = der.data();
        X509* x509 = d2i_X509(nullptr, &der_ptr, der.size());
        if (!x509) {
            std::cerr << "Failed to parse X.509 structure\n";
            return 1;
        }

        // Inspect certificate
        InspectX509Certificate(x509, verbose);

        // Inspect device metadata
        InspectDeviceMetadata(cert);

        // Inspect manifest
        InspectManifest(x509, verbose, json_output);

        X509_free(x509);

        std::cout << "\n✅ Inspection complete\n\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
