/**
 * @file backend_example.cpp
 * @brief Example: Backend creating update certificates
 *
 * This example demonstrates how a backend server creates secure update
 * certificates for distribution to devices.
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum/common/crypto.h"
#include "sum/common/manifest.h"
#include "sum/backend/generator.h"
#include <glog/logging.h>
#include <fstream>
#include <iostream>
#include <vector>

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

// Helper to write file
void WriteFile(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot write file: " + path);
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

int main(int argc, char* argv[]) {
    google::InitGoogleLogging(argv[0]);
    FLAGS_logtostderr = 1;

    try {
        LOG(INFO) << "=== Backend Example: Creating Update Certificate ===";
        LOG(INFO) << "";

        // Step 1: Load intermediate CA credentials (PRODUCTION BEST PRACTICE)
        LOG(INFO) << "Step 1: Loading intermediate CA credentials...";
        LOG(INFO) << "";
        LOG(INFO) << "Production PKI hierarchy:";
        LOG(INFO) << "  - Root CA (ca.key): Kept offline in HSM";
        LOG(INFO) << "  - Intermediate CA (intermediate.key): Signs update certificates";
        LOG(INFO) << "  - Benefits: Root CA compromise much less likely";
        LOG(INFO) << "";

        auto intermediate_key = crypto::PrivateKey::LoadFromFile("intermediate.key");
        auto intermediate_cert = crypto::Certificate::LoadFromFile("intermediate.crt");
        LOG(INFO) << "  ✅ Intermediate CA credentials loaded";
        LOG(INFO) << "";

        // Step 2: Load device public key
        // In production, this would be retrieved from device database
        // using hardware_id as lookup key
        LOG(INFO) << "Step 2: Loading device public key...";
        auto device_pubkey = crypto::PublicKey::LoadFromFile("device.pub");
        LOG(INFO) << "  ✅ Device public key loaded";
        LOG(INFO) << "";

        // Step 3: Read firmware to be distributed
        LOG(INFO) << "Step 3: Reading firmware...";
        auto firmware = ReadFile("firmware.bin");
        LOG(INFO) << "  ✅ Firmware loaded (" << firmware.size() << " bytes)";
        LOG(INFO) << "";

        // Step 4: Create device metadata
        // This links the update to specific device characteristics
        LOG(INFO) << "Step 4: Creating device metadata...";
        DeviceMetadata device_meta;
        device_meta.hardware_id = "DEVICE-12345";      // Links to device_pubkey in DB
        device_meta.manufacturer = "Acme Corp";
        device_meta.device_type = "ESP32-Gateway";
        device_meta.hardware_version = "v2.1";

        LOG(INFO) << "  Hardware ID: " << device_meta.hardware_id;
        LOG(INFO) << "  Manufacturer: " << device_meta.manufacturer;
        LOG(INFO) << "  Device Type: " << device_meta.device_type;
        LOG(INFO) << "  Hardware Version: " << device_meta.hardware_version;
        LOG(INFO) << "";

        // Step 5: Generate update certificate chain (PRODUCTION BEST PRACTICE)
        LOG(INFO) << "Step 5: Generating update certificate chain...";
        LOG(INFO) << "  Creating PEM bundle: update cert + intermediate cert";
        LOG(INFO) << "  Signing with intermediate CA (not root CA)";

        ManifestGenerator generator(intermediate_key, intermediate_cert);

        auto [pem_chain, encrypted_firmware] = generator.CreateCertificateChainPEM(
            firmware,           // Software to distribute
            device_pubkey,      // Device's public key (for encryption)
            device_meta,        // Device metadata (for filtering)
            42,                 // Version number (for anti-rollback)
            true,               // Use encryption (recommended)
            90                  // Certificate validity (days)
        );

        LOG(INFO) << "  ✅ Certificate chain generated (PEM bundle)";
        LOG(INFO) << "  PEM chain size: " << pem_chain.size() << " bytes";
        LOG(INFO) << "  Encrypted firmware: " << encrypted_firmware.size() << " bytes";
        LOG(INFO) << "  Chain contains: update cert + intermediate cert";
        LOG(INFO) << "";

        // Step 6: Save for distribution
        LOG(INFO) << "Step 6: Saving update files...";
        // Save PEM chain as text file (contains update cert + intermediate cert)
        std::ofstream pem_file("update.crt");
        pem_file << pem_chain;
        pem_file.close();
        WriteFile("firmware.enc", encrypted_firmware);
        LOG(INFO) << "  ✅ Saved update.crt (PEM bundle with cert chain)";
        LOG(INFO) << "  ✅ Saved firmware.enc (encrypted firmware)";
        LOG(INFO) << "";
        LOG(INFO) << "update.crt contains:";
        LOG(INFO) << "  1. Update certificate (signed by intermediate CA)";
        LOG(INFO) << "  2. Intermediate CA certificate (signed by root CA)";
        LOG(INFO) << "";
        LOG(INFO) << "Device needs: update.crt (PEM chain) + firmware.enc + ca.crt (root)";
        LOG(INFO) << "";

        // Step 7: Distribution options
        LOG(INFO) << "=== Distribution Options ===";
        LOG(INFO) << "";
        LOG(INFO) << "Offline OTA (USB/SD card):";
        LOG(INFO) << "  1. Copy update.crt (PEM chain) and firmware.enc to USB";
        LOG(INFO) << "  2. Technician delivers to device";
        LOG(INFO) << "  3. Device applies update without internet";
        LOG(INFO) << "  4. Device verifies chain: update cert → intermediate → root CA";
        LOG(INFO) << "";
        LOG(INFO) << "Online OTA (HTTPS/MQTT/CoAP):";
        LOG(INFO) << "  1. Upload update.crt (PEM chain) and firmware.enc to server";
        LOG(INFO) << "  2. Device downloads via network";
        LOG(INFO) << "  3. Same security guarantees as offline";
        LOG(INFO) << "  4. Self-contained PEM bundle simplifies deployment";
        LOG(INFO) << "";

        LOG(INFO) << "✅ Backend example completed successfully!";
        return 0;

    } catch (const std::exception& e) {
        LOG(ERROR) << "Error: " << e.what();
        return 1;
    }
}
