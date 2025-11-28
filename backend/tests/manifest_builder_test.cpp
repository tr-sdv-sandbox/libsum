/**
 * @file manifest_builder_test.cpp
 * @brief Unit tests for ManifestBuilder API
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "sum/backend/manifest_builder.h"
#include "sum/common/crypto.h"
#include "sum/common/manifest.h"

using namespace sum;

class ManifestBuilderTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Generate Root CA key pair
        root_key_ = crypto::PrivateKey::Generate(crypto::KeyType::Ed25519);

        // Create self-signed root CA
        root_cert_ = CreateCACertificate(
            root_key_,
            crypto::PublicKey::FromPrivateKey(root_key_),
            "Test Root CA",
            3650  // 10 years
        );

        // Generate Intermediate CA key pair
        intermediate_key_ = crypto::PrivateKey::Generate(crypto::KeyType::Ed25519);
        auto intermediate_pubkey = crypto::PublicKey::FromPrivateKey(intermediate_key_);

        // Create intermediate CA (signed by root)
        intermediate_cert_ = CreateCACertificate(
            root_key_,
            intermediate_pubkey,
            "Test Intermediate CA",
            1825,  // 5 years
            &root_cert_
        );

        // Generate device key pair (X25519)
        device_key_ = crypto::PrivateKey::Generate(crypto::KeyType::X25519);
        device_pubkey_ = crypto::PublicKey::FromPrivateKey(device_key_);

        device_metadata_.hardware_id = "TEST-DEVICE-001";
        device_metadata_.manufacturer = "Test Manufacturer";
        device_metadata_.device_type = "Test-Device";
        device_metadata_.hardware_version = "v1.0";
    }

    crypto::PrivateKey root_key_;
    crypto::Certificate root_cert_;
    crypto::PrivateKey intermediate_key_;
    crypto::Certificate intermediate_cert_;
    crypto::PrivateKey device_key_;
    crypto::PublicKey device_pubkey_;
    DeviceMetadata device_metadata_;
};

// ============================================================================
// EncryptSoftware Tests
// ============================================================================

TEST_F(ManifestBuilderTest, EncryptSoftware) {
    std::vector<uint8_t> plaintext(1024, 0x42);

    auto encrypted = EncryptSoftware(plaintext);

    // Verify all fields are populated
    EXPECT_EQ(encrypted.aes_key.size(), 16);  // AES-128
    EXPECT_EQ(encrypted.iv.size(), 12);       // GCM IV
    EXPECT_EQ(encrypted.tag.size(), 16);      // GCM tag
    EXPECT_EQ(encrypted.plaintext_hash.size(), 32);  // SHA-256
    EXPECT_EQ(encrypted.plaintext_size, 1024);
    EXPECT_EQ(encrypted.ciphertext_hash.size(), 32); // SHA-256
    EXPECT_EQ(encrypted.ciphertext_size, 1024);      // AES-GCM doesn't expand
    EXPECT_FALSE(encrypted.encrypted_data.empty());
}

TEST_F(ManifestBuilderTest, EncryptSoftwareReusable) {
    std::vector<uint8_t> plaintext(512, 0xAB);

    // Encrypt once
    auto encrypted = EncryptSoftware(plaintext);

    // Should be able to reuse encrypted data for multiple devices
    // (just wrap the AES key differently for each device)
    EXPECT_FALSE(encrypted.aes_key.empty());
    EXPECT_FALSE(encrypted.encrypted_data.empty());
}

// ============================================================================
// ManifestBuilder Tests
// ============================================================================

TEST_F(ManifestBuilderTest, BuildSingleArtifactManifest) {
    std::vector<uint8_t> firmware(2048, 0x55);
    auto encrypted = EncryptSoftware(firmware);

    ManifestBuilder builder(intermediate_key_, intermediate_cert_);

    builder.AddArtifact("firmware", encrypted)
        .SetType("firmware")
        .SetTargetECU("primary")
        .SetInstallOrder(0);

    auto [cert, encrypted_files] = builder.BuildCertificate(
        device_pubkey_, device_metadata_, 1, 365
    );

    // Verify encrypted file is present
    EXPECT_EQ(encrypted_files.size(), 1);
    EXPECT_TRUE(encrypted_files.count("firmware"));
    EXPECT_EQ(encrypted_files["firmware"], encrypted.encrypted_data);
}

TEST_F(ManifestBuilderTest, BuildMultiArtifactManifest) {
    std::vector<uint8_t> bootloader(1024, 0xBB);
    std::vector<uint8_t> firmware(4096, 0xFF);

    auto encrypted_bootloader = EncryptSoftware(bootloader);
    auto encrypted_firmware = EncryptSoftware(firmware);

    ManifestBuilder builder(intermediate_key_, intermediate_cert_);

    builder.AddArtifact("bootloader", encrypted_bootloader)
        .SetType("bootloader")
        .SetInstallOrder(0);

    builder.AddArtifact("firmware", encrypted_firmware)
        .SetType("firmware")
        .SetInstallOrder(1);

    auto [cert, encrypted_files] = builder.BuildCertificate(
        device_pubkey_, device_metadata_, 1, 365
    );

    // Verify both encrypted files are present
    EXPECT_EQ(encrypted_files.size(), 2);
    EXPECT_TRUE(encrypted_files.count("bootloader"));
    EXPECT_TRUE(encrypted_files.count("firmware"));
}

// ============================================================================
// Critical Test: Verify Manifest Has All Required Fields
// ============================================================================

TEST_F(ManifestBuilderTest, ManifestHasAllRequiredFields) {
    std::vector<uint8_t> firmware(1024, 0x33);
    auto encrypted = EncryptSoftware(firmware);

    ManifestBuilder builder(intermediate_key_, intermediate_cert_);

    builder.AddArtifact("firmware", encrypted)
        .SetType("firmware")
        .SetInstallOrder(0);

    auto [cert_unverified, encrypted_files] = builder.BuildCertificate(
        device_pubkey_, device_metadata_, 1, 365
    );

    // Serialize and reload with verification (tests real workflow)
    std::string pem = cert_unverified.ToPEM();
    auto cert = crypto::UpdateCertificate::LoadFromPEM(pem, root_cert_, time(nullptr));

    // Extract manifest (already verified at load time)
    Manifest manifest = cert.GetManifest();

    // Verify critical fields
    EXPECT_EQ(manifest.GetManifestVersion(), 1);
    EXPECT_EQ(manifest.GetArtifacts().size(), 1);
    EXPECT_EQ(manifest.GetEncryptionParams().size(), 1);

    // CRITICAL: Verify signing certificate is present
    // This field is required for nanopb parsing and signature verification
    auto signing_cert = manifest.GetSigningCertificate();
    EXPECT_FALSE(signing_cert.empty())
        << "Signing certificate MUST be present in manifest for verification";

    // Verify signing cert matches intermediate cert
    auto intermediate_der = intermediate_cert_.ToDER();
    EXPECT_EQ(signing_cert, intermediate_der)
        << "Signing certificate should match the intermediate CA certificate";

    // Verify signature is present
    auto signature = manifest.GetSignature();
    EXPECT_FALSE(signature.empty())
        << "Signature MUST be present in manifest";
    EXPECT_EQ(signature.size(), 64)  // Ed25519 signature
        << "Ed25519 signature should be 64 bytes";
}

TEST_F(ManifestBuilderTest, ManifestCanRoundTripThroughProtobuf) {
    std::vector<uint8_t> firmware(512, 0x77);
    auto encrypted = EncryptSoftware(firmware);

    ManifestBuilder builder(intermediate_key_, intermediate_cert_);
    builder.AddArtifact("app", encrypted).SetType("firmware");

    auto [cert_unverified, encrypted_files] = builder.BuildCertificate(
        device_pubkey_, device_metadata_, 42, 365
    );

    // Serialize and reload with verification
    std::string pem = cert_unverified.ToPEM();
    auto cert = crypto::UpdateCertificate::LoadFromPEM(pem, root_cert_, time(nullptr));

    // Extract manifest (already verified)
    Manifest manifest = cert.GetManifest();

    // Re-serialize
    auto re_serialized = manifest.ToProtobuf();

    // Should be able to load again
    Manifest manifest2 = Manifest::LoadFromProtobuf(re_serialized);

    EXPECT_EQ(manifest2.GetManifestVersion(), 42);
    EXPECT_EQ(manifest2.GetArtifacts().size(), 1);
    EXPECT_FALSE(manifest2.GetSigningCertificate().empty());
}

// ============================================================================
// PEM Chain Tests
// ============================================================================

TEST_F(ManifestBuilderTest, BuildCertificateChainPEM) {
    std::vector<uint8_t> firmware(256, 0xCC);
    auto encrypted = EncryptSoftware(firmware);

    ManifestBuilder builder(intermediate_key_, intermediate_cert_);
    builder.AddArtifact("fw", encrypted);

    auto [pem_chain, encrypted_files] = builder.BuildCertificateChainPEM(
        device_pubkey_, device_metadata_, 1, 365
    );

    // Verify PEM chain contains both certificates
    EXPECT_NE(pem_chain.find("-----BEGIN CERTIFICATE-----"), std::string::npos);
    EXPECT_NE(pem_chain.find("-----END CERTIFICATE-----"), std::string::npos);

    // Should have update cert + intermediate cert
    size_t first_begin = pem_chain.find("-----BEGIN CERTIFICATE-----");
    size_t second_begin = pem_chain.find("-----BEGIN CERTIFICATE-----", first_begin + 1);
    EXPECT_NE(second_begin, std::string::npos)
        << "PEM chain should contain both update and intermediate certificates";
}

// ============================================================================
// Metadata Tests
// ============================================================================

TEST_F(ManifestBuilderTest, SetManifestMetadata) {
    std::vector<uint8_t> firmware(128, 0xEE);
    auto encrypted = EncryptSoftware(firmware);

    ManifestBuilder builder(intermediate_key_, intermediate_cert_);
    builder.AddMetadata("vendor", "TestVendor")
           .AddMetadata("release_notes", "Bug fixes")
           .AddArtifact("fw", encrypted);

    auto [cert_unverified, encrypted_files] = builder.BuildCertificate(
        device_pubkey_, device_metadata_, 1, 365
    );

    // Serialize and reload with verification
    std::string pem = cert_unverified.ToPEM();
    auto cert = crypto::UpdateCertificate::LoadFromPEM(pem, root_cert_, time(nullptr));

    Manifest manifest = cert.GetManifest();

    EXPECT_EQ(manifest.GetMetadata("vendor").value(), "TestVendor");
    EXPECT_EQ(manifest.GetMetadata("release_notes").value(), "Bug fixes");
}

// ============================================================================
// Device Metadata Tests (Operational Fields)
// ============================================================================

TEST_F(ManifestBuilderTest, DeviceMetadataContainsOperationalFields) {
    // Create multi-artifact update with versions
    std::vector<uint8_t> bootloader(512, 0xBB);
    std::vector<uint8_t> firmware(1024, 0xFF);

    auto encrypted_bootloader = EncryptSoftware(bootloader);
    auto encrypted_firmware = EncryptSoftware(firmware);

    ManifestBuilder builder(intermediate_key_, intermediate_cert_);

    builder.AddArtifact("bootloader", encrypted_bootloader)
        .SetType("bootloader")
        .SetTargetECU("primary")
        .SetVersion(SemVer{1, 0, 0, "", ""})
        .SetSecurityVersion(5)
        .SetInstallOrder(0);

    builder.AddArtifact("firmware", encrypted_firmware)
        .SetType("firmware")
        .SetTargetECU("primary")
        .SetVersion(SemVer{2, 3, 1, "beta", "git.abc123"})
        .SetSecurityVersion(15)
        .SetInstallOrder(1);

    // Build certificate with manifest_version=42
    auto [cert_unverified, encrypted_files] = builder.BuildCertificate(
        device_pubkey_, device_metadata_, 42, 365
    );

    // Serialize and reload with verification
    std::string pem = cert_unverified.ToPEM();
    auto cert = crypto::UpdateCertificate::LoadFromPEM(pem, root_cert_, time(nullptr));

    // Verify device metadata (device identification only, no operational fields)
    auto metadata = cert.GetDeviceMetadata();
    EXPECT_EQ(metadata.hardware_id, "TEST-DEVICE-001");
    EXPECT_EQ(metadata.manufacturer, "Test Manufacturer");
    EXPECT_EQ(metadata.device_type, "Test-Device");
    EXPECT_EQ(metadata.hardware_version, "v1.0");
    EXPECT_TRUE(metadata.requires.empty());  // No constraints implemented yet

    // Operational metadata is now in Manifest, not DeviceMetadata
    auto manifest = cert.GetManifest();
    EXPECT_EQ(manifest.GetManifestVersion(), 42);
    EXPECT_EQ(manifest.GetType(), ManifestType::FULL);

    // Verify artifacts (what this update provides)
    const auto& artifacts = manifest.GetArtifacts();
    ASSERT_EQ(artifacts.size(), 2);

    // Check bootloader artifact
    const auto& bootloader_artifact = artifacts[0];
    EXPECT_EQ(bootloader_artifact.name, "bootloader");
    EXPECT_EQ(bootloader_artifact.type, "bootloader");
    EXPECT_EQ(bootloader_artifact.target_ecu, "primary");
    EXPECT_EQ(bootloader_artifact.security_version, 5);
    EXPECT_EQ(bootloader_artifact.version.major, 1);
    EXPECT_EQ(bootloader_artifact.version.minor, 0);
    EXPECT_EQ(bootloader_artifact.version.patch, 0);

    // Check firmware artifact
    const auto& firmware_artifact = artifacts[1];
    EXPECT_EQ(firmware_artifact.name, "firmware");
    EXPECT_EQ(firmware_artifact.type, "firmware");
    EXPECT_EQ(firmware_artifact.target_ecu, "primary");
    EXPECT_EQ(firmware_artifact.security_version, 15);
    EXPECT_EQ(firmware_artifact.version.major, 2);
    EXPECT_EQ(firmware_artifact.version.minor, 3);
    EXPECT_EQ(firmware_artifact.version.patch, 1);
    EXPECT_EQ(firmware_artifact.version.prerelease, "beta");
    EXPECT_EQ(firmware_artifact.version.build_metadata, "git.abc123");
}

TEST_F(ManifestBuilderTest, DeviceMetadataRoundTripThroughProtobuf) {
    std::vector<uint8_t> firmware(256, 0xAA);
    auto encrypted = EncryptSoftware(firmware);

    ManifestBuilder builder(intermediate_key_, intermediate_cert_);

    builder.AddArtifact("app", encrypted)
        .SetType("application")
        .SetTargetECU("secondary")
        .SetVersion(SemVer{3, 2, 1, "", ""})
        .SetSecurityVersion(20);

    auto [cert_unverified, encrypted_files] = builder.BuildCertificate(
        device_pubkey_, device_metadata_, 100, 365
    );

    // Serialize and reload with verification
    std::string pem = cert_unverified.ToPEM();
    auto cert = crypto::UpdateCertificate::LoadFromPEM(pem, root_cert_, time(nullptr));

    // Extract device metadata
    auto metadata = cert.GetDeviceMetadata();

    // Serialize to protobuf
    auto protobuf_data = metadata.ToProtobuf();
    EXPECT_FALSE(protobuf_data.empty());

    // Deserialize back
    auto metadata2 = DeviceMetadata::FromProtobuf(protobuf_data);

    // Verify round-trip preserves device identification fields
    EXPECT_EQ(metadata2.hardware_id, metadata.hardware_id);
    EXPECT_EQ(metadata2.manufacturer, metadata.manufacturer);
    EXPECT_EQ(metadata2.device_type, metadata.device_type);
    EXPECT_EQ(metadata2.hardware_version, metadata.hardware_version);
    EXPECT_EQ(metadata2.requires.size(), metadata.requires.size());
}
