/**
 * @file manifest_test.cpp
 * @brief Unit tests for manifest operations
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "sum/common/manifest.h"

using namespace sum;

// ============================================================================
// Manifest Construction Tests
// ============================================================================

TEST(ManifestTest, CreateManifest) {
    Manifest manifest;

    manifest.SetManifestVersion(42);
    EXPECT_EQ(manifest.GetManifestVersion(), 42);
}

TEST(ManifestTest, SemanticVersion) {
    // Test semantic version on artifacts (not on manifest anymore)
    SemVer version;
    version.major = 1;
    version.minor = 2;
    version.patch = 3;
    version.prerelease = "beta.1";
    version.build_metadata = "git.abc123";

    // Create artifact with semantic version
    SoftwareArtifact artifact;
    artifact.name = "test-artifact";
    artifact.type = "firmware";
    artifact.target_ecu = "primary";
    artifact.install_order = 0;
    artifact.version = version;
    artifact.security_version = 100;
    artifact.hash_algorithm = "SHA-256";
    artifact.expected_hash = {0xAA, 0xBB};
    artifact.signature_algorithm = "Ed25519";
    artifact.signature = {0x11, 0x22};
    artifact.size = 1024;
    artifact.ciphertext_size = 1100;

    // Add to manifest
    Manifest manifest;
    manifest.AddArtifact(artifact);

    // Retrieve and verify
    const auto& artifacts = manifest.GetArtifacts();
    ASSERT_EQ(artifacts.size(), 1);
    const auto& retrieved = artifacts[0].version;
    EXPECT_EQ(retrieved.major, 1);
    EXPECT_EQ(retrieved.minor, 2);
    EXPECT_EQ(retrieved.patch, 3);
    EXPECT_EQ(retrieved.prerelease, "beta.1");
    EXPECT_EQ(retrieved.build_metadata, "git.abc123");

    // Test ToString
    EXPECT_EQ(retrieved.ToString(), "1.2.3-beta.1+git.abc123");

    // Test security version
    EXPECT_EQ(artifacts[0].security_version, 100);
}

TEST(ManifestTest, SemanticVersionComparison) {
    SemVer v1{1, 0, 0, "", ""};
    SemVer v2{1, 0, 1, "", ""};
    SemVer v3{1, 1, 0, "", ""};
    SemVer v4{2, 0, 0, "", ""};
    SemVer v5{1, 0, 0, "", ""};

    EXPECT_EQ(v1.Compare(v1), 0);  // Equal
    EXPECT_EQ(v1.Compare(v5), 0);  // Equal
    EXPECT_LT(v1.Compare(v2), 0);  // v1 < v2 (patch)
    EXPECT_GT(v2.Compare(v1), 0);  // v2 > v1
    EXPECT_LT(v1.Compare(v3), 0);  // v1 < v3 (minor)
    EXPECT_LT(v1.Compare(v4), 0);  // v1 < v4 (major)
}

TEST(ManifestTest, SemanticVersionToString) {
    SemVer v1{1, 2, 3, "", ""};
    EXPECT_EQ(v1.ToString(), "1.2.3");

    SemVer v2{1, 2, 3, "alpha", ""};
    EXPECT_EQ(v2.ToString(), "1.2.3-alpha");

    SemVer v3{1, 2, 3, "", "build.123"};
    EXPECT_EQ(v3.ToString(), "1.2.3+build.123");

    SemVer v4{1, 2, 3, "rc.1", "git.abc"};
    EXPECT_EQ(v4.ToString(), "1.2.3-rc.1+git.abc");
}

TEST(ManifestTest, AddArtifact) {
    Manifest manifest;

    SoftwareArtifact artifact;
    artifact.name = "bootloader";
    artifact.hash_algorithm = "SHA-256";
    artifact.expected_hash = {0x01, 0x02, 0x03};
    artifact.signature_algorithm = "Ed25519";
    artifact.signature = {0x04, 0x05, 0x06};
    artifact.size = 1024;

    manifest.AddArtifact(artifact);

    auto artifacts = manifest.GetArtifacts();
    EXPECT_EQ(artifacts.size(), 1);
    EXPECT_EQ(artifacts[0].name, "bootloader");
    EXPECT_EQ(artifacts[0].hash_algorithm, "SHA-256");
    EXPECT_EQ(artifacts[0].size, 1024);
}

TEST(ManifestTest, AddEncryptionParams) {
    Manifest manifest;

    EncryptionParams params;
    params.artifact_name = "application";
    params.algorithm = "AES-128-CTR";
    params.iv = {0x01, 0x02, 0x03};
    params.wrapped_key = {0x04, 0x05, 0x06};
    params.key_wrapping_algorithm = "ECIES-P256-SHA256-AES128";
    params.device_id = "device-12345";

    manifest.AddEncryptionParams(params);

    auto encryption = manifest.GetEncryptionParams();
    EXPECT_EQ(encryption.size(), 1);
    EXPECT_EQ(encryption[0].artifact_name, "application");
    EXPECT_EQ(encryption[0].device_id, "device-12345");
}

TEST(ManifestTest, SetMetadata) {
    Manifest manifest;

    manifest.SetMetadata("vendor", "TestVendor");
    manifest.SetMetadata("hw_version", "v2.1");

    EXPECT_EQ(manifest.GetMetadata("vendor").value(), "TestVendor");
    EXPECT_EQ(manifest.GetMetadata("hw_version").value(), "v2.1");
    EXPECT_FALSE(manifest.GetMetadata("nonexistent").has_value());
}

TEST(ManifestTest, SetSignature) {
    Manifest manifest;

    std::vector<uint8_t> signature = {0x01, 0x02, 0x03, 0x04};
    manifest.SetSignature(signature);

    EXPECT_EQ(manifest.GetSignature(), signature);
}

TEST(ManifestTest, SetSigningCertificate) {
    Manifest manifest;

    std::vector<uint8_t> cert = {0x30, 0x82, 0x01, 0xF0};
    manifest.SetSigningCertificate(cert);

    EXPECT_EQ(manifest.GetSigningCertificate(), cert);
}

// ============================================================================
// JSON Serialization Tests
// ============================================================================

TEST(ManifestTest, SerializeToJSON) {
    Manifest manifest;
    manifest.SetManifestVersion(100);

    SoftwareArtifact artifact;
    artifact.name = "firmware";
    artifact.hash_algorithm = "SHA-256";
    artifact.expected_hash = {0xAA, 0xBB, 0xCC};
    artifact.signature_algorithm = "Ed25519";
    artifact.signature = {0xDD, 0xEE, 0xFF};
    manifest.AddArtifact(artifact);

    std::string json_str = manifest.ToDebugJSON();

    // Basic checks that JSON contains expected fields
    EXPECT_NE(json_str.find("\"manifestVersion\": \"100\""), std::string::npos);
    EXPECT_NE(json_str.find("\"firmware\""), std::string::npos);
    EXPECT_NE(json_str.find("\"SHA-256\""), std::string::npos);
}

TEST(ManifestTest, RoundTripSerialization) {
    // Create manifest
    Manifest original;
    original.SetManifestVersion(42);

    SoftwareArtifact artifact;
    artifact.name = "app";
    artifact.hash_algorithm = "SHA-256";
    artifact.expected_hash = {0x01, 0x02, 0x03, 0x04};
    artifact.signature_algorithm = "Ed25519";
    artifact.signature = {0x05, 0x06, 0x07, 0x08};
    artifact.size = 2048;
    original.AddArtifact(artifact);

    original.SetMetadata("test_key", "test_value");

    // Serialize to protobuf
    auto protobuf_data = original.ToProtobuf();

    // Deserialize back
    Manifest loaded = Manifest::LoadFromProtobuf(protobuf_data);

    // Verify
    EXPECT_EQ(loaded.GetManifestVersion(), 42);
    EXPECT_EQ(loaded.GetArtifacts().size(), 1);
    EXPECT_EQ(loaded.GetArtifacts()[0].name, "app");
    EXPECT_EQ(loaded.GetArtifacts()[0].size, 2048);
    EXPECT_EQ(loaded.GetMetadata("test_key").value(), "test_value");
}

// ============================================================================
// Protobuf Parser Tests
// ============================================================================

TEST(ManifestParserTest, ParseEmptyData) {
    // Protobuf accepts empty data as valid empty message (all fields have defaults)
    std::vector<uint8_t> empty_data;
    Manifest loaded = Manifest::LoadFromProtobuf(empty_data);

    // Empty manifest should have protobuf default (0), not constructor default (1)
    EXPECT_EQ(loaded.GetVersion(), 0);
    EXPECT_EQ(loaded.GetManifestVersion(), 0);
}

TEST(ManifestParserTest, RejectCorruptProtobuf) {
    // Invalid protobuf wire format (field number 0 is invalid)
    std::vector<uint8_t> corrupt_data = {0x00, 0xFF, 0xFF, 0xFF, 0xFF};
    EXPECT_THROW(Manifest::LoadFromProtobuf(corrupt_data), std::runtime_error);
}

TEST(ManifestParserTest, ParsePartialProtobuf) {
    // Protobuf can parse truncated data if it's truncated at field boundaries
    // This is expected behavior - partial messages are valid
    Manifest original;
    original.SetManifestVersion(100);
    auto valid_data = original.ToProtobuf();

    // Truncate it
    std::vector<uint8_t> truncated_data(valid_data.begin(), valid_data.begin() + valid_data.size() / 2);

    // Should parse successfully (with whatever fields were before truncation)
    Manifest loaded = Manifest::LoadFromProtobuf(truncated_data);

    // Version field is early in the message, so it might be present
    EXPECT_GE(loaded.GetVersion(), 0);
}

TEST(ManifestParserTest, ParseMinimalManifest) {
    // Create minimal valid manifest
    Manifest original;
    original.SetManifestVersion(1);

    auto data = original.ToProtobuf();
    Manifest loaded = Manifest::LoadFromProtobuf(data);

    EXPECT_EQ(loaded.GetVersion(), 1);
    EXPECT_EQ(loaded.GetManifestVersion(), 1);
    EXPECT_EQ(loaded.GetArtifacts().size(), 0);
}

TEST(ManifestParserTest, ParseComplexManifest) {
    // Create manifest with multiple artifacts and encryption params
    Manifest original;
    original.SetManifestVersion(42);

    // Add multiple artifacts
    for (int i = 0; i < 3; i++) {
        SoftwareArtifact artifact;
        artifact.name = "artifact_" + std::to_string(i);
        artifact.type = "firmware";
        artifact.target_ecu = "primary";
        artifact.install_order = i;

        // Versioning
        artifact.version.major = 1;
        artifact.version.minor = i;
        artifact.version.patch = 0;
        artifact.security_version = 100 + i;

        artifact.hash_algorithm = "SHA-256";
        artifact.expected_hash = {0xAA, 0xBB, 0xCC, 0xDD};
        artifact.signature_algorithm = "Ed25519";
        artifact.signature = {0x11, 0x22, 0x33, 0x44};
        artifact.size = 1024 * (i + 1);
        artifact.ciphertext_size = 1100 * (i + 1);
        original.AddArtifact(artifact);
    }

    // Add encryption params
    EncryptionParams params;
    params.artifact_name = "artifact_0";
    params.device_id = "device-12345";
    params.algorithm = "AES-128-GCM";
    params.iv = {0x01, 0x02, 0x03, 0x04};
    params.tag = {0x05, 0x06, 0x07, 0x08};
    params.key_wrapping_algorithm = "X25519-HKDF-SHA256-ChaCha20Poly1305";
    params.wrapped_key = {0x09, 0x0A, 0x0B, 0x0C};
    original.AddEncryptionParams(params);

    // Serialize and deserialize
    auto data = original.ToProtobuf();
    Manifest loaded = Manifest::LoadFromProtobuf(data);

    // Verify structure
    EXPECT_EQ(loaded.GetManifestVersion(), 42);
    EXPECT_EQ(loaded.GetArtifacts().size(), 3);
    EXPECT_EQ(loaded.GetEncryptionParams().size(), 1);

    // Verify artifacts
    const auto& artifacts = loaded.GetArtifacts();
    for (size_t i = 0; i < artifacts.size(); i++) {
        EXPECT_EQ(artifacts[i].name, "artifact_" + std::to_string(i));
        EXPECT_EQ(artifacts[i].install_order, i);
        // Verify versioning
        EXPECT_EQ(artifacts[i].version.major, 1);
        EXPECT_EQ(artifacts[i].version.minor, i);
        EXPECT_EQ(artifacts[i].version.patch, 0);
        EXPECT_EQ(artifacts[i].security_version, 100 + i);
        EXPECT_EQ(artifacts[i].size, 1024 * (i + 1));
    }

    // Verify encryption params
    const auto& enc_params = loaded.GetEncryptionParams();
    EXPECT_EQ(enc_params[0].artifact_name, "artifact_0");
    EXPECT_EQ(enc_params[0].device_id, "device-12345");
}

TEST(ManifestParserTest, ParseWithSources) {
    Manifest original;
    original.SetManifestVersion(1);

    SoftwareArtifact artifact;
    artifact.name = "firmware";
    artifact.hash_algorithm = "SHA-256";
    artifact.expected_hash = {0xAA, 0xBB};
    artifact.signature_algorithm = "Ed25519";
    artifact.signature = {0xCC, 0xDD};

    // Add multiple sources with different priorities
    Source src1;
    src1.uri = "https://cdn.example.com/firmware.enc";
    src1.priority = 0;
    src1.type = "https";
    artifact.sources.push_back(src1);

    Source src2;
    src2.uri = "https://backup.example.com/firmware.enc";
    src2.priority = 1;
    src2.type = "https";
    artifact.sources.push_back(src2);

    Source src3;
    src3.uri = "ipfs://QmXyz123.../firmware.enc";
    src3.priority = 2;
    src3.type = "ipfs";
    artifact.sources.push_back(src3);

    original.AddArtifact(artifact);

    // Serialize and deserialize
    auto data = original.ToProtobuf();
    Manifest loaded = Manifest::LoadFromProtobuf(data);

    // Verify sources (including content-addressable IPFS source)
    const auto& artifacts = loaded.GetArtifacts();
    ASSERT_EQ(artifacts.size(), 1);
    EXPECT_EQ(artifacts[0].sources.size(), 3);
    EXPECT_EQ(artifacts[0].sources[0].uri, "https://cdn.example.com/firmware.enc");
    EXPECT_EQ(artifacts[0].sources[0].priority, 0);
    EXPECT_EQ(artifacts[0].sources[1].priority, 1);
    EXPECT_EQ(artifacts[0].sources[2].priority, 2);
    EXPECT_EQ(artifacts[0].sources[2].type, "ipfs");  // IPFS source implies content-addressable
}

// ============================================================================
// DeviceMetadata Parser Tests
// ============================================================================

TEST(DeviceMetadataParserTest, ParseValidMetadata) {
    DeviceMetadata original;
    original.hardware_id = "ESP32-TEST-001";
    original.manufacturer = "Test Corp";
    original.device_type = "ESP32-Gateway";
    original.hardware_version = "v1.0";

    auto data = original.ToProtobuf();
    DeviceMetadata loaded = DeviceMetadata::FromProtobuf(data);

    EXPECT_EQ(loaded.hardware_id, "ESP32-TEST-001");
    EXPECT_EQ(loaded.manufacturer, "Test Corp");
    EXPECT_EQ(loaded.device_type, "ESP32-Gateway");
    EXPECT_EQ(loaded.hardware_version, "v1.0");
}

TEST(DeviceMetadataParserTest, ParseMinimalMetadata) {
    DeviceMetadata original;
    original.hardware_id = "DEVICE-001";
    original.manufacturer = "TestMfg";
    original.device_type = "TestDevice";
    // hardware_version is optional, leave empty

    auto data = original.ToProtobuf();
    DeviceMetadata loaded = DeviceMetadata::FromProtobuf(data);

    EXPECT_EQ(loaded.hardware_id, "DEVICE-001");
    EXPECT_EQ(loaded.manufacturer, "TestMfg");
    EXPECT_EQ(loaded.device_type, "TestDevice");
    EXPECT_TRUE(loaded.hardware_version.empty());
}

TEST(DeviceMetadataParserTest, ParseEmptyData) {
    // Protobuf accepts empty data as valid empty message
    std::vector<uint8_t> empty_data;
    DeviceMetadata loaded = DeviceMetadata::FromProtobuf(empty_data);

    // All string fields should be empty
    EXPECT_TRUE(loaded.hardware_id.empty());
    EXPECT_TRUE(loaded.manufacturer.empty());
    EXPECT_TRUE(loaded.device_type.empty());
    EXPECT_TRUE(loaded.hardware_version.empty());
}

TEST(DeviceMetadataParserTest, RejectCorruptData) {
    std::vector<uint8_t> corrupt_data = {0xFF, 0xFF, 0xFF, 0xFF};
    EXPECT_THROW(DeviceMetadata::FromProtobuf(corrupt_data), std::runtime_error);
}

TEST(DeviceMetadataParserTest, RejectTruncatedData) {
    DeviceMetadata original;
    original.hardware_id = "DEVICE-001";
    original.manufacturer = "Test";
    original.device_type = "TestDevice";

    auto valid_data = original.ToProtobuf();

    // Truncate data
    std::vector<uint8_t> truncated(valid_data.begin(), valid_data.begin() + valid_data.size() / 2);
    EXPECT_THROW(DeviceMetadata::FromProtobuf(truncated), std::runtime_error);
}
