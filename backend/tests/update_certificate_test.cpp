/**
 * @file update_certificate_test.cpp
 * @brief Comprehensive unit tests for UpdateCertificate class
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "sum/common/crypto.h"
#include "sum/common/manifest.h"
#include "sum/backend/manifest_builder.h"
#include <fstream>
#include <ctime>
#include <thread>
#include <chrono>

using namespace sum::crypto;
using namespace sum;

// ============================================================================
// Test Fixture
// ============================================================================

class UpdateCertificateTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create Root CA
        root_key_ = PrivateKey::Generate(KeyType::Ed25519);
        auto root_pubkey = PublicKey::FromPrivateKey(root_key_);
        root_cert_ = CreateCACertificate(root_key_, root_pubkey, "Root CA", 3650);

        // Create Intermediate CA
        intermediate_key_ = PrivateKey::Generate(KeyType::Ed25519);
        auto intermediate_pubkey = PublicKey::FromPrivateKey(intermediate_key_);
        intermediate_cert_ = CreateCACertificate(
            root_key_, intermediate_pubkey, "Intermediate CA", 1825, &root_cert_
        );

        // Create device key pair (X25519)
        device_key_ = PrivateKey::Generate(KeyType::X25519);
        device_pubkey_ = PublicKey::FromPrivateKey(device_key_);

        // Setup device metadata
        device_metadata_.hardware_id = "TEST-DEVICE-001";
        device_metadata_.manufacturer = "Test Manufacturer";
        device_metadata_.device_type = "Test-Device";
        device_metadata_.hardware_version = "v1.0";

        // Create a simple firmware artifact
        firmware_data_ = std::vector<uint8_t>(1024, 0xAA);
        encrypted_firmware_ = EncryptSoftware(firmware_data_);

        // Build update certificate
        ManifestBuilder builder(intermediate_key_, intermediate_cert_);
        builder.AddArtifact("firmware", encrypted_firmware_)
            .SetType("firmware")
            .SetTargetECU("primary")
            .SetVersion(SemVer{1, 0, 0, "", ""})
            .SetSecurityVersion(1)
            .SetInstallOrder(0);

        auto [cert, files] = builder.BuildCertificate(
            device_pubkey_, device_metadata_, 1, 365
        );

        update_cert_ = std::move(cert);
        encrypted_files_ = std::move(files);
    }

    PrivateKey root_key_;
    Certificate root_cert_;
    PrivateKey intermediate_key_;
    Certificate intermediate_cert_;
    PrivateKey device_key_;
    PublicKey device_pubkey_;
    DeviceMetadata device_metadata_;
    std::vector<uint8_t> firmware_data_;
    EncryptedArtifact encrypted_firmware_;
    UpdateCertificate update_cert_;
    std::map<std::string, std::vector<uint8_t>> encrypted_files_;
};

// ============================================================================
// Load/Save Tests
// ============================================================================

TEST_F(UpdateCertificateTest, LoadFromPEMWithValidBundle) {
    // Save to PEM
    std::string pem = update_cert_.ToPEM();

    // Load back with verification (atomic operation)
    auto loaded = UpdateCertificate::LoadFromPEM(pem, root_cert_, time(nullptr));

    // If we got here, verification succeeded (would have thrown otherwise)
    EXPECT_NO_THROW(loaded.GetManifest());
}

TEST_F(UpdateCertificateTest, LoadFromPEMWithEmptyString) {
    EXPECT_THROW(
        UpdateCertificate::LoadFromPEM("", root_cert_, time(nullptr)),
        CryptoError
    );
}

TEST_F(UpdateCertificateTest, LoadFromPEMWithInvalidData) {
    std::string invalid_pem = "-----BEGIN CERTIFICATE-----\ninvalid data\n-----END CERTIFICATE-----\n";
    EXPECT_THROW(
        UpdateCertificate::LoadFromPEM(invalid_pem, root_cert_, time(nullptr)),
        CryptoError
    );
}

TEST_F(UpdateCertificateTest, LoadFromPEMWithOneCertificate) {
    // Should fail - need exactly 2 certificates
    EXPECT_THROW(
        UpdateCertificate::LoadFromPEM(root_cert_.ToPEM(), root_cert_, time(nullptr)),
        CryptoError
    );
}

TEST_F(UpdateCertificateTest, LoadFromPEMWithThreeCertificates) {
    // Create 3-cert bundle
    std::string three_cert_pem = update_cert_.ToPEM() + root_cert_.ToPEM();

    // Should fail - need exactly 2 certificates
    EXPECT_THROW(
        UpdateCertificate::LoadFromPEM(three_cert_pem, root_cert_, time(nullptr)),
        CryptoError
    );
}

TEST_F(UpdateCertificateTest, LoadFromFileRoundTrip) {
    const char* temp_file = "/tmp/libsum_update_cert_test.pem";

    // Save to file
    std::string pem = update_cert_.ToPEM();
    std::ofstream ofs(temp_file);
    ofs << pem;
    ofs.close();

    // Load from file with verification (atomic operation)
    auto loaded = UpdateCertificate::LoadFromFile(temp_file, root_cert_, time(nullptr));

    // If we got here, verification succeeded
    EXPECT_NO_THROW(loaded.GetManifest());

    std::remove(temp_file);
}

TEST_F(UpdateCertificateTest, LoadFromFileNotFound) {
    EXPECT_THROW(
        UpdateCertificate::LoadFromFile("/nonexistent/path.pem", root_cert_, time(nullptr)),
        CryptoError
    );
}

TEST_F(UpdateCertificateTest, ToPEMContainsTwoCertificates) {
    std::string pem = update_cert_.ToPEM();

    // Count certificate blocks
    size_t count = 0;
    size_t pos = 0;
    while ((pos = pem.find("-----BEGIN CERTIFICATE-----", pos)) != std::string::npos) {
        count++;
        pos++;
    }

    EXPECT_EQ(count, 2) << "PEM should contain exactly 2 certificates (update + intermediate)";
}

// ============================================================================
// Verification Tests
// ============================================================================

TEST_F(UpdateCertificateTest, VerifyWithValidChain) {
    // Verification happens at load time - if we got update_cert_ in SetUp, it's valid
    std::string pem = update_cert_.ToPEM();
    EXPECT_NO_THROW(UpdateCertificate::LoadFromPEM(pem, root_cert_, time(nullptr)));
}

TEST_F(UpdateCertificateTest, VerifyWithWrongRootCA) {
    // Create different root CA
    auto wrong_root_key = PrivateKey::Generate(KeyType::Ed25519);
    auto wrong_root_pubkey = PublicKey::FromPrivateKey(wrong_root_key);
    auto wrong_root = CreateCACertificate(wrong_root_key, wrong_root_pubkey, "Wrong Root", 3650);

    // Should fail during load when verifying against wrong root
    std::string pem = update_cert_.ToPEM();
    EXPECT_THROW(
        UpdateCertificate::LoadFromPEM(pem, wrong_root, time(nullptr)),
        CryptoError
    );
}

TEST_F(UpdateCertificateTest, VerifyWithExpiredCertificate) {
    // Create short-lived certificate
    auto short_key = PrivateKey::Generate(KeyType::Ed25519);
    auto short_pubkey = PublicKey::FromPrivateKey(short_key);
    auto short_intermediate = CreateCACertificate(
        root_key_, short_pubkey, "Short Intermediate", 0, &root_cert_
    );

    ManifestBuilder builder(short_key, short_intermediate);
    builder.AddArtifact("fw", encrypted_firmware_);

    auto [expired_cert_unverified, files] = builder.BuildCertificate(
        device_pubkey_, device_metadata_, 1, 0  // 0 days validity
    );

    // Wait to ensure expiration
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Should fail during load due to expiration
    std::string pem = expired_cert_unverified.ToPEM();
    EXPECT_THROW(
        UpdateCertificate::LoadFromPEM(pem, root_cert_, time(nullptr)),
        CryptoError
    );
}

TEST_F(UpdateCertificateTest, VerifyWithFutureCertificate) {
    // Check validity 2 days ago (certificate not yet valid then)
    int64_t past_time = time(nullptr) - 86400 * 2;

    // Should fail during load - certificate not yet valid at past_time
    std::string pem = update_cert_.ToPEM();
    EXPECT_THROW(
        UpdateCertificate::LoadFromPEM(pem, root_cert_, past_time),
        CryptoError
    );
}

TEST_F(UpdateCertificateTest, VerifyWithSelfSignedIntermediate) {
    // Create self-signed intermediate (invalid)
    auto bad_key = PrivateKey::Generate(KeyType::Ed25519);
    auto bad_pubkey = PublicKey::FromPrivateKey(bad_key);
    auto self_signed_intermediate = CreateCACertificate(bad_key, bad_pubkey, "Self-Signed", 365);

    ManifestBuilder builder(bad_key, self_signed_intermediate);
    builder.AddArtifact("fw", encrypted_firmware_);

    // Should throw during BuildCertificate - intermediate must not be self-signed
    EXPECT_THROW(
        builder.BuildCertificate(device_pubkey_, device_metadata_, 1, 365),
        CryptoError
    );
}

TEST_F(UpdateCertificateTest, VerifyWithMismatchedIntermediate) {
    // Create different intermediate signed by root
    auto other_key = PrivateKey::Generate(KeyType::Ed25519);
    auto other_pubkey = PublicKey::FromPrivateKey(other_key);
    auto other_intermediate = CreateCACertificate(
        root_key_, other_pubkey, "Other Intermediate", 1825, &root_cert_
    );

    // Sign update cert with original intermediate_key but pass other_intermediate
    // This creates a mismatch: update cert signed by intermediate_key, but cert chain contains other_intermediate
    ManifestBuilder builder(intermediate_key_, other_intermediate);
    builder.AddArtifact("fw", encrypted_firmware_);

    auto [bad_cert_unverified, files] = builder.BuildCertificate(
        device_pubkey_, device_metadata_, 1, 365
    );

    // Should fail during load - update cert not signed by the intermediate in the chain
    std::string pem = bad_cert_unverified.ToPEM();
    EXPECT_THROW(
        UpdateCertificate::LoadFromPEM(pem, root_cert_, time(nullptr)),
        CryptoError
    );
}

// ============================================================================
// Manifest Extraction Tests
// ============================================================================

TEST_F(UpdateCertificateTest, GetVerifiedManifestWithValidChain) {
    // Serialize and reload with verification
    std::string pem = update_cert_.ToPEM();
    auto verified_cert = UpdateCertificate::LoadFromPEM(pem, root_cert_, time(nullptr));

    // Extract manifest (already verified at load)
    auto manifest = verified_cert.GetManifest();

    EXPECT_EQ(manifest.GetManifestVersion(), 1);
    EXPECT_EQ(manifest.GetArtifacts().size(), 1);
}

TEST_F(UpdateCertificateTest, GetVerifiedManifestFailsWithInvalidChain) {
    // Create wrong root CA
    auto wrong_root_key = PrivateKey::Generate(KeyType::Ed25519);
    auto wrong_root_pubkey = PublicKey::FromPrivateKey(wrong_root_key);
    auto wrong_root = CreateCACertificate(wrong_root_key, wrong_root_pubkey, "Wrong Root", 3650);

    // Should fail during load with wrong root
    std::string pem = update_cert_.ToPEM();
    EXPECT_THROW(
        UpdateCertificate::LoadFromPEM(pem, wrong_root, time(nullptr)),
        CryptoError
    );
}

TEST_F(UpdateCertificateTest, GetVerifiedManifestFailsWithExpiredCert) {
    // Create expired certificate
    auto short_key = PrivateKey::Generate(KeyType::Ed25519);
    auto short_pubkey = PublicKey::FromPrivateKey(short_key);
    auto short_intermediate = CreateCACertificate(
        root_key_, short_pubkey, "Short Intermediate", 0, &root_cert_
    );

    ManifestBuilder builder(short_key, short_intermediate);
    builder.AddArtifact("fw", encrypted_firmware_);

    auto [expired_cert_unverified, files] = builder.BuildCertificate(
        device_pubkey_, device_metadata_, 1, 0
    );

    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Should fail during load due to expiration
    std::string pem = expired_cert_unverified.ToPEM();
    EXPECT_THROW(
        UpdateCertificate::LoadFromPEM(pem, root_cert_, time(nullptr)),
        CryptoError
    );
}

TEST_F(UpdateCertificateTest, GetVerifiedManifestParsesCorrectly) {
    // Serialize and reload with verification
    std::string pem = update_cert_.ToPEM();
    auto verified_cert = UpdateCertificate::LoadFromPEM(pem, root_cert_, time(nullptr));

    auto manifest = verified_cert.GetManifest();

    // Verify manifest structure
    EXPECT_EQ(manifest.GetManifestVersion(), 1);

    auto artifacts = manifest.GetArtifacts();
    ASSERT_EQ(artifacts.size(), 1);
    EXPECT_EQ(artifacts[0].name, "firmware");
    EXPECT_EQ(artifacts[0].type, "firmware");
    EXPECT_EQ(artifacts[0].target_ecu, "primary");

    auto encryption_params = manifest.GetEncryptionParams();
    ASSERT_EQ(encryption_params.size(), 1);
    // encryption_params is a vector, access by index
    EXPECT_EQ(encryption_params[0].artifact_name, "firmware");
}

TEST_F(UpdateCertificateTest, GetVerifiedManifestPreservesAllData) {
    // Create manifest with metadata
    ManifestBuilder builder(intermediate_key_, intermediate_cert_);
    builder.AddArtifact("app", encrypted_firmware_)
        .SetType("application")
        .SetVersion(SemVer{2, 3, 4, "beta", "git.abc123"})
        .SetSecurityVersion(42);

    builder.AddMetadata("vendor", "TestVendor")
           .AddMetadata("release_notes", "Important update");

    auto [cert_unverified, files] = builder.BuildCertificate(
        device_pubkey_, device_metadata_, 99, 365
    );

    // Serialize and reload with verification
    std::string pem = cert_unverified.ToPEM();
    auto cert = UpdateCertificate::LoadFromPEM(pem, root_cert_, time(nullptr));

    auto manifest = cert.GetManifest();

    // Verify all fields preserved
    EXPECT_EQ(manifest.GetManifestVersion(), 99);
    EXPECT_EQ(manifest.GetMetadata("vendor").value(), "TestVendor");
    EXPECT_EQ(manifest.GetMetadata("release_notes").value(), "Important update");

    auto artifacts = manifest.GetArtifacts();
    EXPECT_EQ(artifacts[0].security_version, 42);
    EXPECT_EQ(artifacts[0].version.major, 2);
    EXPECT_EQ(artifacts[0].version.prerelease, "beta");
}

TEST_F(UpdateCertificateTest, GetVerifiedManifestWithMultipleArtifacts) {
    // Create multi-artifact update
    auto app_data = std::vector<uint8_t>(512, 0xBB);
    auto encrypted_app = EncryptSoftware(app_data);

    ManifestBuilder builder(intermediate_key_, intermediate_cert_);
    builder.AddArtifact("firmware", encrypted_firmware_);
    builder.AddArtifact("app", encrypted_app);

    auto [cert_unverified, files] = builder.BuildCertificate(
        device_pubkey_, device_metadata_, 1, 365
    );

    // Serialize and reload with verification
    std::string pem = cert_unverified.ToPEM();
    auto cert = UpdateCertificate::LoadFromPEM(pem, root_cert_, time(nullptr));

    auto manifest = cert.GetManifest();

    // Verify both artifacts present
    EXPECT_EQ(manifest.GetArtifacts().size(), 2);
    EXPECT_EQ(manifest.GetEncryptionParams().size(), 2);
}

// ============================================================================
// Device Metadata Extraction Tests
// ============================================================================

TEST_F(UpdateCertificateTest, GetDeviceMetadataWithValidChain) {
    // Serialize and reload with verification
    std::string pem = update_cert_.ToPEM();
    auto verified_cert = UpdateCertificate::LoadFromPEM(pem, root_cert_, time(nullptr));

    auto metadata = verified_cert.GetDeviceMetadata();

    EXPECT_EQ(metadata.hardware_id, "TEST-DEVICE-001");
    EXPECT_EQ(metadata.manufacturer, "Test Manufacturer");
    EXPECT_EQ(metadata.device_type, "Test-Device");
    EXPECT_EQ(metadata.hardware_version, "v1.0");
}

TEST_F(UpdateCertificateTest, GetDeviceMetadataFailsWithInvalidChain) {
    auto wrong_root_key = PrivateKey::Generate(KeyType::Ed25519);
    auto wrong_root_pubkey = PublicKey::FromPrivateKey(wrong_root_key);
    auto wrong_root = CreateCACertificate(wrong_root_key, wrong_root_pubkey, "Wrong Root", 3650);

    // Should fail during load with wrong root
    std::string pem = update_cert_.ToPEM();
    EXPECT_THROW(
        UpdateCertificate::LoadFromPEM(pem, wrong_root, time(nullptr)),
        CryptoError
    );
}

TEST_F(UpdateCertificateTest, GetDeviceMetadataParsesCorrectly) {
    // Serialize and reload with verification
    std::string pem = update_cert_.ToPEM();
    auto verified_cert = UpdateCertificate::LoadFromPEM(pem, root_cert_, time(nullptr));

    auto metadata = verified_cert.GetDeviceMetadata();

    // DeviceMetadata now contains only device identification
    EXPECT_EQ(metadata.hardware_id, "TEST-DEVICE-001");
    EXPECT_EQ(metadata.manufacturer, "Test Manufacturer");
    EXPECT_EQ(metadata.device_type, "Test-Device");
    EXPECT_TRUE(metadata.requires.empty());  // No constraints

    // Operational fields (manifest_version, type, artifacts) are in Manifest
    auto manifest = verified_cert.GetManifest();
    EXPECT_EQ(manifest.GetManifestVersion(), 1);
    EXPECT_EQ(manifest.GetType(), ManifestType::FULL);
    EXPECT_EQ(manifest.GetArtifacts().size(), 1);
    EXPECT_EQ(manifest.GetArtifacts()[0].name, "firmware");
}

TEST_F(UpdateCertificateTest, GetDeviceMetadataWithAllOperationalFields) {
    // Create multi-artifact update
    auto bootloader_data = std::vector<uint8_t>(512, 0xBB);
    auto encrypted_bootloader = EncryptSoftware(bootloader_data);

    ManifestBuilder builder(intermediate_key_, intermediate_cert_);
    builder.AddArtifact("bootloader", encrypted_bootloader)
        .SetType("bootloader")
        .SetTargetECU("primary")
        .SetVersion(SemVer{1, 0, 0, "", ""})
        .SetSecurityVersion(5)
        .SetInstallOrder(0);

    builder.AddArtifact("firmware", encrypted_firmware_)
        .SetType("firmware")
        .SetTargetECU("primary")
        .SetVersion(SemVer{2, 3, 1, "beta", "git.abc"})
        .SetSecurityVersion(15)
        .SetInstallOrder(1);

    auto [cert_unverified, files] = builder.BuildCertificate(
        device_pubkey_, device_metadata_, 42, 365
    );

    // Serialize and reload with verification
    std::string pem = cert_unverified.ToPEM();
    auto cert = UpdateCertificate::LoadFromPEM(pem, root_cert_, time(nullptr));

    // Check device metadata
    auto metadata = cert.GetDeviceMetadata();
    EXPECT_EQ(metadata.hardware_id, "TEST-DEVICE-001");

    // Check manifest for operational fields
    auto manifest = cert.GetManifest();
    EXPECT_EQ(manifest.GetManifestVersion(), 42);
    ASSERT_EQ(manifest.GetArtifacts().size(), 2);

    EXPECT_EQ(manifest.GetArtifacts()[0].security_version, 5);
    EXPECT_EQ(manifest.GetArtifacts()[1].security_version, 15);
    EXPECT_EQ(manifest.GetArtifacts()[1].version.prerelease, "beta");
}

TEST_F(UpdateCertificateTest, GetDeviceMetadataRoundTrip) {
    // Serialize and reload with verification
    std::string pem = update_cert_.ToPEM();
    auto verified_cert = UpdateCertificate::LoadFromPEM(pem, root_cert_, time(nullptr));

    auto metadata = verified_cert.GetDeviceMetadata();

    // Serialize to protobuf
    auto pb_data = metadata.ToProtobuf();
    EXPECT_FALSE(pb_data.empty());

    // Deserialize back
    auto metadata2 = DeviceMetadata::FromProtobuf(pb_data);

    // Verify round-trip (only device identification fields)
    EXPECT_EQ(metadata2.hardware_id, metadata.hardware_id);
    EXPECT_EQ(metadata2.manufacturer, metadata.manufacturer);
    EXPECT_EQ(metadata2.device_type, metadata.device_type);
    EXPECT_EQ(metadata2.requires.size(), metadata.requires.size());
}

// ============================================================================
// Revocation Tests
// ============================================================================

TEST_F(UpdateCertificateTest, GetIntermediateIssuanceTimeReturnsCorrectTimestamp) {
    auto issuance_time = update_cert_.GetIntermediateIssuanceTime();

    // Should be recent (within last minute)
    int64_t now = time(nullptr);
    EXPECT_GE(issuance_time, now - 60);
    EXPECT_LE(issuance_time, now + 60);
}

TEST_F(UpdateCertificateTest, CanRejectCertificatesBasedOnIssuanceTime) {
    // Get issuance time
    auto issuance_time = update_cert_.GetIntermediateIssuanceTime();

    // Simulate revocation: reject all certs issued before (now + 1 second)
    std::this_thread::sleep_for(std::chrono::seconds(2));
    int64_t revocation_time = time(nullptr);

    // Old certificate should be considered revoked
    EXPECT_LT(issuance_time, revocation_time);

    // Create new intermediate after revocation
    auto new_intermediate_key = PrivateKey::Generate(KeyType::Ed25519);
    auto new_intermediate_pubkey = PublicKey::FromPrivateKey(new_intermediate_key);
    auto new_intermediate = CreateCACertificate(
        root_key_, new_intermediate_pubkey, "New Intermediate", 1825, &root_cert_
    );

    ManifestBuilder builder(new_intermediate_key, new_intermediate);
    builder.AddArtifact("fw", encrypted_firmware_);

    auto [new_cert, files] = builder.BuildCertificate(
        device_pubkey_, device_metadata_, 1, 365
    );

    auto new_issuance_time = new_cert.GetIntermediateIssuanceTime();

    // New certificate should be after revocation time
    EXPECT_GE(new_issuance_time, revocation_time);
}

// ============================================================================
// Integration Tests
// ============================================================================

TEST_F(UpdateCertificateTest, FullWorkflowLoadVerifyExtractManifestAndMetadata) {
    // 1. Save to PEM
    std::string pem = update_cert_.ToPEM();

    // 2. Load from PEM with verification (simulating HTTP response)
    //    Verification is atomic - happens during load
    auto loaded_cert = UpdateCertificate::LoadFromPEM(pem, root_cert_, time(nullptr));

    // 3. Extract manifest (already verified at load)
    auto manifest = loaded_cert.GetManifest();
    EXPECT_EQ(manifest.GetManifestVersion(), 1);
    EXPECT_EQ(manifest.GetArtifacts().size(), 1);

    // 4. Extract device metadata (already verified at load)
    auto metadata = loaded_cert.GetDeviceMetadata();
    EXPECT_EQ(metadata.hardware_id, "TEST-DEVICE-001");

    // 5. Check manifest for artifact details (not in DeviceMetadata anymore)
    EXPECT_EQ(manifest.GetArtifacts().size(), 1);
    EXPECT_EQ(manifest.GetArtifacts()[0].name, "firmware");

    // 6. Verify issuance time for revocation check
    auto issuance_time = loaded_cert.GetIntermediateIssuanceTime();
    EXPECT_GT(issuance_time, 0);
}

TEST_F(UpdateCertificateTest, MultiArtifactWorkflow) {
    // Create 3 different artifacts
    auto bootloader_data = std::vector<uint8_t>(256, 0x11);
    auto firmware_data = std::vector<uint8_t>(512, 0x22);
    auto app_data = std::vector<uint8_t>(1024, 0x33);

    auto encrypted_bootloader = EncryptSoftware(bootloader_data);
    auto encrypted_firmware = EncryptSoftware(firmware_data);
    auto encrypted_app = EncryptSoftware(app_data);

    ManifestBuilder builder(intermediate_key_, intermediate_cert_);
    builder.AddArtifact("bootloader", encrypted_bootloader).SetInstallOrder(0);
    builder.AddArtifact("firmware", encrypted_firmware).SetInstallOrder(1);
    builder.AddArtifact("app", encrypted_app).SetInstallOrder(2);

    auto [cert_unverified, files] = builder.BuildCertificate(
        device_pubkey_, device_metadata_, 1, 365
    );

    // Serialize and reload with verification
    std::string pem = cert_unverified.ToPEM();
    auto cert = UpdateCertificate::LoadFromPEM(pem, root_cert_, time(nullptr));

    // Verify manifest
    auto manifest = cert.GetManifest();
    EXPECT_EQ(manifest.GetArtifacts().size(), 3);
    EXPECT_EQ(manifest.GetEncryptionParams().size(), 3);

    // Verify metadata (device identification only)
    auto metadata = cert.GetDeviceMetadata();
    EXPECT_EQ(metadata.hardware_id, "TEST-DEVICE-001");

    // Artifact info is in manifest, not metadata
    EXPECT_EQ(manifest.GetArtifacts().size(), 3);
}
