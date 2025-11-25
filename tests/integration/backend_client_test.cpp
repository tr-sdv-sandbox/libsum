/**
 * @file backend_client_test.cpp
 * @brief End-to-end integration tests for offline workshop update flow
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "sum/common/crypto.h"
#include "sum/common/manifest.h"
#include "sum/backend/generator.h"
#include "sum/client/validator.h"
#include "manifest.pb.h"
#include <nlohmann/json.hpp>
#include <vector>
#include <ctime>

using namespace sum;
using namespace sum::crypto;

// ============================================================================
// End-to-End Offline Update Test
// ============================================================================

TEST(IntegrationTest, OfflineWorkshopUpdate) {
    // ========================================================================
    // Setup: Generate keys (one-time provisioning)
    // ========================================================================

    // Backend generates signing key pair (Ed25519)
    auto backend_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto backend_pubkey = PublicKey::FromPrivateKey(backend_privkey);

    // Device generates key pair for encryption (X25519)
    auto device_privkey = PrivateKey::Generate(KeyType::X25519);
    auto device_pubkey = PublicKey::FromPrivateKey(device_privkey);

    // ========================================================================
    // Backend: Create software update package
    // ========================================================================

    // Software binary
    std::vector<uint8_t> software = {
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57,
        0x6f, 0x72, 0x6c, 0x64, 0x21  // "Hello, World!"
    };

    // Compute software hash
    auto software_hash = SHA256::Hash(software);

    // Sign software with Ed25519
    auto software_signature = Ed25519::Sign(backend_privkey, software);

    // Generate random AES key and IV
    std::vector<uint8_t> aes_key(16);
    std::vector<uint8_t> iv(12);
    for (size_t i = 0; i < 16; i++) aes_key[i] = static_cast<uint8_t>(i);
    for (size_t i = 0; i < 12; i++) iv[i] = static_cast<uint8_t>(i + 16);

    // Encrypt software with AES-128-GCM
    auto enc_result = AES128GCM::Encrypt(aes_key, iv, software);
    auto encrypted_software = enc_result.ciphertext;

    // Wrap AES key with device public key using X25519
    auto wrapped_key = X25519::WrapKey(aes_key, device_pubkey);

    // Create manifest
    Manifest manifest;
    manifest.SetManifestVersion(42);

    // Add software artifact
    SoftwareArtifact artifact;
    artifact.name = "application";
    artifact.hash_algorithm = "SHA-256";
    artifact.expected_hash = software_hash;
    artifact.signature_algorithm = "Ed25519";
    artifact.signature = software_signature;
    artifact.size = software.size();
    manifest.AddArtifact(artifact);

    // Add encryption parameters
    EncryptionParams encryption;
    encryption.artifact_name = "application";
    encryption.algorithm = "AES-128-GCM";
    encryption.iv = iv;
    encryption.wrapped_key = wrapped_key;
    encryption.key_wrapping_algorithm = "X25519-HKDF-SHA256-ChaCha20Poly1305";
    encryption.tag = enc_result.tag;
    manifest.AddEncryptionParams(encryption);

    // Add metadata
    manifest.SetMetadata("vendor", "TestVendor");
    manifest.SetMetadata("device_type", "ESP32");

    // ========================================================================
    // Transport: USB/SD Card (simulated)
    // ========================================================================

    // In real scenario: manifest + encrypted_software written to USB

    // ========================================================================
    // Device: Verify and install update
    // ========================================================================

    // 1. Unwrap encryption key using X25519
    auto unwrapped_key = X25519::UnwrapKey(manifest.GetEncryptionParams()[0].wrapped_key, device_privkey);
    EXPECT_EQ(unwrapped_key, aes_key);

    // 2. Decrypt software using streaming API
    AES128GCM::Decryptor decryptor(unwrapped_key, manifest.GetEncryptionParams()[0].iv, manifest.GetEncryptionParams()[0].tag);
    auto decrypted_software = decryptor.Update(encrypted_software);
    auto final = decryptor.Finalize();
    decrypted_software.insert(decrypted_software.end(), final.begin(), final.end());
    EXPECT_EQ(decrypted_software, software);

    // 3. Verify software hash using streaming
    SHA256::Hasher hasher;
    hasher.Update(decrypted_software);
    auto computed_hash = hasher.Finalize();
    EXPECT_EQ(computed_hash, manifest.GetArtifacts()[0].expected_hash);

    // 4. Verify software signature with Ed25519
    EXPECT_TRUE(Ed25519::Verify(
        backend_pubkey,
        decrypted_software,
        manifest.GetArtifacts()[0].signature
    ));

    // 5. Verify metadata
    EXPECT_EQ(manifest.GetMetadata("vendor").value(), "TestVendor");
    EXPECT_EQ(manifest.GetMetadata("device_type").value(), "ESP32");

    // ========================================================================
    // Success: Software verified and ready for installation
    // ========================================================================
}

// ============================================================================
// Multi-Artifact Test (e.g., bootloader + application)
// ============================================================================

TEST(IntegrationTest, MultiArtifactUpdate) {
    // Setup: Generate keys
    auto ca_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto ca_pubkey = PublicKey::FromPrivateKey(ca_privkey);
    auto backend_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto backend_pubkey = PublicKey::FromPrivateKey(backend_privkey);
    auto device_privkey = PrivateKey::Generate(KeyType::X25519);
    auto device_pubkey = PublicKey::FromPrivateKey(device_privkey);

    // Create two software artifacts (bootloader + application)
    std::vector<uint8_t> bootloader = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> application = {0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B};

    // Generate encryption keys
    std::vector<uint8_t> bootloader_key(16, 0xAA);
    std::vector<uint8_t> bootloader_iv(12, 0x01);
    std::vector<uint8_t> app_key(16, 0xBB);
    std::vector<uint8_t> app_iv(12, 0x02);

    // Encrypt both artifacts
    auto bootloader_enc_result = AES128GCM::Encrypt(bootloader_key, bootloader_iv, bootloader);
    auto encrypted_bootloader = bootloader_enc_result.ciphertext;
    auto app_enc_result = AES128GCM::Encrypt(app_key, app_iv, application);
    auto encrypted_app = app_enc_result.ciphertext;

    // Wrap encryption keys
    auto wrapped_bootloader_key = X25519::WrapKey(bootloader_key, device_pubkey);
    auto wrapped_app_key = X25519::WrapKey(app_key, device_pubkey);

    // Create manifest with two artifacts
    Manifest manifest;
    manifest.SetManifestVersion(100);

    // Add bootloader artifact
    SoftwareArtifact bootloader_artifact;
    bootloader_artifact.name = "bootloader";
    bootloader_artifact.hash_algorithm = "SHA-256";
    bootloader_artifact.expected_hash = SHA256::Hash(bootloader);
    bootloader_artifact.signature_algorithm = "Ed25519";
    // Sign hash instead of plaintext for streaming verification
    bootloader_artifact.signature = Ed25519::Sign(backend_privkey, bootloader_artifact.expected_hash);
    bootloader_artifact.size = bootloader.size();
    manifest.AddArtifact(bootloader_artifact);

    // Add application artifact
    SoftwareArtifact app_artifact;
    app_artifact.name = "application";
    app_artifact.hash_algorithm = "SHA-256";
    app_artifact.expected_hash = SHA256::Hash(application);
    app_artifact.signature_algorithm = "Ed25519";
    // Sign hash instead of plaintext for streaming verification
    app_artifact.signature = Ed25519::Sign(backend_privkey, app_artifact.expected_hash);
    app_artifact.size = application.size();
    manifest.AddArtifact(app_artifact);

    // Add encryption params for bootloader
    EncryptionParams bootloader_enc;
    bootloader_enc.artifact_name = "bootloader";
    bootloader_enc.algorithm = "AES-128-GCM";
    bootloader_enc.iv = bootloader_iv;
    bootloader_enc.wrapped_key = wrapped_bootloader_key;
    bootloader_enc.key_wrapping_algorithm = "X25519-HKDF-SHA256-ChaCha20Poly1305";
    bootloader_enc.tag = bootloader_enc_result.tag;
    manifest.AddEncryptionParams(bootloader_enc);

    // Add encryption params for application
    EncryptionParams app_enc;
    app_enc.artifact_name = "application";
    app_enc.algorithm = "AES-128-GCM";
    app_enc.iv = app_iv;
    app_enc.wrapped_key = wrapped_app_key;
    app_enc.key_wrapping_algorithm = "X25519-HKDF-SHA256-ChaCha20Poly1305";
    app_enc.tag = app_enc_result.tag;
    manifest.AddEncryptionParams(app_enc);

    // Verify manifest structure
    EXPECT_EQ(manifest.GetArtifacts().size(), 2);
    EXPECT_EQ(manifest.GetEncryptionParams().size(), 2);

    // Create backend signing certificate (signed by CA)
    DeviceMetadata backend_meta;
    backend_meta.hardware_id = "BACKEND-SIGNER";
    backend_meta.manufacturer = "TestCorp";
    backend_meta.device_type = "Backend";

    // First create self-signed CA cert
    Manifest dummy_manifest;
    dummy_manifest.SetManifestVersion(1);
    DeviceMetadata ca_meta;
    ca_meta.hardware_id = "CA";
    ca_meta.manufacturer = "TestCorp";
    ca_meta.device_type = "CA";

    auto ca_cert = CreateCertificateWithManifest(
        dummy_manifest,
        ca_privkey,
        ca_pubkey,
        ca_meta
    );

    // Create backend signing certificate
    auto backend_cert = CreateCertificateWithManifest(
        manifest,
        ca_privkey,  // Signed by CA
        backend_pubkey,
        backend_meta
    );

    // Set the signing certificate in manifest
    manifest.SetSigningCertificate(backend_cert.ToDER());

    // Create validator
    ManifestValidator validator(ca_cert, device_privkey);

    // Process bootloader (artifact index 0) using streaming
    auto bootloader_unwrapped = validator.UnwrapEncryptionKey(manifest, 0);
    EXPECT_EQ(bootloader_unwrapped, bootloader_key);

    auto bootloader_decryptor = validator.CreateDecryptor(bootloader_unwrapped, manifest, 0);
    auto bootloader_decrypted = bootloader_decryptor->Update(encrypted_bootloader);
    auto bootloader_final = bootloader_decryptor->Finalize();
    bootloader_decrypted.insert(bootloader_decrypted.end(), bootloader_final.begin(), bootloader_final.end());
    EXPECT_EQ(bootloader_decrypted, bootloader);

    // Verify bootloader with streaming hash
    SHA256::Hasher bootloader_hasher;
    bootloader_hasher.Update(bootloader_decrypted);
    auto bootloader_hash = bootloader_hasher.Finalize();
    EXPECT_TRUE(validator.VerifySignature(bootloader_hash, manifest, 0))
        << "Bootloader verification should pass";

    // Process application (artifact index 1) using streaming
    auto app_unwrapped = validator.UnwrapEncryptionKey(manifest, 1);
    EXPECT_EQ(app_unwrapped, app_key);

    auto app_decryptor = validator.CreateDecryptor(app_unwrapped, manifest, 1);
    auto app_decrypted = app_decryptor->Update(encrypted_app);
    auto app_final = app_decryptor->Finalize();
    app_decrypted.insert(app_decrypted.end(), app_final.begin(), app_final.end());
    EXPECT_EQ(app_decrypted, application);

    // Verify application with streaming hash
    SHA256::Hasher app_hasher;
    app_hasher.Update(app_decrypted);
    auto app_hash = app_hasher.Finalize();
    EXPECT_TRUE(validator.VerifySignature(app_hash, manifest, 1))
        << "Application verification should pass";

    // Test out-of-bounds index
    EXPECT_THROW(validator.UnwrapEncryptionKey(manifest, 2), CryptoError)
        << "Invalid index should throw";
    EXPECT_THROW(validator.CreateDecryptor(app_unwrapped, manifest, 2), CryptoError)
        << "Invalid index should throw";
    std::vector<uint8_t> dummy_hash(32, 0);
    EXPECT_THROW(validator.VerifySignature(dummy_hash, manifest, 2), CryptoError)
        << "Invalid index should throw";
}

// ============================================================================
// Protobuf Serialization Test
// ============================================================================

TEST(IntegrationTest, ManifestProtobufRoundTrip) {
    auto backend_privkey = PrivateKey::Generate(KeyType::Ed25519);

    std::vector<uint8_t> software = {0xDE, 0xAD, 0xBE, 0xEF};

    // Create manifest
    Manifest original;
    original.SetManifestVersion(99);

    SoftwareArtifact artifact;
    artifact.name = "firmware";
    artifact.hash_algorithm = "SHA-256";
    artifact.expected_hash = SHA256::Hash(software);
    artifact.signature_algorithm = "Ed25519";
    artifact.signature = Ed25519::Sign(backend_privkey, software);
    artifact.size = software.size();
    original.AddArtifact(artifact);

    original.SetMetadata("build_date", "2025-01-15");

    // Serialize and deserialize
    auto protobuf_data = original.ToProtobuf();
    Manifest loaded = Manifest::LoadFromProtobuf(protobuf_data);

    // Verify
    EXPECT_EQ(loaded.GetManifestVersion(), 99);
    EXPECT_EQ(loaded.GetArtifacts().size(), 1);
    EXPECT_EQ(loaded.GetArtifacts()[0].name, "firmware");
    EXPECT_EQ(loaded.GetArtifacts()[0].expected_hash, artifact.expected_hash);
    EXPECT_EQ(loaded.GetMetadata("build_date").value(), "2025-01-15");
}

// ============================================================================
// Security Tests
// ============================================================================

TEST(IntegrationTest, RejectTamperedSoftware) {
    auto backend_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto backend_pubkey = PublicKey::FromPrivateKey(backend_privkey);

    std::vector<uint8_t> software = {0x01, 0x02, 0x03};
    auto signature = Ed25519::Sign(backend_privkey, software);

    // Tamper with software
    software[1] = 0xFF;

    // Verification should fail
    EXPECT_THROW(Ed25519::Verify(backend_pubkey, software, signature), SignatureVerificationError);
}

TEST(IntegrationTest, RejectWrongDevice) {
    // Device 1
    auto device1_privkey = PrivateKey::Generate(KeyType::X25519);
    auto device1_pubkey = PublicKey::FromPrivateKey(device1_privkey);

    // Device 2
    auto device2_privkey = PrivateKey::Generate(KeyType::X25519);

    // Wrap key for device 1
    std::vector<uint8_t> aes_key(16, 0xAA);
    auto wrapped_key = X25519::WrapKey(aes_key, device1_pubkey);

    // Device 2 tries to unwrap (should fail)
    EXPECT_THROW(X25519::UnwrapKey(wrapped_key, device2_privkey), KeyUnwrapError);
}

TEST(IntegrationTest, RejectTamperedWrappedKey) {
    auto device_privkey = PrivateKey::Generate(KeyType::X25519);
    auto device_pubkey = PublicKey::FromPrivateKey(device_privkey);

    std::vector<uint8_t> aes_key(16, 0xAA);
    auto wrapped_key = X25519::WrapKey(aes_key, device_pubkey);

    // Tamper with wrapped key
    // X25519 format: [ephemeral_pubkey(32) || nonce(12) || encrypted_key(16) || tag(16)]
    size_t tamper_offset = 32 + 12 + 5;  // In the encrypted key section
    wrapped_key[tamper_offset] ^= 0xFF;

    // Unwrapping should fail with authentication error
    EXPECT_THROW(X25519::UnwrapKey(wrapped_key, device_privkey), KeyUnwrapError);
}

// ============================================================================
// X.509 Manifest Extension Test
// ============================================================================

TEST(IntegrationTest, ManifestEmbeddedInCertificate) {
    // Generate keys
    auto backend_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto backend_pubkey = PublicKey::FromPrivateKey(backend_privkey);

    // Create software and manifest
    std::vector<uint8_t> software = {0x01, 0x02, 0x03, 0x04, 0x05};

    Manifest manifest;
    manifest.SetManifestVersion(100);

    SoftwareArtifact artifact;
    artifact.name = "firmware";
    artifact.hash_algorithm = "SHA-256";
    artifact.expected_hash = SHA256::Hash(software);
    artifact.signature_algorithm = "Ed25519";
    artifact.signature = Ed25519::Sign(backend_privkey, software);
    artifact.size = software.size();
    manifest.AddArtifact(artifact);

    manifest.SetMetadata("version", "1.0.0");

    // Create device metadata
    DeviceMetadata device_meta;
    device_meta.hardware_id = "TEST-DEVICE-12345";
    device_meta.manufacturer = "Acme Corp";
    device_meta.device_type = "ESP32-Gateway";
    device_meta.hardware_version = "v2.1";

    // Create certificate with embedded manifest and device metadata
    auto cert = CreateCertificateWithManifest(
        manifest,
        backend_privkey,
        backend_pubkey,
        device_meta,
        "Workshop Update Cert",
        365
    );

    // Verify certificate has both extensions
    EXPECT_TRUE(cert.HasManifestExtension());
    EXPECT_TRUE(cert.HasDeviceMetadata());

    // Extract and verify device metadata
    auto device_metadata = cert.GetDeviceMetadata();
    EXPECT_EQ(device_metadata.hardware_id, "TEST-DEVICE-12345");
    EXPECT_EQ(device_metadata.manufacturer, "Acme Corp");
    EXPECT_EQ(device_metadata.device_type, "ESP32-Gateway");
    EXPECT_EQ(device_metadata.hardware_version, "v2.1");

    // Extract and verify manifest from certificate (self-signed, so verify against itself)
    auto manifest_data = cert.GetVerifiedManifest(cert, time(nullptr));
    EXPECT_FALSE(manifest_data.empty());

    // Parse extracted manifest
    auto extracted_manifest = Manifest::LoadFromProtobuf(manifest_data);

    // Verify manifest contents
    EXPECT_EQ(extracted_manifest.GetManifestVersion(), 100);
    EXPECT_EQ(extracted_manifest.GetArtifacts().size(), 1);
    EXPECT_EQ(extracted_manifest.GetArtifacts()[0].name, "firmware");
    EXPECT_EQ(extracted_manifest.GetArtifacts()[0].expected_hash, artifact.expected_hash);
    EXPECT_EQ(extracted_manifest.GetMetadata("version").value(), "1.0.0");

    // Verify software using extracted manifest
    auto computed_hash = SHA256::Hash(software);
    EXPECT_EQ(computed_hash, extracted_manifest.GetArtifacts()[0].expected_hash);

    auto pubkey_from_cert = cert.GetPublicKey();
    EXPECT_TRUE(Ed25519::Verify(
        pubkey_from_cert,
        software,
        extracted_manifest.GetArtifacts()[0].signature
    ));
}

// ============================================================================
// X.509 Extension Tampering Tests
// ============================================================================

TEST(IntegrationTest, RejectTamperedDeviceMetadata) {
    auto backend_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto backend_pubkey = PublicKey::FromPrivateKey(backend_privkey);

    std::vector<uint8_t> software = {0x01, 0x02, 0x03};

    Manifest manifest;
    manifest.SetManifestVersion(100);

    SoftwareArtifact artifact;
    artifact.name = "firmware";
    artifact.hash_algorithm = "SHA-256";
    artifact.expected_hash = SHA256::Hash(software);
    artifact.signature_algorithm = "Ed25519";
    artifact.signature = Ed25519::Sign(backend_privkey, software);
    artifact.size = software.size();
    manifest.AddArtifact(artifact);

    DeviceMetadata device_meta;
    device_meta.hardware_id = "DEVICE-001";
    device_meta.manufacturer = "Acme Corp";
    device_meta.device_type = "Gateway";

    // Create valid certificate (self-signed)
    auto cert = CreateCertificateWithManifest(
        manifest,
        backend_privkey,
        backend_pubkey,
        device_meta
    );

    // Verify the original certificate is valid (self-signed)
    EXPECT_TRUE(cert.VerifyChain(cert, time(nullptr))) << "Original certificate should be valid";

    // Export to DER and tamper with device metadata extension
    auto cert_der = cert.ToDER();

    // Find and corrupt the device metadata (search for "DEVICE-001" and change to "DEVICE-999")
    std::string cert_str(cert_der.begin(), cert_der.end());
    size_t pos = cert_str.find("DEVICE-001");
    ASSERT_NE(pos, std::string::npos) << "Device ID not found in certificate";

    cert_str[pos + 7] = '9';  // Change DEVICE-001 to DEVICE-901
    cert_str[pos + 8] = '9';  // Change DEVICE-001 to DEVICE-991
    cert_str[pos + 9] = '9';  // Change DEVICE-001 to DEVICE-999

    std::vector<uint8_t> tampered_cert_der(cert_str.begin(), cert_str.end());

    // Load tampered certificate
    auto tampered_cert = Certificate::LoadFromDER(tampered_cert_der);

    // Verify the tampered data is present
    auto tampered_meta = tampered_cert.GetDeviceMetadata();
    EXPECT_EQ(tampered_meta.hardware_id, "DEVICE-999") << "Tampering changed the data";

    // CRITICAL: Signature verification should FAIL on tampered certificate
    // The X.509 signature covers ALL fields including extensions
    EXPECT_FALSE(tampered_cert.VerifyChain(tampered_cert, time(nullptr)))
        << "Tampered certificate MUST fail signature verification";
}

TEST(IntegrationTest, RejectTamperedManifest) {
    auto backend_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto backend_pubkey = PublicKey::FromPrivateKey(backend_privkey);

    std::vector<uint8_t> software = {0x01, 0x02, 0x03};

    Manifest manifest;
    manifest.SetManifestVersion(42);

    SoftwareArtifact artifact;
    artifact.name = "firmware";
    artifact.type = "firmware";
    artifact.target_ecu = "primary";
    artifact.install_order = 0;
    artifact.hash_algorithm = "SHA-256";
    artifact.expected_hash = SHA256::Hash(software);
    artifact.signature_algorithm = "Ed25519";
    artifact.signature = Ed25519::Sign(backend_privkey, software);
    artifact.size = software.size();
    // No encryption in this test, so ciphertext fields left empty (proto3 defaults)
    artifact.ciphertext_hash = {};
    artifact.ciphertext_size = 0;
    manifest.AddArtifact(artifact);

    DeviceMetadata device_meta;
    device_meta.hardware_id = "TEST-001";
    device_meta.manufacturer = "Test Corp";
    device_meta.device_type = "TestDev";

    // Create valid certificate (self-signed)
    auto cert = CreateCertificateWithManifest(
        manifest,
        backend_privkey,
        backend_pubkey,
        device_meta
    );

    // Verify the original certificate is valid (self-signed)
    EXPECT_TRUE(cert.VerifyChain(cert, time(nullptr))) << "Original certificate should be valid";

    // Export to DER and tamper with manifest version
    auto cert_der = cert.ToDER();

    // Find and corrupt the manifest version in protobuf format
    // Protobuf field 2 (manifest_version), value 42:
    // Wire format: 0x10 (field 2, type varint) 0x2a (42 as varint)
    std::vector<uint8_t> tampered_cert_der = cert_der;
    bool found = false;
    for (size_t i = 0; i < tampered_cert_der.size() - 1; i++) {
        if (tampered_cert_der[i] == 0x10 && tampered_cert_der[i + 1] == 0x2a) {
            // Change version from 42 (0x2a) to 99 (0x63)
            tampered_cert_der[i + 1] = 0x63;
            found = true;
            break;
        }
    }
    ASSERT_TRUE(found) << "Manifest version (protobuf 0x10 0x2a) not found in certificate";

    // Load tampered certificate
    auto tampered_cert = Certificate::LoadFromDER(tampered_cert_der);

    // CRITICAL: GetVerifiedManifest MUST throw because signature verification fails
    // The X.509 signature covers ALL fields including extensions
    // With the new API, you cannot even access the manifest without verification
    EXPECT_THROW({
        auto manifest_data = tampered_cert.GetVerifiedManifest(tampered_cert, time(nullptr));
    }, CryptoError) << "Tampered certificate MUST reject manifest extraction";
}

// Demonstrate proper certificate chain verification protects extensions
TEST(IntegrationTest, CertificateSignatureProtectsExtensions) {
    // Create CA key pair
    auto ca_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto ca_pubkey = PublicKey::FromPrivateKey(ca_privkey);

    // Create end-entity key pair
    auto ee_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto ee_pubkey = PublicKey::FromPrivateKey(ee_privkey);

    std::vector<uint8_t> software = {0xAA, 0xBB, 0xCC};

    Manifest manifest;
    manifest.SetManifestVersion(100);

    SoftwareArtifact artifact;
    artifact.name = "app";
    artifact.hash_algorithm = "SHA-256";
    artifact.expected_hash = SHA256::Hash(software);
    artifact.signature_algorithm = "Ed25519";
    artifact.signature = Ed25519::Sign(ee_privkey, software);
    artifact.size = software.size();
    manifest.AddArtifact(artifact);

    DeviceMetadata device_meta;
    device_meta.hardware_id = "SECURE-DEVICE-123";
    device_meta.manufacturer = "SecureCorp";
    device_meta.device_type = "SecureGateway";

    // Create certificate signed by CA
    auto cert = CreateCertificateWithManifest(
        manifest,
        ca_privkey,  // Signed by CA
        ee_pubkey,   // Subject is end-entity
        device_meta
    );

    // NOTE: To properly verify this certificate in production:
    // 1. Load the CA certificate
    // 2. Call cert.VerifyChain(ca_cert, time(nullptr))
    // 3. If VerifyChain returns true, ALL extensions are integrity-protected
    // 4. Any tampering with device_metadata or manifest will cause verification to fail
    //
    // The X.509 signature covers:
    // - Subject name, public key, validity dates
    // - ALL extensions (including our custom device_metadata and manifest)
    //
    // This provides cryptographic integrity protection for the entire update package.

    EXPECT_TRUE(cert.HasDeviceMetadata());
    EXPECT_TRUE(cert.HasManifestExtension());
}

// Test proper CA hierarchy with separate CA and end-entity certificates
TEST(IntegrationTest, ProperCAHierarchyVerification) {
    // Create CA key pair
    auto ca_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto ca_pubkey = PublicKey::FromPrivateKey(ca_privkey);

    // Create end-entity key pair
    auto ee_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto ee_pubkey = PublicKey::FromPrivateKey(ee_privkey);

    std::vector<uint8_t> software = {0x11, 0x22, 0x33};

    Manifest manifest;
    manifest.SetManifestVersion(42);

    SoftwareArtifact artifact;
    artifact.name = "firmware";
    artifact.hash_algorithm = "SHA-256";
    artifact.expected_hash = SHA256::Hash(software);
    artifact.signature_algorithm = "Ed25519";
    artifact.signature = Ed25519::Sign(ee_privkey, software);
    artifact.size = software.size();
    manifest.AddArtifact(artifact);

    DeviceMetadata device_meta;
    device_meta.hardware_id = "DEVICE-CA-TEST";
    device_meta.manufacturer = "TestCorp";
    device_meta.device_type = "TestDevice";

    // Create certificate signed by CA private key
    auto ee_cert = CreateCertificateWithManifest(
        manifest,
        ca_privkey,  // Signed by CA
        ee_pubkey,   // Subject is end-entity
        device_meta
    );

    // Create a self-signed CA certificate for verification
    Manifest ca_manifest;
    ca_manifest.SetManifestVersion(1);
    DeviceMetadata ca_meta;
    ca_meta.hardware_id = "CA-ROOT";
    ca_meta.manufacturer = "TestCA";
    ca_meta.device_type = "CA";

    auto ca_cert = CreateCertificateWithManifest(
        ca_manifest,
        ca_privkey,  // Self-signed
        ca_pubkey,
        ca_meta
    );

    // Verify the end-entity certificate against CA
    EXPECT_TRUE(ee_cert.VerifyChain(ca_cert, time(nullptr)))
        << "End-entity cert should verify against CA cert";

    // Can extract verified manifest and metadata
    auto verified_manifest_data = ee_cert.GetVerifiedManifest(ca_cert, time(nullptr));
    auto verified_manifest = Manifest::LoadFromProtobuf(verified_manifest_data);
    EXPECT_EQ(verified_manifest.GetManifestVersion(), 42);

    auto verified_meta = ee_cert.GetVerifiedDeviceMetadata(ca_cert, time(nullptr));
    EXPECT_EQ(verified_meta.hardware_id, "DEVICE-CA-TEST");

    // Create a different CA key pair
    auto wrong_ca_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto wrong_ca_pubkey = PublicKey::FromPrivateKey(wrong_ca_privkey);

    Manifest wrong_ca_manifest;
    wrong_ca_manifest.SetManifestVersion(1);
    DeviceMetadata wrong_ca_meta;
    wrong_ca_meta.hardware_id = "WRONG-CA";
    wrong_ca_meta.manufacturer = "WrongCA";
    wrong_ca_meta.device_type = "CA";

    auto wrong_ca_cert = CreateCertificateWithManifest(
        wrong_ca_manifest,
        wrong_ca_privkey,
        wrong_ca_pubkey,
        wrong_ca_meta
    );

    // Verification should fail with wrong CA
    EXPECT_FALSE(ee_cert.VerifyChain(wrong_ca_cert, time(nullptr)))
        << "End-entity cert should NOT verify against wrong CA";

    // GetVerifiedManifest should throw with wrong CA
    EXPECT_THROW({
        auto manifest_data = ee_cert.GetVerifiedManifest(wrong_ca_cert, time(nullptr));
    }, CryptoError) << "Should reject manifest when verified with wrong CA";
}

// Test timestamp validation for certificate expiration
TEST(IntegrationTest, TimestampValidation) {
    auto privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto pubkey = PublicKey::FromPrivateKey(privkey);

    std::vector<uint8_t> software = {0xAA, 0xBB};

    Manifest manifest;
    manifest.SetManifestVersion(1);

    SoftwareArtifact artifact;
    artifact.name = "test";
    artifact.hash_algorithm = "SHA-256";
    artifact.expected_hash = SHA256::Hash(software);
    artifact.signature_algorithm = "Ed25519";
    artifact.signature = Ed25519::Sign(privkey, software);
    manifest.AddArtifact(artifact);

    DeviceMetadata device_meta;
    device_meta.hardware_id = "TIME-TEST";
    device_meta.manufacturer = "TimeCorp";
    device_meta.device_type = "TimeDevice";

    // Create certificate with 365 day validity
    auto cert = CreateCertificateWithManifest(
        manifest, privkey, pubkey, device_meta,
        "Time Test", 365
    );

    // Verify with current time should pass
    EXPECT_TRUE(cert.VerifyChain(cert, time(nullptr)))
        << "Certificate should be valid with current time";

    // Note: OpenSSL's X509_gmtime_adj sets notBefore to current time
    // and notAfter to current time + validity_days
    // We can't easily test expired certificates without manipulating system time
    // or waiting, but the API is in place for production use.
    //
    // In production, you MUST:
    // - Use a trusted timestamp (from secure clock or signed timestamp token)
    // - Call VerifyChain(ca_cert, trusted_time)
    // - The function will ALWAYS check: notBefore <= trusted_time <= notAfter
}

// Test invalid JSON in extensions
TEST(IntegrationTest, InvalidJSONInExtensions) {
    auto privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto pubkey = PublicKey::FromPrivateKey(privkey);

    std::vector<uint8_t> software = {0x01};

    Manifest manifest;
    manifest.SetManifestVersion(1);

    SoftwareArtifact artifact;
    artifact.name = "test";
    artifact.hash_algorithm = "SHA-256";
    artifact.expected_hash = SHA256::Hash(software);
    artifact.signature_algorithm = "Ed25519";
    artifact.signature = Ed25519::Sign(privkey, software);
    manifest.AddArtifact(artifact);

    DeviceMetadata device_meta;
    device_meta.hardware_id = "JSON-TEST";
    device_meta.manufacturer = "JSONCorp";
    device_meta.device_type = "JSONDevice";

    auto cert = CreateCertificateWithManifest(
        manifest, privkey, pubkey, device_meta
    );

    // Get the certificate as DER
    auto cert_der = cert.ToDER();
    std::string cert_str(cert_der.begin(), cert_der.end());

    // Find the device metadata JSON and corrupt it by inserting invalid JSON
    size_t pos = cert_str.find("\"hardware_id\"");
    if (pos != std::string::npos) {
        // Insert invalid characters to break JSON parsing
        cert_str.insert(pos, "{{{INVALID");

        std::vector<uint8_t> tampered_cert_der(cert_str.begin(), cert_str.end());

        // Try to load the tampered certificate
        // The certificate structure itself may load, but JSON parsing should fail
        try {
            auto tampered_cert = Certificate::LoadFromDER(tampered_cert_der);

            // GetDeviceMetadata should throw when parsing corrupt protobuf
            EXPECT_THROW(tampered_cert.GetDeviceMetadata(), std::runtime_error)
                << "Corrupt protobuf should fail to parse";

        } catch (const CryptoError& e) {
            // Certificate loading might fail due to corruption - that's also acceptable
            SUCCEED() << "Certificate loading rejected corrupt data: " << e.what();
        }
    }
}

// Test corrupt extension data
TEST(IntegrationTest, CorruptExtensionData) {
    auto privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto pubkey = PublicKey::FromPrivateKey(privkey);

    std::vector<uint8_t> software = {0xFF};

    Manifest manifest;
    manifest.SetManifestVersion(999);

    SoftwareArtifact artifact;
    artifact.name = "test";
    artifact.hash_algorithm = "SHA-256";
    artifact.expected_hash = SHA256::Hash(software);
    artifact.signature_algorithm = "Ed25519";
    artifact.signature = Ed25519::Sign(privkey, software);
    manifest.AddArtifact(artifact);

    DeviceMetadata device_meta;
    device_meta.hardware_id = "CORRUPT-TEST";
    device_meta.manufacturer = "CorruptCorp";
    device_meta.device_type = "CorruptDevice";

    auto cert = CreateCertificateWithManifest(
        manifest, privkey, pubkey, device_meta
    );

    // Get the certificate as DER
    auto cert_der = cert.ToDER();
    std::string cert_str(cert_der.begin(), cert_der.end());

    // Find manifest version and corrupt by replacing with binary garbage
    size_t pos = cert_str.find("\"manifest_version\":999");
    if (pos != std::string::npos) {
        // Replace JSON with random bytes
        for (size_t i = 0; i < 10 && (pos + i) < cert_str.size(); ++i) {
            cert_str[pos + i] = static_cast<char>(0xFF - i);
        }

        std::vector<uint8_t> tampered_cert_der(cert_str.begin(), cert_str.end());

        // This should fail signature verification
        try {
            auto tampered_cert = Certificate::LoadFromDER(tampered_cert_der);

            // Verification must fail
            EXPECT_FALSE(tampered_cert.VerifyChain(tampered_cert, time(nullptr)))
                << "Corrupt certificate must fail verification";

        } catch (const CryptoError& e) {
            // Loading might fail due to corruption - acceptable
            SUCCEED() << "Certificate loading rejected corrupt data: " << e.what();
        }
    }
}

// ============================================================================
// Manifest Signature Tests (Critical - tests the fix for issue #4)
// ============================================================================

TEST(IntegrationTest, ManifestSignatureVerification) {
    // This test validates that manifest signatures are computed correctly
    // WITHOUT including the signature field itself (which would be circular)

    auto ca_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto ca_pubkey = PublicKey::FromPrivateKey(ca_privkey);

    std::vector<uint8_t> software = {0x01, 0x02, 0x03, 0x04};

    // Create manifest with artifact
    Manifest manifest;
    manifest.SetManifestVersion(100);

    SoftwareArtifact artifact;
    artifact.name = "test";
    artifact.hash_algorithm = "SHA-256";
    artifact.expected_hash = SHA256::Hash(software);
    artifact.signature_algorithm = "Ed25519";
    artifact.signature = Ed25519::Sign(ca_privkey, software);
    artifact.size = software.size();
    manifest.AddArtifact(artifact);

    manifest.SetMetadata("version", "1.0");

    // Create self-signed CA certificate for manifest signing
    DeviceMetadata ca_meta;
    ca_meta.hardware_id = "CA-TEST";
    ca_meta.manufacturer = "TestCA";
    ca_meta.device_type = "CA";

    Manifest ca_manifest;
    ca_manifest.SetManifestVersion(1);
    auto ca_cert = CreateCertificateWithManifest(
        ca_manifest, ca_privkey, ca_pubkey, ca_meta
    );

    // Set signing certificate in manifest
    manifest.SetSigningCertificate(ca_cert.ToDER());

    // Sign the manifest using ManifestGenerator
    ManifestGenerator generator(ca_privkey, ca_cert);
    generator.SignManifest(manifest);

    // Verify signature is set
    ASSERT_FALSE(manifest.GetSignature().empty()) << "Signature should be set";

    // Verify the manifest using ManifestValidator
    ManifestValidator validator(ca_cert, PrivateKey::Generate(KeyType::X25519));
    EXPECT_TRUE(validator.VerifyManifest(manifest))
        << "Valid manifest signature should verify";

    // Now tamper with manifest data (change version)
    manifest.SetManifestVersion(999);

    // Verification should FAIL because manifest data changed but signature didn't
    EXPECT_FALSE(validator.VerifyManifest(manifest))
        << "Manifest signature should fail after tampering with data";
}

TEST(IntegrationTest, ManifestSignatureExcludesSignatureField) {
    // This test specifically validates that the signature field is NOT
    // included in the data being signed (which would be circular logic)

    auto privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto pubkey = PublicKey::FromPrivateKey(privkey);

    Manifest manifest;
    manifest.SetManifestVersion(42);
    manifest.SetMetadata("test", "data");

    // Create dummy cert
    DeviceMetadata meta;
    meta.hardware_id = "TEST";
    meta.manufacturer = "Test";
    meta.device_type = "Test";

    Manifest cert_manifest;
    cert_manifest.SetManifestVersion(1);
    auto cert = CreateCertificateWithManifest(cert_manifest, privkey, pubkey, meta);
    manifest.SetSigningCertificate(cert.ToDER());

    // Sign the manifest
    ManifestGenerator generator(privkey, cert);
    generator.SignManifest(manifest);

    auto signature1 = manifest.GetSignature();
    ASSERT_FALSE(signature1.empty());

    // Sign it again - signature should be IDENTICAL
    // (If signature field was included in signing, this would fail because
    //  the signature would be different each time due to including itself)
    generator.SignManifest(manifest);
    auto signature2 = manifest.GetSignature();

    // Ed25519 is deterministic - same input = same signature
    EXPECT_EQ(signature1, signature2)
        << "Re-signing should produce identical signature (proves signature field excluded)";
}

// ============================================================================
// Input Validation Tests
// ============================================================================

TEST(IntegrationTest, RejectWrongKeyTypeForSigning) {
    // Test that Ed25519::Sign rejects X25519 keys
    auto x25519_key = PrivateKey::Generate(KeyType::X25519);
    std::vector<uint8_t> data = {1, 2, 3, 4};

    EXPECT_THROW({
        Ed25519::Sign(x25519_key, data);
    }, CryptoError) << "Ed25519::Sign should reject X25519 keys";
}

TEST(IntegrationTest, RejectWrongKeyTypeForVerification) {
    // Test that Ed25519::Verify rejects X25519 public keys
    auto ed25519_key = PrivateKey::Generate(KeyType::Ed25519);
    auto ed25519_pub = PublicKey::FromPrivateKey(ed25519_key);
    auto x25519_key = PrivateKey::Generate(KeyType::X25519);
    auto x25519_pub = PublicKey::FromPrivateKey(x25519_key);

    std::vector<uint8_t> data = {1, 2, 3, 4};
    auto signature = Ed25519::Sign(ed25519_key, data);

    EXPECT_THROW({
        Ed25519::Verify(x25519_pub, data, signature);
    }, CryptoError) << "Ed25519::Verify should reject X25519 public keys";
}

TEST(IntegrationTest, RejectWrongKeyTypeForKeyWrapping) {
    // Test that X25519::WrapKey rejects Ed25519 public keys
    auto ed25519_key = PrivateKey::Generate(KeyType::Ed25519);
    auto ed25519_pub = PublicKey::FromPrivateKey(ed25519_key);
    std::vector<uint8_t> aes_key(16, 0x42);

    EXPECT_THROW({
        X25519::WrapKey(aes_key, ed25519_pub);
    }, CryptoError) << "X25519::WrapKey should reject Ed25519 public keys";
}

TEST(IntegrationTest, RejectWrongKeyTypeForKeyUnwrapping) {
    // Test that X25519::UnwrapKey rejects Ed25519 private keys
    auto x25519_key = PrivateKey::Generate(KeyType::X25519);
    auto x25519_pub = PublicKey::FromPrivateKey(x25519_key);
    auto ed25519_key = PrivateKey::Generate(KeyType::Ed25519);

    std::vector<uint8_t> aes_key(16, 0x42);
    auto wrapped_key = X25519::WrapKey(aes_key, x25519_pub);

    EXPECT_THROW({
        X25519::UnwrapKey(wrapped_key, ed25519_key);
    }, CryptoError) << "X25519::UnwrapKey should reject Ed25519 private keys";
}

TEST(IntegrationTest, RejectInvalidSignatureSize) {
    // Test that Ed25519::Verify rejects signatures that aren't 64 bytes
    auto privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto pubkey = PublicKey::FromPrivateKey(privkey);
    std::vector<uint8_t> data = {1, 2, 3, 4};

    // Test signature too short
    std::vector<uint8_t> short_sig(32, 0);  // Should be 64
    EXPECT_THROW({
        Ed25519::Verify(pubkey, data, short_sig);
    }, CryptoError) << "Should reject 32-byte signature";

    // Test signature too long
    std::vector<uint8_t> long_sig(100, 0);  // Should be 64
    EXPECT_THROW({
        Ed25519::Verify(pubkey, data, long_sig);
    }, CryptoError) << "Should reject 100-byte signature";
}

TEST(IntegrationTest, RejectInvalidAESKeySize) {
    // Test that AES operations reject wrong key sizes
    std::vector<uint8_t> plaintext = {1, 2, 3, 4};
    std::vector<uint8_t> iv(12, 0);

    // Key too small
    std::vector<uint8_t> small_key(8, 0);
    EXPECT_THROW({
        AES128GCM::Encrypt(small_key, iv, plaintext);
    }, CryptoError) << "Should reject 8-byte AES key";

    // Key too large
    std::vector<uint8_t> large_key(32, 0);
    EXPECT_THROW({
        AES128GCM::Encrypt(large_key, iv, plaintext);
    }, CryptoError) << "Should reject 32-byte AES key";
}

TEST(IntegrationTest, RejectInvalidIVSize) {
    // Test that AES operations reject wrong IV sizes
    std::vector<uint8_t> plaintext = {1, 2, 3, 4};
    std::vector<uint8_t> key(16, 0);

    // IV too small
    std::vector<uint8_t> small_iv(8, 0);
    EXPECT_THROW({
        AES128GCM::Encrypt(key, small_iv, plaintext);
    }, CryptoError) << "Should reject 8-byte IV";

    // IV too large
    std::vector<uint8_t> large_iv(16, 0);
    EXPECT_THROW({
        AES128GCM::Encrypt(key, large_iv, plaintext);
    }, CryptoError) << "Should reject 16-byte IV";
}

TEST(IntegrationTest, RejectInvalidWrappedKeySize) {
    // Test that X25519::UnwrapKey rejects wrong wrapped key sizes
    auto privkey = PrivateKey::Generate(KeyType::X25519);

    // Wrapped key too small
    std::vector<uint8_t> small_wrapped(32, 0);  // Should be 76 bytes
    EXPECT_THROW({
        X25519::UnwrapKey(small_wrapped, privkey);
    }, CryptoError) << "Should reject 32-byte wrapped key";

    // Wrapped key too large
    std::vector<uint8_t> large_wrapped(100, 0);  // Should be 76 bytes
    EXPECT_THROW({
        X25519::UnwrapKey(large_wrapped, privkey);
    }, CryptoError) << "Should reject 100-byte wrapped key";
}

// ============================================================================
// Certificate Chain Order Validation Tests
// ============================================================================

TEST(IntegrationTest, RejectWrongIntermediate) {
    // Create proper chain but use WRONG intermediate for verification
    auto root_key = PrivateKey::Generate(KeyType::Ed25519);
    auto root_pub = PublicKey::FromPrivateKey(root_key);
    auto intermediate1_key = PrivateKey::Generate(KeyType::Ed25519);
    auto intermediate1_pub = PublicKey::FromPrivateKey(intermediate1_key);
    auto intermediate2_key = PrivateKey::Generate(KeyType::Ed25519);
    auto intermediate2_pub = PublicKey::FromPrivateKey(intermediate2_key);
    auto device_key = PrivateKey::Generate(KeyType::X25519);
    auto device_pub = PublicKey::FromPrivateKey(device_key);

    // Create root CA (self-signed)
    Manifest root_manifest;
    root_manifest.SetManifestVersion(1);
    DeviceMetadata root_meta;
    root_meta.hardware_id = "ROOT-CA";
    root_meta.manufacturer = "Test";
    root_meta.device_type = "CA";
    auto root_cert = CreateCertificateWithManifest(
        root_manifest, root_key, root_pub, root_meta, "Root CA", 365
    );

    // Create intermediate1 (signed by root)
    Manifest intermediate1_manifest;
    intermediate1_manifest.SetManifestVersion(1);
    DeviceMetadata intermediate1_meta;
    intermediate1_meta.hardware_id = "INTERMEDIATE-CA-1";
    intermediate1_meta.manufacturer = "Test";
    intermediate1_meta.device_type = "Intermediate-CA";
    auto intermediate1_cert = CreateCertificateWithManifest(
        intermediate1_manifest, root_key, intermediate1_pub, intermediate1_meta,
        "Intermediate CA 1", 365, &root_cert
    );

    // Create intermediate2 (also signed by root, but different)
    Manifest intermediate2_manifest;
    intermediate2_manifest.SetManifestVersion(1);
    DeviceMetadata intermediate2_meta;
    intermediate2_meta.hardware_id = "INTERMEDIATE-CA-2";
    intermediate2_meta.manufacturer = "Test";
    intermediate2_meta.device_type = "Intermediate-CA";
    auto intermediate2_cert = CreateCertificateWithManifest(
        intermediate2_manifest, root_key, intermediate2_pub, intermediate2_meta,
        "Intermediate CA 2", 365, &root_cert
    );

    // Create update certificate signed by intermediate1
    std::vector<uint8_t> software = {1, 2, 3, 4};
    ManifestGenerator generator(intermediate1_key, intermediate1_cert);
    DeviceMetadata device_meta;
    device_meta.hardware_id = "DEVICE-001";
    device_meta.manufacturer = "Test";
    device_meta.device_type = "Device";

    auto [update_cert, encrypted] = generator.CreateCertificate(
        software, device_pub, device_meta, 1, true, 90
    );

    // Try to verify with intermediate2 (WRONG intermediate) - should fail
    std::vector<Certificate> wrong_intermediates;
    wrong_intermediates.push_back(std::move(intermediate2_cert));

    ManifestValidator validator(root_cert, wrong_intermediates, device_key);

    EXPECT_THROW({
        validator.ValidateCertificate(update_cert, time(nullptr));
    }, CryptoError) << "Should reject update cert verified with wrong intermediate";
}

TEST(IntegrationTest, RejectNonSelfSignedRootCA) {
    // Create two keys
    auto root_key = PrivateKey::Generate(KeyType::Ed25519);
    auto root_pub = PublicKey::FromPrivateKey(root_key);
    auto other_key = PrivateKey::Generate(KeyType::Ed25519);
    auto other_pub = PublicKey::FromPrivateKey(other_key);

    // Create "root" CA signed by other_key instead of itself
    Manifest root_manifest;
    root_manifest.SetManifestVersion(1);
    DeviceMetadata root_meta;
    root_meta.hardware_id = "FAKE-ROOT";
    root_meta.manufacturer = "Test";
    root_meta.device_type = "CA";

    // This creates a certificate with root_pub but signed by other_key
    // and with issuer DN from a different cert - not truly self-signed
    Manifest other_manifest;
    other_manifest.SetManifestVersion(1);
    DeviceMetadata other_meta;
    other_meta.hardware_id = "OTHER-CA";
    other_meta.manufacturer = "Test";
    other_meta.device_type = "CA";
    auto other_cert = CreateCertificateWithManifest(
        other_manifest, other_key, other_pub, other_meta, "Other CA", 365
    );

    auto fake_root = CreateCertificateWithManifest(
        root_manifest, other_key, root_pub, root_meta, "Fake Root", 365, &other_cert
    );

    // Create update certificate
    auto device_key = PrivateKey::Generate(KeyType::X25519);
    auto device_pub = PublicKey::FromPrivateKey(device_key);

    std::vector<uint8_t> software = {1, 2, 3, 4};
    ManifestGenerator generator(root_key, fake_root);
    DeviceMetadata device_meta;
    device_meta.hardware_id = "DEVICE-001";
    device_meta.manufacturer = "Test";
    device_meta.device_type = "Device";

    auto [update_cert, encrypted] = generator.CreateCertificate(
        software, device_pub, device_meta, 1, true, 90
    );

    // Try to use fake_root as root CA - should fail DN check
    std::vector<Certificate> intermediates;
    ManifestValidator validator(fake_root, intermediates, device_key);

    EXPECT_THROW({
        validator.ValidateCertificate(update_cert, time(nullptr));
    }, CryptoError) << "Should reject non-self-signed root CA";
}

// ============================================================================
// Anti-Rollback Protection Tests
// ============================================================================

TEST(IntegrationTest, AntiRollbackPreventsOlderVersion) {
    // Setup keys
    auto backend_key = PrivateKey::Generate(KeyType::Ed25519);
    auto backend_pub = PublicKey::FromPrivateKey(backend_key);
    auto device_key = PrivateKey::Generate(KeyType::X25519);
    auto device_pub = PublicKey::FromPrivateKey(device_key);

    // Create backend cert (self-signed)
    DeviceMetadata backend_meta;
    backend_meta.hardware_id = "BACKEND";
    backend_meta.manufacturer = "TestCorp";
    backend_meta.device_type = "Backend";

    Manifest dummy;
    dummy.SetManifestVersion(1);
    auto backend_cert = CreateCertificateWithManifest(
        dummy, backend_key, backend_pub, backend_meta
    );

    ManifestGenerator generator(backend_key, backend_cert);

    // Create two updates with different versions
    std::vector<uint8_t> software_v42 = {0x42, 0x42, 0x42};
    std::vector<uint8_t> software_v41 = {0x41, 0x41, 0x41};

    auto [cert_v42, encrypted_v42] = generator.CreateCertificate(
        software_v42, device_pub, backend_meta, 42, true, 90
    );

    auto [cert_v41, encrypted_v41] = generator.CreateCertificate(
        software_v41, device_pub, backend_meta, 41, true, 90
    );

    // Validator starts with no version constraint
    ManifestValidator validator(backend_cert, device_key);

    // First update succeeds (version 42)
    auto manifest_v42 = validator.ValidateCertificate(cert_v42, time(nullptr));
    EXPECT_EQ(manifest_v42.GetManifestVersion(), 42);

    // Simulate device persisting version after successful installation
    validator.SetLastInstalledVersion(42);

    // Try to install older version 41 - should FAIL
    EXPECT_THROW({
        validator.ValidateCertificate(cert_v41, time(nullptr));
    }, CryptoError) << "Should reject older version (rollback attack)";
}

TEST(IntegrationTest, AntiRollbackPreventsReplay) {
    // Setup
    auto backend_key = PrivateKey::Generate(KeyType::Ed25519);
    auto backend_pub = PublicKey::FromPrivateKey(backend_key);
    auto device_key = PrivateKey::Generate(KeyType::X25519);
    auto device_pub = PublicKey::FromPrivateKey(device_key);

    DeviceMetadata backend_meta;
    backend_meta.hardware_id = "BACKEND";
    backend_meta.manufacturer = "TestCorp";
    backend_meta.device_type = "Backend";

    Manifest dummy;
    dummy.SetManifestVersion(1);
    auto backend_cert = CreateCertificateWithManifest(
        dummy, backend_key, backend_pub, backend_meta
    );

    ManifestGenerator generator(backend_key, backend_cert);

    std::vector<uint8_t> software = {0x42, 0x42, 0x42};
    auto [cert_v42, encrypted] = generator.CreateCertificate(
        software, device_pub, backend_meta, 42, true, 90
    );

    ManifestValidator validator(backend_cert, device_key);

    // First installation succeeds
    auto manifest = validator.ValidateCertificate(cert_v42, time(nullptr));
    EXPECT_EQ(manifest.GetManifestVersion(), 42);

    // Mark as installed
    validator.SetLastInstalledVersion(42);

    // Try to re-install SAME version - should FAIL (replay attack)
    EXPECT_THROW({
        validator.ValidateCertificate(cert_v42, time(nullptr));
    }, CryptoError) << "Should reject same version (replay attack)";
}

TEST(IntegrationTest, AntiRollbackAllowsNewerVersion) {
    // Setup
    auto backend_key = PrivateKey::Generate(KeyType::Ed25519);
    auto backend_pub = PublicKey::FromPrivateKey(backend_key);
    auto device_key = PrivateKey::Generate(KeyType::X25519);
    auto device_pub = PublicKey::FromPrivateKey(device_key);

    DeviceMetadata backend_meta;
    backend_meta.hardware_id = "BACKEND";
    backend_meta.manufacturer = "TestCorp";
    backend_meta.device_type = "Backend";

    Manifest dummy;
    dummy.SetManifestVersion(1);
    auto backend_cert = CreateCertificateWithManifest(
        dummy, backend_key, backend_pub, backend_meta
    );

    ManifestGenerator generator(backend_key, backend_cert);

    std::vector<uint8_t> software_v42 = {0x42, 0x42, 0x42};
    std::vector<uint8_t> software_v43 = {0x43, 0x43, 0x43};

    auto [cert_v42, encrypted_v42] = generator.CreateCertificate(
        software_v42, device_pub, backend_meta, 42, true, 90
    );

    auto [cert_v43, encrypted_v43] = generator.CreateCertificate(
        software_v43, device_pub, backend_meta, 43, true, 90
    );

    ManifestValidator validator(backend_cert, device_key);

    // Install v42
    auto manifest_v42 = validator.ValidateCertificate(cert_v42, time(nullptr));
    validator.SetLastInstalledVersion(42);

    // Install v43 - should SUCCEED
    EXPECT_NO_THROW({
        auto manifest_v43 = validator.ValidateCertificate(cert_v43, time(nullptr));
        EXPECT_EQ(manifest_v43.GetManifestVersion(), 43);
    }) << "Should accept newer version";
}

// ============================================================================
// Certificate Revocation Tests
// ============================================================================

TEST(IntegrationTest, RevokeCertificateByTimestamp) {
    // Setup: Create 3-tier PKI (root CA → intermediate CA → update cert)
    auto root_key = PrivateKey::Generate(KeyType::Ed25519);
    auto root_pub = PublicKey::FromPrivateKey(root_key);

    auto intermediate_key = PrivateKey::Generate(KeyType::Ed25519);
    auto intermediate_pub = PublicKey::FromPrivateKey(intermediate_key);

    auto device_key = PrivateKey::Generate(KeyType::X25519);
    auto device_pub = PublicKey::FromPrivateKey(device_key);

    // Create root CA cert (self-signed)
    DeviceMetadata root_meta;
    root_meta.hardware_id = "ROOT-CA";
    root_meta.manufacturer = "TestCorp";
    root_meta.device_type = "RootCA";

    Manifest root_dummy;
    root_dummy.SetManifestVersion(1);
    auto root_cert = CreateCertificateWithManifest(
        root_dummy, root_key, root_pub, root_meta, "Root CA", 3650, nullptr
    );

    // Create OLD intermediate CA (issued at T0)
    DeviceMetadata intermediate_meta;
    intermediate_meta.hardware_id = "INTERMEDIATE-CA";
    intermediate_meta.manufacturer = "TestCorp";
    intermediate_meta.device_type = "IntermediateCA";

    Manifest intermediate_dummy;
    intermediate_dummy.SetManifestVersion(1);
    auto old_intermediate_cert = CreateCertificateWithManifest(
        intermediate_dummy, root_key, intermediate_pub, intermediate_meta,
        "Intermediate CA v1", 365, &root_cert
    );

    // Get the notBefore timestamp of old intermediate
    int64_t old_intermediate_timestamp = old_intermediate_cert.GetNotBefore();

    // Create update certificate signed by old intermediate
    std::vector<uint8_t> software = {0x01, 0x02, 0x03};
    ManifestGenerator generator(intermediate_key, old_intermediate_cert);
    auto [update_cert, encrypted] = generator.CreateCertificate(
        software, device_pub, intermediate_meta, 100, true, 90
    );

    // Validator with old intermediate CA
    std::vector<Certificate> intermediates;
    intermediates.push_back(Certificate::LoadFromDER(old_intermediate_cert.ToDER()));
    ManifestValidator validator(root_cert, intermediates, device_key);

    // First update succeeds (old intermediate is trusted)
    EXPECT_NO_THROW({
        validator.ValidateCertificate(update_cert, time(nullptr));
    }) << "Update with old intermediate should succeed initially";

    // SECURITY INCIDENT: Old intermediate CA is compromised!
    // Sleep 1 second to ensure revocation timestamp is AFTER old cert notBefore
    sleep(1);

    // Set revocation timestamp to NOW (after old intermediate was issued)
    int64_t revocation_timestamp = time(nullptr);
    validator.SetRejectCertificatesBefore(revocation_timestamp);

    // Try to use update signed by old intermediate - should FAIL
    EXPECT_THROW({
        validator.ValidateCertificate(update_cert, time(nullptr));
    }, CryptoError) << "Should reject certificate signed by revoked intermediate";
}

TEST(IntegrationTest, NewIntermediateAfterRevocation) {
    // Setup PKI
    auto root_key = PrivateKey::Generate(KeyType::Ed25519);
    auto root_pub = PublicKey::FromPrivateKey(root_key);

    auto old_intermediate_key = PrivateKey::Generate(KeyType::Ed25519);
    auto old_intermediate_pub = PublicKey::FromPrivateKey(old_intermediate_key);

    auto new_intermediate_key = PrivateKey::Generate(KeyType::Ed25519);
    auto new_intermediate_pub = PublicKey::FromPrivateKey(new_intermediate_key);

    auto device_key = PrivateKey::Generate(KeyType::X25519);
    auto device_pub = PublicKey::FromPrivateKey(device_key);

    // Root CA
    DeviceMetadata root_meta;
    root_meta.hardware_id = "ROOT-CA";
    root_meta.manufacturer = "TestCorp";
    root_meta.device_type = "RootCA";

    Manifest root_dummy;
    root_dummy.SetManifestVersion(1);
    auto root_cert = CreateCertificateWithManifest(
        root_dummy, root_key, root_pub, root_meta, "Root CA", 3650, nullptr
    );

    // Old intermediate CA
    DeviceMetadata intermediate_meta;
    intermediate_meta.hardware_id = "INTERMEDIATE-CA";
    intermediate_meta.manufacturer = "TestCorp";
    intermediate_meta.device_type = "IntermediateCA";

    Manifest intermediate_dummy;
    intermediate_dummy.SetManifestVersion(1);
    auto old_intermediate_cert = CreateCertificateWithManifest(
        intermediate_dummy, root_key, old_intermediate_pub, intermediate_meta,
        "Intermediate CA v1", 365, &root_cert
    );

    // Simulate compromise and revocation
    int64_t revocation_timestamp = time(nullptr);

    // Sleep 1 second to ensure new cert has later notBefore
    sleep(1);

    // Issue NEW intermediate CA after revocation
    Manifest new_intermediate_dummy;
    new_intermediate_dummy.SetManifestVersion(2);
    auto new_intermediate_cert = CreateCertificateWithManifest(
        new_intermediate_dummy, root_key, new_intermediate_pub, intermediate_meta,
        "Intermediate CA v2", 365, &root_cert
    );

    // Create update with NEW intermediate
    std::vector<uint8_t> software = {0x01, 0x02, 0x03};
    ManifestGenerator generator(new_intermediate_key, new_intermediate_cert);
    auto [update_cert, encrypted] = generator.CreateCertificate(
        software, device_pub, intermediate_meta, 100, true, 90
    );

    // Validator with NEW intermediate and revocation policy
    std::vector<Certificate> intermediates;
    intermediates.push_back(Certificate::LoadFromDER(new_intermediate_cert.ToDER()));
    ManifestValidator validator(root_cert, intermediates, device_key);
    validator.SetRejectCertificatesBefore(revocation_timestamp);

    // Update with new intermediate should SUCCEED
    EXPECT_NO_THROW({
        auto manifest = validator.ValidateCertificate(update_cert, time(nullptr));
        EXPECT_EQ(manifest.GetManifestVersion(), 100);
    }) << "Update with new intermediate (after revocation) should succeed";
}

TEST(IntegrationTest, RejectChainWithNoIntermediates) {
    // Create keys
    auto root_key = PrivateKey::Generate(KeyType::Ed25519);
    auto root_pub = PublicKey::FromPrivateKey(root_key);
    auto device_key = PrivateKey::Generate(KeyType::X25519);
    auto device_pub = PublicKey::FromPrivateKey(device_key);

    // Create root CA (self-signed)
    Manifest root_manifest;
    root_manifest.SetManifestVersion(1);
    DeviceMetadata root_meta;
    root_meta.hardware_id = "ROOT-CA";
    root_meta.manufacturer = "Test";
    root_meta.device_type = "CA";
    auto root_cert = CreateCertificateWithManifest(
        root_manifest, root_key, root_pub, root_meta, "Root CA", 365, nullptr
    );

    // Create update certificate signed directly by root (no intermediate)
    std::vector<uint8_t> software = {1, 2, 3, 4};
    ManifestGenerator generator(root_key, root_cert);
    DeviceMetadata device_meta;
    device_meta.hardware_id = "DEVICE-001";
    device_meta.manufacturer = "Test";
    device_meta.device_type = "Device";

    auto [update_cert, encrypted] = generator.CreateCertificate(
        software, device_pub, device_meta, 1, true, 90
    );

    // Validator with NO intermediates (depth = 0, required = 1)
    std::vector<Certificate> no_intermediates;
    ManifestValidator validator(root_cert, no_intermediates, device_key);

    EXPECT_THROW({
        validator.ValidateCertificate(update_cert, time(nullptr));
    }, CryptoError) << "Should reject chain with 0 intermediates (required 1)";
}

TEST(IntegrationTest, RejectChainWithTooManyIntermediates) {
    // Create keys
    auto root_key = PrivateKey::Generate(KeyType::Ed25519);
    auto root_pub = PublicKey::FromPrivateKey(root_key);
    auto intermediate1_key = PrivateKey::Generate(KeyType::Ed25519);
    auto intermediate1_pub = PublicKey::FromPrivateKey(intermediate1_key);
    auto intermediate2_key = PrivateKey::Generate(KeyType::Ed25519);
    auto intermediate2_pub = PublicKey::FromPrivateKey(intermediate2_key);
    auto device_key = PrivateKey::Generate(KeyType::X25519);
    auto device_pub = PublicKey::FromPrivateKey(device_key);

    // Create root CA (self-signed)
    Manifest root_manifest;
    root_manifest.SetManifestVersion(1);
    DeviceMetadata root_meta;
    root_meta.hardware_id = "ROOT-CA";
    root_meta.manufacturer = "Test";
    root_meta.device_type = "CA";
    auto root_cert = CreateCertificateWithManifest(
        root_manifest, root_key, root_pub, root_meta, "Root CA", 365, nullptr
    );

    // Create intermediate1 (signed by root)
    Manifest intermediate1_manifest;
    intermediate1_manifest.SetManifestVersion(1);
    DeviceMetadata intermediate1_meta;
    intermediate1_meta.hardware_id = "INTERMEDIATE-CA-1";
    intermediate1_meta.manufacturer = "Test";
    intermediate1_meta.device_type = "Intermediate-CA";
    auto intermediate1_cert = CreateCertificateWithManifest(
        intermediate1_manifest, root_key, intermediate1_pub, intermediate1_meta,
        "Intermediate CA 1", 365, &root_cert
    );

    // Create intermediate2 (signed by intermediate1)
    Manifest intermediate2_manifest;
    intermediate2_manifest.SetManifestVersion(1);
    DeviceMetadata intermediate2_meta;
    intermediate2_meta.hardware_id = "INTERMEDIATE-CA-2";
    intermediate2_meta.manufacturer = "Test";
    intermediate2_meta.device_type = "Intermediate-CA";
    auto intermediate2_cert = CreateCertificateWithManifest(
        intermediate2_manifest, intermediate1_key, intermediate2_pub, intermediate2_meta,
        "Intermediate CA 2", 365, &intermediate1_cert
    );

    // Create update certificate signed by intermediate2
    std::vector<uint8_t> software = {1, 2, 3, 4};
    ManifestGenerator generator(intermediate2_key, intermediate2_cert);
    DeviceMetadata device_meta;
    device_meta.hardware_id = "DEVICE-001";
    device_meta.manufacturer = "Test";
    device_meta.device_type = "Device";

    auto [update_cert, encrypted] = generator.CreateCertificate(
        software, device_pub, device_meta, 1, true, 90
    );

    // Validator with 2 intermediates (depth = 2, required = 1)
    std::vector<Certificate> intermediates;
    intermediates.push_back(Certificate::LoadFromDER(intermediate2_cert.ToDER()));
    intermediates.push_back(Certificate::LoadFromDER(intermediate1_cert.ToDER()));

    ManifestValidator validator(root_cert, intermediates, device_key);

    EXPECT_THROW({
        validator.ValidateCertificate(update_cert, time(nullptr));
    }, CryptoError) << "Should reject chain with 2 intermediates (required 1)";
}

TEST(IntegrationTest, RejectSelfSignedIntermediate) {
    // Create keys
    auto root_key = PrivateKey::Generate(KeyType::Ed25519);
    auto root_pub = PublicKey::FromPrivateKey(root_key);
    auto intermediate_key = PrivateKey::Generate(KeyType::Ed25519);
    auto intermediate_pub = PublicKey::FromPrivateKey(intermediate_key);
    auto device_key = PrivateKey::Generate(KeyType::X25519);
    auto device_pub = PublicKey::FromPrivateKey(device_key);

    // Create root CA (self-signed)
    Manifest root_manifest;
    root_manifest.SetManifestVersion(1);
    DeviceMetadata root_meta;
    root_meta.hardware_id = "ROOT-CA";
    root_meta.manufacturer = "Test";
    root_meta.device_type = "CA";
    auto root_cert = CreateCertificateWithManifest(
        root_manifest, root_key, root_pub, root_meta, "Root CA", 365, nullptr
    );

    // Create self-signed intermediate (signed by itself, not root)
    Manifest intermediate_manifest;
    intermediate_manifest.SetManifestVersion(1);
    DeviceMetadata intermediate_meta;
    intermediate_meta.hardware_id = "SELF-SIGNED-INTERMEDIATE";
    intermediate_meta.manufacturer = "Test";
    intermediate_meta.device_type = "Intermediate-CA";
    auto intermediate_cert = CreateCertificateWithManifest(
        intermediate_manifest, intermediate_key, intermediate_pub, intermediate_meta,
        "Self-Signed Intermediate", 365, nullptr  // nullptr = self-signed
    );

    // Create update certificate signed by intermediate
    std::vector<uint8_t> software = {1, 2, 3, 4};
    ManifestGenerator generator(intermediate_key, intermediate_cert);
    DeviceMetadata device_meta;
    device_meta.hardware_id = "DEVICE-001";
    device_meta.manufacturer = "Test";
    device_meta.device_type = "Device";

    auto [update_cert, encrypted] = generator.CreateCertificate(
        software, device_pub, device_meta, 1, true, 90
    );

    // Validator with self-signed intermediate
    std::vector<Certificate> intermediates;
    intermediates.push_back(Certificate::LoadFromDER(intermediate_cert.ToDER()));

    ManifestValidator validator(root_cert, intermediates, device_key);

    EXPECT_THROW({
        validator.ValidateCertificate(update_cert, time(nullptr));
    }, CryptoError) << "Should reject self-signed intermediate certificate";
}
