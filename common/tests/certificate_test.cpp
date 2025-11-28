/**
 * @file certificate_test.cpp
 * @brief Comprehensive unit tests for Certificate class
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "sum/common/crypto.h"
#include "sum/common/manifest.h"
#include <fstream>
#include <ctime>
#include <thread>
#include <chrono>

using namespace sum::crypto;
using namespace sum;

// ============================================================================
// Test Fixture
// ============================================================================

class CertificateTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create CA key pair
        ca_privkey = PrivateKey::Generate(KeyType::Ed25519);
        ca_pubkey = PublicKey::FromPrivateKey(ca_privkey);

        // Create end-entity key pair
        ee_privkey = PrivateKey::Generate(KeyType::Ed25519);
        ee_pubkey = PublicKey::FromPrivateKey(ee_privkey);

        // Create CA certificate (self-signed)
        ca_cert = CreateCACertificate(ca_privkey, ca_pubkey, "Test CA", 365);

        // Create end-entity certificate signed by CA
        ee_cert = CreateEndEntityCertificate(ca_privkey, ee_pubkey, "Test EE", 365, &ca_cert);
    }

    PrivateKey ca_privkey;
    PublicKey ca_pubkey;
    PrivateKey ee_privkey;
    PublicKey ee_pubkey;
    Certificate ca_cert;
    Certificate ee_cert;
};

// ============================================================================
// Load/Save Tests
// ============================================================================

TEST_F(CertificateTest, LoadFromDER) {
    auto der = ca_cert.ToDER();

    auto loaded_cert = Certificate::LoadFromDER(der);

    // Verify loaded cert matches original
    EXPECT_EQ(loaded_cert.ToDER(), ca_cert.ToDER());
}

TEST_F(CertificateTest, LoadFromDERInvalidData) {
    std::vector<uint8_t> invalid_der = {0x01, 0x02, 0x03};

    EXPECT_THROW(Certificate::LoadFromDER(invalid_der), CryptoError);
}

TEST_F(CertificateTest, LoadFromDEREmptyData) {
    std::vector<uint8_t> empty_der;

    EXPECT_THROW(Certificate::LoadFromDER(empty_der), CryptoError);
}

TEST_F(CertificateTest, ToDERRoundTrip) {
    auto der1 = ca_cert.ToDER();
    auto loaded = Certificate::LoadFromDER(der1);
    auto der2 = loaded.ToDER();

    EXPECT_EQ(der1, der2);
}

TEST_F(CertificateTest, ToPEMFormat) {
    auto pem = ca_cert.ToPEM();

    // Verify PEM structure
    EXPECT_NE(pem.find("-----BEGIN CERTIFICATE-----"), std::string::npos);
    EXPECT_NE(pem.find("-----END CERTIFICATE-----"), std::string::npos);
    EXPECT_GT(pem.size(), 100);
}

TEST_F(CertificateTest, ToPEMRoundTrip) {
    auto pem = ca_cert.ToPEM();

    // Write to temp file and reload
    const char* temp_file = "/tmp/libsum_cert_test.pem";
    std::ofstream ofs(temp_file);
    ofs << pem;
    ofs.close();

    auto loaded = Certificate::LoadFromFile(temp_file);

    EXPECT_EQ(loaded.ToDER(), ca_cert.ToDER());

    std::remove(temp_file);
}

TEST_F(CertificateTest, LoadFromFileNotFound) {
    EXPECT_THROW(Certificate::LoadFromFile("/nonexistent/path.pem"), CryptoError);
}

// ============================================================================
// Clone Tests
// ============================================================================

TEST_F(CertificateTest, CloneProducesIdenticalCertificate) {
    auto cloned = ca_cert.Clone();

    // Verify DER encoding is identical
    EXPECT_EQ(cloned.ToDER(), ca_cert.ToDER());
    EXPECT_EQ(cloned.GetSubject(), ca_cert.GetSubject());
    EXPECT_EQ(cloned.GetIssuer(), ca_cert.GetIssuer());
}

TEST_F(CertificateTest, CloneIsIndependentCopy) {
    auto cloned = ca_cert.Clone();

    // Verify they have different memory addresses (move semantics work)
    auto der1 = ca_cert.ToDER();
    auto der2 = cloned.ToDER();

    EXPECT_EQ(der1, der2);

    // After moving original, clone should still be valid
    Certificate moved_cert = std::move(ca_cert);
    EXPECT_EQ(cloned.ToDER(), der2);
}

// ============================================================================
// Public Key Extraction Tests
// ============================================================================

TEST_F(CertificateTest, GetPublicKeyExtractsCorrectKey) {
    auto extracted_pubkey = ca_cert.GetPublicKey();

    // Verify the extracted key matches the original public key
    // We can test this by signing with the private key and verifying with extracted public key
    std::vector<uint8_t> test_data = {0x01, 0x02, 0x03};
    auto signature = Ed25519::Sign(ca_privkey, test_data);

    EXPECT_TRUE(Ed25519::Verify(extracted_pubkey, test_data, signature));
}

TEST_F(CertificateTest, GetPublicKeyCanVerifySignatures) {
    // Create a certificate signed by CA
    auto ee_pubkey_from_cert = ee_cert.GetPublicKey();

    // Sign data with EE private key
    std::vector<uint8_t> data = {0xAA, 0xBB, 0xCC};
    auto sig = Ed25519::Sign(ee_privkey, data);

    // Verify with public key extracted from certificate
    EXPECT_TRUE(Ed25519::Verify(ee_pubkey_from_cert, data, sig));
}

// ============================================================================
// Chain Verification Tests
// ============================================================================

TEST_F(CertificateTest, VerifyChainWithValidCertificate) {
    // EE cert is signed by CA
    EXPECT_TRUE(ee_cert.VerifyChain(ca_cert, time(nullptr)));
}

TEST_F(CertificateTest, VerifyChainSelfSigned) {
    // CA cert is self-signed
    EXPECT_TRUE(ca_cert.VerifyChain(ca_cert, time(nullptr)));
}

TEST_F(CertificateTest, VerifyChainWithWrongIssuer) {
    // Create another CA
    auto wrong_ca_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto wrong_ca_pubkey = PublicKey::FromPrivateKey(wrong_ca_privkey);
    auto wrong_ca = CreateCACertificate(wrong_ca_privkey, wrong_ca_pubkey, "Wrong CA", 365);

    // EE cert should not verify against wrong CA
    EXPECT_FALSE(ee_cert.VerifyChain(wrong_ca, time(nullptr)));
}

TEST_F(CertificateTest, VerifyChainWithExpiredCertificate) {
    // Create a certificate with very short validity (already expired)
    auto expired_cert = CreateEndEntityCertificate(ca_privkey, ee_pubkey, "Expired", 0, &ca_cert);

    // Wait 2 seconds to ensure it's expired
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Verification should fail
    EXPECT_FALSE(expired_cert.VerifyChain(ca_cert, time(nullptr)));
}

TEST_F(CertificateTest, VerifyChainWithFutureCertificate) {
    // Use a future timestamp (certificate not yet valid)
    int64_t future_time = time(nullptr) - 86400 * 2;  // 2 days ago

    // Fresh certificate created now should not be valid 2 days ago
    EXPECT_FALSE(ee_cert.VerifyChain(ca_cert, future_time));
}

TEST_F(CertificateTest, VerifyChainWithIntermediatesValid) {
    // Create 3-tier chain: Root -> Intermediate -> EE
    auto root_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto root_pubkey = PublicKey::FromPrivateKey(root_privkey);
    auto root_cert = CreateCACertificate(root_privkey, root_pubkey, "Root CA", 365);

    auto inter_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto inter_pubkey = PublicKey::FromPrivateKey(inter_privkey);
    auto inter_cert = CreateCACertificate(root_privkey, inter_pubkey, "Intermediate CA", 365, &root_cert);

    auto ee_cert_3tier = CreateEndEntityCertificate(inter_privkey, ee_pubkey, "End Entity", 365, &inter_cert);

    // Verify 3-tier chain
    EXPECT_TRUE(ee_cert_3tier.VerifyChainWithIntermediates(inter_cert, root_cert, time(nullptr)));
}

TEST_F(CertificateTest, VerifyChainWithIntermediatesInvalidIntermediate) {
    // Create 3-tier chain with wrong intermediate
    auto root_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto root_pubkey = PublicKey::FromPrivateKey(root_privkey);
    auto root_cert = CreateCACertificate(root_privkey, root_pubkey, "Root CA", 365);

    auto inter_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto inter_pubkey = PublicKey::FromPrivateKey(inter_privkey);
    auto inter_cert = CreateCACertificate(root_privkey, inter_pubkey, "Intermediate CA", 365, &root_cert);

    // Create EE cert signed by different key (not by the intermediate)
    auto wrong_inter_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto wrong_inter_pubkey = PublicKey::FromPrivateKey(wrong_inter_privkey);
    auto wrong_inter_cert = CreateCACertificate(wrong_inter_privkey, wrong_inter_pubkey, "Wrong Intermediate", 365);
    auto ee_cert_wrong = CreateEndEntityCertificate(wrong_inter_privkey, ee_pubkey, "End Entity", 365, &wrong_inter_cert);

    // Verification should throw (EE cert signed by wrong intermediate)
    EXPECT_THROW(ee_cert_wrong.VerifyChainWithIntermediates(inter_cert, root_cert, time(nullptr)), CryptoError);
}

// ============================================================================
// Certificate Purpose Validation Tests
// ============================================================================

TEST_F(CertificateTest, RejectUpdateCertificateWithCAFlag) {
    // Create 3-tier chain but use CA certificate as update cert (should be rejected)
    auto root_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto root_pubkey = PublicKey::FromPrivateKey(root_privkey);
    auto root_cert = CreateCACertificate(root_privkey, root_pubkey, "Root CA", 365);

    auto inter_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto inter_pubkey = PublicKey::FromPrivateKey(inter_privkey);
    auto inter_cert = CreateCACertificate(root_privkey, inter_pubkey, "Intermediate CA", 365, &root_cert);

    // Create update cert with CA flag set (using CreateCACertificate) - WRONG!
    auto update_cert_wrong = CreateCACertificate(inter_privkey, ee_pubkey, "Update Cert", 365, &inter_cert);

    // Verification should fail because update cert has CA flag set
    EXPECT_THROW({
        try {
            update_cert_wrong.VerifyChainWithIntermediates(inter_cert, root_cert, time(nullptr));
        } catch (const CryptoError& e) {
            // Verify we get the correct error message
            EXPECT_THAT(std::string(e.what()), testing::HasSubstr("CA flag set"));
            throw;
        }
    }, CryptoError);
}

TEST_F(CertificateTest, RejectIntermediateWithoutCAFlag) {
    // Create 3-tier chain but intermediate is not a CA (should be rejected)
    auto root_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto root_pubkey = PublicKey::FromPrivateKey(root_privkey);
    auto root_cert = CreateCACertificate(root_privkey, root_pubkey, "Root CA", 365);

    auto inter_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto inter_pubkey = PublicKey::FromPrivateKey(inter_privkey);
    // Create intermediate without CA flag (using CreateEndEntityCertificate) - WRONG!
    auto inter_cert_wrong = CreateEndEntityCertificate(root_privkey, inter_pubkey, "Intermediate", 365, &root_cert);

    auto update_cert = CreateEndEntityCertificate(inter_privkey, ee_pubkey, "Update Cert", 365, &inter_cert_wrong);

    // Verification should fail because intermediate doesn't have CA flag
    EXPECT_THROW({
        try {
            update_cert.VerifyChainWithIntermediates(inter_cert_wrong, root_cert, time(nullptr));
        } catch (const CryptoError& e) {
            // Verify we get the correct error message
            EXPECT_THAT(std::string(e.what()), testing::HasSubstr("intermediate CA is not a CA certificate"));
            throw;
        }
    }, CryptoError);
}

TEST_F(CertificateTest, RejectRootCAWithoutCAFlag) {
    // Create root CA without CA flag (should be rejected)
    auto root_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto root_pubkey = PublicKey::FromPrivateKey(root_privkey);
    // Create self-signed end-entity cert (simulates root without CA flag) - WRONG!
    auto root_cert_wrong = CreateEndEntityCertificate(root_privkey, root_pubkey, "Root CA", 365, nullptr);

    auto inter_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto inter_pubkey = PublicKey::FromPrivateKey(inter_privkey);
    auto inter_cert = CreateCACertificate(root_privkey, inter_pubkey, "Intermediate CA", 365, &root_cert_wrong);

    auto update_cert = CreateEndEntityCertificate(inter_privkey, ee_pubkey, "Update Cert", 365, &inter_cert);

    // Verification should fail because root doesn't have CA flag
    EXPECT_THROW({
        try {
            update_cert.VerifyChainWithIntermediates(inter_cert, root_cert_wrong, time(nullptr));
        } catch (const CryptoError& e) {
            // Verify we get the correct error message
            EXPECT_THAT(std::string(e.what()), testing::HasSubstr("root CA is not a CA certificate"));
            throw;
        }
    }, CryptoError);
}

TEST_F(CertificateTest, AcceptValidCertificatePurposes) {
    // Create properly configured 3-tier chain (should succeed)
    auto root_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto root_pubkey = PublicKey::FromPrivateKey(root_privkey);
    auto root_cert = CreateCACertificate(root_privkey, root_pubkey, "Root CA", 365, nullptr);

    auto inter_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto inter_pubkey = PublicKey::FromPrivateKey(inter_privkey);
    auto inter_cert = CreateCACertificate(root_privkey, inter_pubkey, "Intermediate CA", 365, &root_cert);

    auto update_cert = CreateEndEntityCertificate(inter_privkey, ee_pubkey, "Update Cert", 365, &inter_cert);

    // Verification should succeed - all certificate purposes are correct
    EXPECT_NO_THROW(update_cert.VerifyChainWithIntermediates(inter_cert, root_cert, time(nullptr)));
}

// ============================================================================
// Extension Tests
// ============================================================================

TEST_F(CertificateTest, HasExtensionFindsExistingExtension) {
    // Create certificate with manifest extension
    Manifest manifest;
    manifest.SetManifestVersion(42);

    DeviceMetadata metadata;
    metadata.hardware_id = "TEST-001";
    metadata.manufacturer = "Test Corp";
    metadata.device_type = "Test Device";

    auto cert_with_ext = CreateCertificateWithManifest(manifest, ca_privkey, ee_pubkey, metadata);

    EXPECT_TRUE(cert_with_ext.HasExtension(oid::MANIFEST));
    EXPECT_TRUE(cert_with_ext.HasExtension(oid::DEVICE_METADATA));
}

TEST_F(CertificateTest, HasExtensionReturnsFalseForMissingExtension) {
    // CA cert has no custom extensions
    EXPECT_FALSE(ca_cert.HasExtension(oid::MANIFEST));
    EXPECT_FALSE(ca_cert.HasExtension(oid::DEVICE_METADATA));
    EXPECT_FALSE(ca_cert.HasExtension("1.2.3.4.5"));  // Random OID
}

TEST_F(CertificateTest, GetExtensionExtractsData) {
    // Create certificate with manifest extension
    Manifest manifest;
    manifest.SetManifestVersion(42);

    DeviceMetadata metadata;
    metadata.hardware_id = "TEST-001";
    metadata.manufacturer = "Test Corp";
    metadata.device_type = "Test Device";

    auto cert_with_ext = CreateCertificateWithManifest(manifest, ca_privkey, ee_pubkey, metadata);

    // Extract manifest extension
    auto manifest_data = cert_with_ext.GetExtension(oid::MANIFEST);
    EXPECT_FALSE(manifest_data.empty());

    // Verify it's valid protobuf data by parsing
    auto parsed_manifest = Manifest::LoadFromProtobuf(manifest_data);
    EXPECT_EQ(parsed_manifest.GetManifestVersion(), 42);
}

TEST_F(CertificateTest, GetExtensionThrowsOnMissingExtension) {
    EXPECT_THROW(ca_cert.GetExtension(oid::MANIFEST), CryptoError);
    EXPECT_THROW(ca_cert.GetExtension("1.2.3.4.5"), CryptoError);
}

// ============================================================================
// Metadata Tests
// ============================================================================

TEST_F(CertificateTest, GetNotBeforeReturnsValidTimestamp) {
    auto not_before = ca_cert.GetNotBefore();

    // Should be a recent timestamp (within last minute)
    int64_t now = time(nullptr);
    EXPECT_GE(not_before, now - 60);
    EXPECT_LE(not_before, now + 60);
}

TEST_F(CertificateTest, GetSubjectReturnsCorrectDN) {
    auto subject = ca_cert.GetSubject();

    // Should contain "Test CA"
    EXPECT_NE(subject.find("Test CA"), std::string::npos);
}

TEST_F(CertificateTest, GetIssuerReturnsCorrectDN) {
    auto issuer = ca_cert.GetIssuer();

    // Self-signed cert: subject == issuer
    EXPECT_EQ(issuer, ca_cert.GetSubject());
}

TEST_F(CertificateTest, GetIssuerDiffersFromSubjectForNonSelfSigned) {
    auto ee_subject = ee_cert.GetSubject();
    auto ee_issuer = ee_cert.GetIssuer();

    // EE cert is signed by CA, so issuer != subject
    EXPECT_NE(ee_subject, ee_issuer);
    EXPECT_NE(ee_subject.find("Test EE"), std::string::npos);
    EXPECT_NE(ee_issuer.find("Test CA"), std::string::npos);
}

TEST_F(CertificateTest, GetValidityPeriodReturnsCorrectRange) {
    auto [not_before, not_after] = ca_cert.GetValidityPeriod();

    // notBefore should be recent
    int64_t now = time(nullptr);
    EXPECT_GE(not_before, now - 60);
    EXPECT_LE(not_before, now + 60);

    // notAfter should be ~365 days in the future (certificate created with 365 days validity)
    int64_t expected_not_after = now + 365 * 86400;
    EXPECT_GE(not_after, expected_not_after - 120);  // Allow 2 minute variance
    EXPECT_LE(not_after, expected_not_after + 120);

    // notAfter should be after notBefore
    EXPECT_GT(not_after, not_before);
}

// ============================================================================
// Low-level Signature Tests
// ============================================================================

TEST_F(CertificateTest, VerifySignatureWithCorrectKey) {
    auto ca_pubkey_from_cert = ca_cert.GetPublicKey();

    // CA cert is self-signed, so it should verify with its own public key
    EXPECT_TRUE(ca_cert.VerifySignature(ca_pubkey_from_cert));
}

TEST_F(CertificateTest, VerifySignatureWithIssuerKey) {
    // EE cert is signed by CA
    auto ca_pubkey_from_cert = ca_cert.GetPublicKey();

    EXPECT_TRUE(ee_cert.VerifySignature(ca_pubkey_from_cert));
}

TEST_F(CertificateTest, VerifySignatureWithWrongKey) {
    auto wrong_privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto wrong_pubkey = PublicKey::FromPrivateKey(wrong_privkey);

    // EE cert signed by CA should not verify with wrong key
    EXPECT_FALSE(ee_cert.VerifySignature(wrong_pubkey));
}

TEST_F(CertificateTest, VerifySignatureWithEEKey) {
    auto ee_pubkey_from_cert = ee_cert.GetPublicKey();

    // EE cert is not self-signed, so it should not verify with its own public key
    EXPECT_FALSE(ee_cert.VerifySignature(ee_pubkey_from_cert));
}
