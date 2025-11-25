/**
 * @file crypto_keys.cpp
 * @brief ECC key and certificate wrapper implementations (OpenSSL 3.x)
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum/common/crypto.h"
#include "sum/common/manifest.h"
#include "openssl_wrappers.h"
#include "x509_constants.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <fstream>
#include <sstream>
#include <cstring>

namespace sum {
namespace crypto {

using namespace internal;

// ============================================================================
// PrivateKey Implementation
// ============================================================================

class PrivateKey::Impl {
public:
    EVP_PKEY* pkey = nullptr;

    ~Impl() {
        if (pkey) {
            EVP_PKEY_free(pkey);
        }
    }
};

PrivateKey::PrivateKey() : impl_(std::make_unique<Impl>()) {}

PrivateKey::~PrivateKey() = default;

PrivateKey::PrivateKey(PrivateKey&&) noexcept = default;
PrivateKey& PrivateKey::operator=(PrivateKey&&) noexcept = default;

PrivateKey PrivateKey::LoadFromFile(const std::string& path) {
    FILE* fp = fopen(path.c_str(), "r");
    if (!fp) {
        throw CryptoError("Failed to open private key file: " + path);
    }

    PrivateKey key;
    key.impl_->pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!key.impl_->pkey) {
        throw CryptoError("Failed to parse private key from: " + path);
    }

    return key;
}

PrivateKey PrivateKey::LoadFromPEM(const std::string& pem) {
    BIO_ptr bio(BIO_new_mem_buf(pem.data(), pem.size()));
    if (!bio) {
        throw CryptoError("Failed to create BIO from PEM");
    }

    PrivateKey key;
    key.impl_->pkey = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);

    if (!key.impl_->pkey) {
        throw CryptoError("Failed to parse private key from PEM");
    }

    return key;
}

PrivateKey PrivateKey::Generate(KeyType type) {
    // SECURITY: Verify PRNG is properly seeded before generating keys
    if (RAND_status() != 1) {
        throw CryptoError("OpenSSL PRNG not properly seeded - insufficient entropy");
    }

    const char* key_name = (type == KeyType::Ed25519) ? "ED25519" : "X25519";

    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_from_name(nullptr, key_name, nullptr));
    if (!ctx) {
        throw CryptoError(std::string("Failed to create ") + key_name + " context");
    }

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        throw CryptoError(std::string("Failed to initialize ") + key_name + " keygen");
    }

    PrivateKey key;
    if (EVP_PKEY_keygen(ctx.get(), &key.impl_->pkey) <= 0) {
        throw CryptoError(std::string("Failed to generate ") + key_name + " key pair");
    }

    return key;
}

std::string PrivateKey::ToPEM() const {
    BIO_ptr bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        throw CryptoError("Failed to create BIO");
    }

    if (!PEM_write_bio_PrivateKey(bio.get(), impl_->pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        throw CryptoError("Failed to write private key to PEM");
    }

    char* data = nullptr;
    long len = BIO_get_mem_data(bio.get(), &data);
    return std::string(data, len);
}

void* PrivateKey::GetNativeHandle() const {
    return impl_->pkey;
}

// ============================================================================
// PublicKey Implementation
// ============================================================================

class PublicKey::Impl {
public:
    EVP_PKEY* pkey = nullptr;

    ~Impl() {
        if (pkey) {
            EVP_PKEY_free(pkey);
        }
    }
};

PublicKey::PublicKey() : impl_(std::make_unique<Impl>()) {}

PublicKey::~PublicKey() = default;

PublicKey::PublicKey(PublicKey&&) noexcept = default;
PublicKey& PublicKey::operator=(PublicKey&&) noexcept = default;

PublicKey PublicKey::LoadFromFile(const std::string& path) {
    FILE* fp = fopen(path.c_str(), "r");
    if (!fp) {
        throw CryptoError("Failed to open public key file: " + path);
    }

    PublicKey key;
    key.impl_->pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!key.impl_->pkey) {
        throw CryptoError("Failed to parse public key from: " + path);
    }

    return key;
}

PublicKey PublicKey::LoadFromPEM(const std::string& pem) {
    BIO_ptr bio(BIO_new_mem_buf(pem.data(), pem.size()));
    if (!bio) {
        throw CryptoError("Failed to create BIO from PEM");
    }

    PublicKey key;
    key.impl_->pkey = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);

    if (!key.impl_->pkey) {
        throw CryptoError("Failed to parse public key from PEM");
    }

    return key;
}

PublicKey PublicKey::FromPrivateKey(const PrivateKey& privkey) {
    EVP_PKEY* priv_pkey = static_cast<EVP_PKEY*>(privkey.GetNativeHandle());

    // Ed25519: Simple approach - export and re-import public key via BIO
    BIO_ptr bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        throw CryptoError("Failed to create BIO for public key");
    }

    // Write public key to BIO
    if (!PEM_write_bio_PUBKEY(bio.get(), priv_pkey)) {
        throw CryptoError("Failed to write Ed25519 public key");
    }

    // Read back public key
    PublicKey pubkey;
    pubkey.impl_->pkey = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    if (!pubkey.impl_->pkey) {
        throw CryptoError("Failed to read Ed25519 public key");
    }

    return pubkey;
}

std::string PublicKey::ToPEM() const {
    BIO_ptr bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        throw CryptoError("Failed to create BIO");
    }

    if (!PEM_write_bio_PUBKEY(bio.get(), impl_->pkey)) {
        throw CryptoError("Failed to write public key to PEM");
    }

    char* data = nullptr;
    long len = BIO_get_mem_data(bio.get(), &data);
    return std::string(data, len);
}

void* PublicKey::GetNativeHandle() const {
    return impl_->pkey;
}

// ============================================================================
// Certificate Implementation
// ============================================================================

class Certificate::Impl {
public:
    X509* cert = nullptr;

    ~Impl() {
        if (cert) {
            X509_free(cert);
        }
    }
};

Certificate::Certificate() : impl_(std::make_unique<Impl>()) {}

Certificate::~Certificate() = default;

Certificate::Certificate(Certificate&&) noexcept = default;
Certificate& Certificate::operator=(Certificate&&) noexcept = default;

Certificate Certificate::LoadFromFile(const std::string& path) {
    FILE* fp = fopen(path.c_str(), "r");
    if (!fp) {
        throw CryptoError("Failed to open certificate file: " + path);
    }

    Certificate cert;

    // Try PEM first
    cert.impl_->cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);

    if (!cert.impl_->cert) {
        // Try DER
        fseek(fp, 0, SEEK_SET);
        cert.impl_->cert = d2i_X509_fp(fp, nullptr);
    }

    fclose(fp);

    if (!cert.impl_->cert) {
        throw CryptoError("Failed to parse certificate from: " + path);
    }

    return cert;
}

std::vector<Certificate> Certificate::LoadChainFromFile(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        throw CryptoError("Failed to open certificate chain file: " + path);
    }

    std::string pem_data((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());

    return LoadChainFromPEM(pem_data);
}

std::vector<Certificate> Certificate::LoadChainFromPEM(const std::string& pem) {
    BIO_ptr bio(BIO_new_mem_buf(pem.data(), pem.size()));
    if (!bio) {
        throw CryptoError("Failed to create BIO from PEM data");
    }

    std::vector<Certificate> chain;

    // Read all certificates from the PEM data
    while (true) {
        X509* x509 = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
        if (!x509) {
            break;  // No more certificates
        }

        Certificate cert;
        cert.impl_->cert = x509;
        chain.push_back(std::move(cert));
    }

    if (chain.empty()) {
        throw CryptoError("No certificates found in PEM data");
    }

    return chain;
}

Certificate Certificate::LoadFromDER(const std::vector<uint8_t>& der) {
    const unsigned char* p = der.data();
    Certificate cert;
    cert.impl_->cert = d2i_X509(nullptr, &p, der.size());

    if (!cert.impl_->cert) {
        throw CryptoError("Failed to parse certificate from DER");
    }

    return cert;
}

std::vector<uint8_t> Certificate::ToDER() const {
    unsigned char* der = nullptr;
    int len = i2d_X509(impl_->cert, &der);

    if (len < 0) {
        throw CryptoError("Failed to encode certificate to DER");
    }

    std::vector<uint8_t> result(der, der + len);
    OPENSSL_free(der);

    return result;
}

std::string Certificate::ToPEM() const {
    BIO_ptr bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        throw CryptoError("Failed to create BIO");
    }

    if (!PEM_write_bio_X509(bio.get(), impl_->cert)) {
        throw CryptoError("Failed to write certificate to PEM");
    }

    char* data = nullptr;
    long len = BIO_get_mem_data(bio.get(), &data);
    return std::string(data, len);
}

std::string Certificate::CreateChainPEM(const std::vector<Certificate>& chain) {
    if (chain.empty()) {
        throw CryptoError("Cannot create PEM bundle from empty chain");
    }

    std::string pem_bundle;
    for (const auto& cert : chain) {
        pem_bundle += cert.ToPEM();
    }

    return pem_bundle;
}

PublicKey Certificate::GetPublicKey() const {
    EVP_PKEY_ptr pkey(X509_get_pubkey(impl_->cert));
    if (!pkey) {
        throw CryptoError("Failed to extract public key from certificate");
    }

    // Convert to PEM and back to create PublicKey object properly
    BIO_ptr bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        throw CryptoError("Failed to create BIO");
    }

    if (!PEM_write_bio_PUBKEY(bio.get(), pkey.get())) {
        throw CryptoError("Failed to write public key to PEM");
    }

    char* data = nullptr;
    long len = BIO_get_mem_data(bio.get(), &data);
    std::string pem(data, len);

    return PublicKey::LoadFromPEM(pem);
}

bool Certificate::VerifyChain(const Certificate& issuer, int64_t trusted_time) const {
    EVP_PKEY_ptr issuer_pubkey(X509_get_pubkey(issuer.impl_->cert));
    if (!issuer_pubkey) {
        return false;
    }

    int result = X509_verify(impl_->cert, issuer_pubkey.get());
    if (result != 1) {
        return false;
    }

    // Validate certificate time (REQUIRED)
    time_t check_time = static_cast<time_t>(trusted_time);

    // Get certificate validity period
    const ASN1_TIME* not_before = X509_get0_notBefore(impl_->cert);
    const ASN1_TIME* not_after = X509_get0_notAfter(impl_->cert);

    if (!not_before || !not_after) {
        return false;
    }

    // Check if trusted_time is within validity period
    // X509_cmp_time returns -1 if ASN1_TIME < time_t, 0 if equal, 1 if >
    // We want: not_before <= trusted_time <= not_after
    if (X509_cmp_time(not_before, &check_time) > 0) {
        // Certificate not yet valid
        return false;
    }

    if (X509_cmp_time(not_after, &check_time) < 0) {
        // Certificate expired
        return false;
    }

    return true;
}

bool Certificate::VerifyChainWithIntermediates(
    const std::vector<Certificate>& intermediates,
    const Certificate& root_ca,
    int64_t trusted_time
) const {
    // Build certificate chain: this cert → intermediates → root_ca
    // Verify each link in the chain

    // SECURITY: Enforce required certificate chain depth
    const size_t expected_intermediates = REQUIRED_CERT_CHAIN_DEPTH - 1;  // Chain depth - root = intermediates
    if (intermediates.size() != expected_intermediates) {
        throw CryptoError("Invalid certificate chain depth: expected " +
                         std::to_string(expected_intermediates) + " intermediate(s), got " +
                         std::to_string(intermediates.size()));
    }

    // SECURITY: Validate root CA is self-signed
    X509_NAME* root_subject = X509_get_subject_name(root_ca.impl_->cert);
    X509_NAME* root_issuer = X509_get_issuer_name(root_ca.impl_->cert);
    if (!root_subject || !root_issuer || X509_NAME_cmp(root_subject, root_issuer) != 0) {
        throw CryptoError("Chain validation failed: root CA is not self-signed");
    }

    // SECURITY: Verify root CA signature
    EVP_PKEY_ptr root_pubkey(X509_get_pubkey(root_ca.impl_->cert));
    if (!root_pubkey || X509_verify(root_ca.impl_->cert, root_pubkey.get()) != 1) {
        throw CryptoError("Chain validation failed: root CA signature is invalid");
    }

    // SECURITY: Validate intermediates are NOT self-signed
    for (const auto& intermediate : intermediates) {
        X509_NAME* int_subject = X509_get_subject_name(intermediate.impl_->cert);
        X509_NAME* int_issuer = X509_get_issuer_name(intermediate.impl_->cert);
        if (int_subject && int_issuer && X509_NAME_cmp(int_subject, int_issuer) == 0) {
            throw CryptoError("Chain validation failed: intermediate CA cannot be self-signed");
        }
    }

    // First, verify this certificate against the first intermediate (or root if no intermediates)
    const Certificate* current_issuer = intermediates.empty() ? &root_ca : &intermediates[0];

    if (!VerifyChain(*current_issuer, trusted_time)) {
        throw CryptoError("Chain verification failed: update certificate not signed by intermediate CA");
    }

    // SECURITY: Validate issuer/subject DN chain order
    X509_NAME* subject_issuer = X509_get_issuer_name(impl_->cert);
    X509_NAME* issuer_subject = X509_get_subject_name(current_issuer->impl_->cert);
    if (!subject_issuer || !issuer_subject || X509_NAME_cmp(subject_issuer, issuer_subject) != 0) {
        throw CryptoError("Chain validation failed: update certificate issuer DN does not match " +
                        std::string(intermediates.empty() ? "root CA" : "intermediate CA") + " subject DN");
    }

    // Verify each intermediate against the next one
    for (size_t i = 0; i < intermediates.size(); ++i) {
        const Certificate* next_issuer = (i + 1 < intermediates.size())
            ? &intermediates[i + 1]
            : &root_ca;

        if (!intermediates[i].VerifyChain(*next_issuer, trusted_time)) {
            throw CryptoError("Chain verification failed: intermediate CA " + std::to_string(i) +
                            " not signed by next CA in chain");
        }

        // SECURITY: Validate issuer/subject DN match
        X509_NAME* cert_issuer = X509_get_issuer_name(intermediates[i].impl_->cert);
        X509_NAME* next_subject = X509_get_subject_name(next_issuer->impl_->cert);
        if (!cert_issuer || !next_subject || X509_NAME_cmp(cert_issuer, next_subject) != 0) {
            throw CryptoError("Chain validation failed: intermediate CA " + std::to_string(i) +
                            " issuer DN does not match next CA subject DN");
        }
    }

    // All verifications passed
    return true;
}

std::vector<uint8_t> Certificate::GetVerifiedManifestWithChain(
    const std::vector<Certificate>& intermediates,
    const Certificate& root_ca,
    int64_t trusted_time
) const {
    // SECURITY: Verify entire certificate chain BEFORE extracting manifest
    if (!VerifyChainWithIntermediates(intermediates, root_ca, trusted_time)) {
        throw CryptoError("Chain verification failed: cannot extract manifest from untrusted certificate");
    }

    // Chain verified, extract manifest (without re-verifying)
    ASN1_OBJECT* obj = OBJ_txt2obj(internal::MANIFEST_EXTENSION_OID, 1);
    if (!obj) {
        throw CryptoError("Failed to create ASN1 object for manifest OID");
    }

    int ext_idx = X509_get_ext_by_OBJ(impl_->cert, obj, -1);
    ASN1_OBJECT_free(obj);

    if (ext_idx < 0) {
        throw CryptoError("No manifest extension found in certificate");
    }

    X509_EXTENSION* ext = X509_get_ext(impl_->cert, ext_idx);
    if (!ext) {
        throw CryptoError("Failed to extract manifest extension");
    }

    ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(ext);
    if (!data) {
        throw CryptoError("Failed to extract manifest data from extension");
    }

    // SECURITY: Reject manifests larger than 1MB to prevent DoS attacks
    constexpr size_t MAX_MANIFEST_SIZE = 1024 * 1024;  // 1MB
    size_t manifest_size = ASN1_STRING_length(data);
    if (manifest_size > MAX_MANIFEST_SIZE) {
        throw CryptoError("Manifest too large in certificate extension: " +
                         std::to_string(manifest_size) + " bytes (max " +
                         std::to_string(MAX_MANIFEST_SIZE) + " bytes)");
    }

    return std::vector<uint8_t>(
        ASN1_STRING_get0_data(data),
        ASN1_STRING_get0_data(data) + manifest_size
    );
}

void* Certificate::GetNativeHandle() const {
    return impl_->cert;
}

bool Certificate::HasManifestExtension() const {
    ASN1_OBJECT* obj = OBJ_txt2obj(internal::MANIFEST_EXTENSION_OID, 1);
    if (!obj) {
        return false;
    }

    int ext_idx = X509_get_ext_by_OBJ(impl_->cert, obj, -1);
    ASN1_OBJECT_free(obj);

    return ext_idx >= 0;
}

std::vector<uint8_t> Certificate::GetVerifiedManifest(const Certificate& ca_cert, int64_t trusted_time) const {
    // SECURITY: Verify certificate signature BEFORE extracting manifest
    // Provide detailed error messages about why verification failed

    // First check signature
    EVP_PKEY_ptr issuer_pubkey(X509_get_pubkey(ca_cert.impl_->cert));
    if (!issuer_pubkey) {
        throw CryptoError("Certificate verification failed: Cannot extract CA public key");
    }

    int result = X509_verify(impl_->cert, issuer_pubkey.get());
    if (result != 1) {
        throw CryptoError("Certificate verification failed: Invalid signature (certificate not signed by provided CA)");
    }

    // Check time validity (REQUIRED)
    time_t check_time = static_cast<time_t>(trusted_time);
    const ASN1_TIME* not_before = X509_get0_notBefore(impl_->cert);
    const ASN1_TIME* not_after = X509_get0_notAfter(impl_->cert);

    if (!not_before || !not_after) {
        throw CryptoError("Certificate verification failed: Invalid validity period");
    }

    if (X509_cmp_time(not_before, &check_time) > 0) {
        throw CryptoError("Certificate verification failed: Certificate not yet valid at trusted time");
    }

    if (X509_cmp_time(not_after, &check_time) < 0) {
        throw CryptoError("Certificate verification failed: Certificate expired at trusted time");
    }

    // Verification passed, extract manifest
    ASN1_OBJECT* obj = OBJ_txt2obj(internal::MANIFEST_EXTENSION_OID, 1);
    if (!obj) {
        throw CryptoError("Failed to create manifest OID");
    }

    int ext_idx = X509_get_ext_by_OBJ(impl_->cert, obj, -1);
    ASN1_OBJECT_free(obj);

    if (ext_idx < 0) {
        throw CryptoError("Certificate does not have manifest extension");
    }

    X509_EXTENSION* ext = X509_get_ext(impl_->cert, ext_idx);
    if (!ext) {
        throw CryptoError("Failed to get extension");
    }

    ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(ext);
    if (!data) {
        throw CryptoError("Failed to get extension data");
    }

    // SECURITY: Reject manifests larger than 1MB to prevent DoS attacks
    constexpr size_t MAX_MANIFEST_SIZE = 1024 * 1024;  // 1MB
    if (static_cast<size_t>(data->length) > MAX_MANIFEST_SIZE) {
        throw CryptoError("Manifest too large in certificate extension: " +
                         std::to_string(data->length) + " bytes (max " +
                         std::to_string(MAX_MANIFEST_SIZE) + " bytes)");
    }

    return std::vector<uint8_t>(data->data, data->data + data->length);
}

bool Certificate::HasDeviceMetadata() const {
    constexpr const char* DEVICE_METADATA_OID = "1.3.6.1.3.1";  // libsum device metadata

    ASN1_OBJECT* obj = OBJ_txt2obj(DEVICE_METADATA_OID, 1);
    if (!obj) {
        return false;
    }

    int ext_idx = X509_get_ext_by_OBJ(impl_->cert, obj, -1);
    ASN1_OBJECT_free(obj);

    return ext_idx >= 0;
}

DeviceMetadata Certificate::GetDeviceMetadata() const {
    constexpr const char* DEVICE_METADATA_OID = "1.3.6.1.3.1";  // libsum device metadata

    ASN1_OBJECT* obj = OBJ_txt2obj(DEVICE_METADATA_OID, 1);
    if (!obj) {
        throw CryptoError("Failed to create device metadata OID");
    }

    int ext_idx = X509_get_ext_by_OBJ(impl_->cert, obj, -1);
    ASN1_OBJECT_free(obj);

    if (ext_idx < 0) {
        throw CryptoError("Certificate does not have device metadata extension");
    }

    X509_EXTENSION* ext = X509_get_ext(impl_->cert, ext_idx);
    if (!ext) {
        throw CryptoError("Failed to get extension");
    }

    ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(ext);
    if (!data) {
        throw CryptoError("Failed to get extension data");
    }

    std::vector<uint8_t> proto_bytes(data->data, data->data + data->length);
    return DeviceMetadata::FromProtobuf(proto_bytes);
}

DeviceMetadata Certificate::GetVerifiedDeviceMetadata(const Certificate& ca_cert, int64_t trusted_time) const {
    // SECURITY: Verify certificate signature BEFORE extracting device metadata
    // Provide detailed error messages about why verification failed

    // First check signature
    EVP_PKEY_ptr issuer_pubkey(X509_get_pubkey(ca_cert.impl_->cert));
    if (!issuer_pubkey) {
        throw CryptoError("Certificate verification failed: Cannot extract CA public key");
    }

    int result = X509_verify(impl_->cert, issuer_pubkey.get());
    if (result != 1) {
        throw CryptoError("Certificate verification failed: Invalid signature (certificate not signed by provided CA)");
    }

    // Check time validity (REQUIRED)
    time_t check_time = static_cast<time_t>(trusted_time);
    const ASN1_TIME* not_before = X509_get0_notBefore(impl_->cert);
    const ASN1_TIME* not_after = X509_get0_notAfter(impl_->cert);

    if (!not_before || !not_after) {
        throw CryptoError("Certificate verification failed: Invalid validity period");
    }

    if (X509_cmp_time(not_before, &check_time) > 0) {
        throw CryptoError("Certificate verification failed: Certificate not yet valid at trusted time");
    }

    if (X509_cmp_time(not_after, &check_time) < 0) {
        throw CryptoError("Certificate verification failed: Certificate expired at trusted time");
    }

    // After verification passes, extract the metadata
    return GetDeviceMetadata();
}

int64_t Certificate::GetNotBefore() const {
    const ASN1_TIME* not_before = X509_get0_notBefore(impl_->cert);
    if (!not_before) {
        throw CryptoError("Failed to get certificate notBefore time");
    }

    // Convert ASN1_TIME to time_t
    struct tm tm_time = {};
    if (!ASN1_TIME_to_tm(not_before, &tm_time)) {
        throw CryptoError("Failed to convert ASN1_TIME to tm");
    }

    // Convert to Unix epoch (UTC)
    time_t epoch_time = timegm(&tm_time);
    return static_cast<int64_t>(epoch_time);
}

std::string Certificate::GetSubject() const {
    char* subject_str = X509_NAME_oneline(X509_get_subject_name(impl_->cert), nullptr, 0);
    if (!subject_str) {
        throw CryptoError("Failed to get certificate subject");
    }
    std::string result(subject_str);
    OPENSSL_free(subject_str);
    return result;
}

std::string Certificate::GetIssuer() const {
    char* issuer_str = X509_NAME_oneline(X509_get_issuer_name(impl_->cert), nullptr, 0);
    if (!issuer_str) {
        throw CryptoError("Failed to get certificate issuer");
    }
    std::string result(issuer_str);
    OPENSSL_free(issuer_str);
    return result;
}

std::pair<int64_t, int64_t> Certificate::GetValidityPeriod() const {
    const ASN1_TIME* not_before = X509_get0_notBefore(impl_->cert);
    const ASN1_TIME* not_after = X509_get0_notAfter(impl_->cert);

    if (!not_before || !not_after) {
        throw CryptoError("Failed to get certificate validity period");
    }

    // Convert notBefore
    struct tm tm_before = {};
    if (!ASN1_TIME_to_tm(not_before, &tm_before)) {
        throw CryptoError("Failed to convert notBefore");
    }
    int64_t epoch_before = static_cast<int64_t>(timegm(&tm_before));

    // Convert notAfter
    struct tm tm_after = {};
    if (!ASN1_TIME_to_tm(not_after, &tm_after)) {
        throw CryptoError("Failed to convert notAfter");
    }
    int64_t epoch_after = static_cast<int64_t>(timegm(&tm_after));

    return {epoch_before, epoch_after};
}

std::vector<uint8_t> Certificate::ExtractManifest() const {
    if (!HasManifestExtension()) {
        throw CryptoError("Certificate does not have manifest extension");
    }

    // Extract the manifest extension data (unverified)
    ASN1_OBJECT* obj = OBJ_txt2obj(internal::MANIFEST_EXTENSION_OID, 1);
    if (!obj) {
        throw CryptoError("Failed to create manifest OID");
    }

    int idx = X509_get_ext_by_OBJ(impl_->cert, obj, -1);
    ASN1_OBJECT_free(obj);

    if (idx < 0) {
        throw CryptoError("Failed to find manifest extension");
    }

    X509_EXTENSION* ext = X509_get_ext(impl_->cert, idx);
    if (!ext) {
        throw CryptoError("Failed to get manifest extension");
    }

    ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(ext);
    if (!data) {
        throw CryptoError("Failed to get manifest extension data");
    }

    return std::vector<uint8_t>(data->data, data->data + data->length);
}

bool Certificate::VerifySignature(const PublicKey& issuer_pubkey) const {
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(issuer_pubkey.GetNativeHandle());
    if (!pkey) {
        throw CryptoError("Invalid issuer public key");
    }

    int result = X509_verify(impl_->cert, pkey);
    return result == 1;
}

} // namespace crypto
} // namespace sum
