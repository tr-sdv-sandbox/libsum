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
#include <glog/logging.h>
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
    X509* intermediate = nullptr;  // Single intermediate certificate (opinionated: exactly 1)

    ~Impl() {
        if (cert) {
            X509_free(cert);
        }
        if (intermediate) {
            X509_free(intermediate);
        }
    }
};

Certificate::Certificate() : impl_(std::make_unique<Impl>()) {}

Certificate::~Certificate() = default;

Certificate::Certificate(Certificate&&) noexcept = default;
Certificate& Certificate::operator=(Certificate&&) noexcept = default;

namespace {
    // Helper: Load raw X509 certificates from PEM string
    std::vector<X509*> LoadX509ChainFromPEM(const std::string& pem) {
        BIO_ptr bio(BIO_new_mem_buf(pem.data(), pem.size()));
        if (!bio) {
            throw CryptoError("Failed to create BIO from PEM data");
        }

        std::vector<X509*> chain;

        // Read all certificates from the PEM data
        while (true) {
            X509* x509 = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
            if (!x509) {
                break;  // No more certificates
            }
            chain.push_back(x509);
        }

        if (chain.empty()) {
            throw CryptoError("No certificates found in PEM data");
        }

        return chain;
    }

    // Helper: Load raw X509 certificates from file
    std::vector<X509*> LoadX509ChainFromFile(const std::string& path) {
        std::ifstream file(path);
        if (!file) {
            throw CryptoError("Failed to open certificate file: " + path);
        }

        std::string pem_data((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());

        return LoadX509ChainFromPEM(pem_data);
    }
}

Certificate Certificate::LoadFromFile(const std::string& path) {
    // Load as PEM file (may contain 1 or more certificates)
    std::vector<X509*> x509_chain = LoadX509ChainFromFile(path);

    if (x509_chain.empty()) {
        throw CryptoError("No certificates found in: " + path);
    }

    // First certificate is the primary certificate (CA or update cert)
    Certificate cert;
    cert.impl_->cert = x509_chain[0];

    // Second certificate (if present) is the intermediate
    // For CA certificates: no intermediate (size == 1)
    // For update certificates: exactly 1 intermediate (size == 2)
    if (x509_chain.size() == 2) {
        cert.impl_->intermediate = x509_chain[1];
    } else if (x509_chain.size() > 2) {
        // Clean up extra certificates
        for (size_t i = 1; i < x509_chain.size(); i++) {
            X509_free(x509_chain[i]);
        }
        throw CryptoError("Invalid certificate bundle: found " + std::to_string(x509_chain.size()) +
                         " certificates (opinionated: expect 1 for CA or 2 for update cert + intermediate) in: " + path);
    }

    return cert;
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
    const Certificate& intermediate,
    const Certificate& root_ca,
    int64_t trusted_time
) const {
    // Build certificate chain: this cert → intermediate → root_ca
    // Verify each link in the chain (opinionated: exactly 1 intermediate)

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

    // SECURITY: Validate intermediate is NOT self-signed
    X509_NAME* int_subject = X509_get_subject_name(intermediate.impl_->cert);
    X509_NAME* int_issuer = X509_get_issuer_name(intermediate.impl_->cert);
    if (int_subject && int_issuer && X509_NAME_cmp(int_subject, int_issuer) == 0) {
        throw CryptoError("Chain validation failed: intermediate CA cannot be self-signed");
    }

    // First, verify this certificate against the intermediate
    if (!VerifyChain(intermediate, trusted_time)) {
        throw CryptoError("Chain verification failed: update certificate not signed by intermediate CA");
    }

    // SECURITY: Validate issuer/subject DN chain order (update cert → intermediate)
    X509_NAME* subject_issuer = X509_get_issuer_name(impl_->cert);
    X509_NAME* issuer_subject = X509_get_subject_name(intermediate.impl_->cert);
    if (!subject_issuer || !issuer_subject || X509_NAME_cmp(subject_issuer, issuer_subject) != 0) {
        throw CryptoError("Chain validation failed: update certificate issuer DN does not match intermediate CA subject DN");
    }

    // Verify intermediate against root CA
    if (!intermediate.VerifyChain(root_ca, trusted_time)) {
        throw CryptoError("Chain verification failed: intermediate CA not signed by root CA");
    }

    // SECURITY: Validate issuer/subject DN match (intermediate → root)
    X509_NAME* int_issuer_dn = X509_get_issuer_name(intermediate.impl_->cert);
    X509_NAME* root_subject_dn = X509_get_subject_name(root_ca.impl_->cert);
    if (!int_issuer_dn || !root_subject_dn || X509_NAME_cmp(int_issuer_dn, root_subject_dn) != 0) {
        throw CryptoError("Chain validation failed: intermediate CA issuer DN does not match root CA subject DN");
    }

    // All verifications passed
    return true;
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

std::vector<uint8_t> Certificate::GetVerifiedManifest(const Certificate& root_ca, int64_t trusted_time) const {
    // SECURITY: Verify entire certificate chain BEFORE extracting manifest
    // Chain: this cert → internal intermediate → root CA

    // Wrap internal X509* intermediate in Certificate object for verification
    if (!impl_->intermediate) {
        throw CryptoError("No intermediate certificate embedded (opinionated: exactly 1 required)");
    }

    Certificate intermediate_cert;
    intermediate_cert.impl_->cert = X509_dup(impl_->intermediate);
    if (!intermediate_cert.impl_->cert) {
        throw CryptoError("Failed to duplicate intermediate certificate for verification");
    }

    // Verify the full certificate chain (includes signature + time validity checking)
    if (!VerifyChainWithIntermediates(intermediate_cert, root_ca, trusted_time)) {
        throw CryptoError("Chain verification failed: cannot extract manifest from untrusted certificate");
    }

    // Chain verified, extract manifest
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

void Certificate::AddIntermediate(const Certificate& intermediate_cert) {
    if (impl_->intermediate) {
        throw CryptoError("Intermediate certificate already set (opinionated: exactly 1 intermediate)");
    }

    // Duplicate the X509 certificate and store as single intermediate
    impl_->intermediate = X509_dup(static_cast<X509*>(intermediate_cert.impl_->cert));
    if (!impl_->intermediate) {
        throw CryptoError("Failed to duplicate intermediate certificate");
    }
}

DeviceMetadata Certificate::GetDeviceMetadata(const Certificate& root_ca, int64_t trusted_time) const {
    // SECURITY: Verify entire certificate chain BEFORE extracting device metadata
    // Chain: this cert → internal intermediate → root CA
    // This includes signature verification AND time validity checking for all certs in chain

    // Wrap internal X509* intermediate in Certificate object for verification
    if (!impl_->intermediate) {
        throw CryptoError("No intermediate certificate embedded (opinionated: exactly 1 required)");
    }

    Certificate intermediate_cert;
    intermediate_cert.impl_->cert = X509_dup(impl_->intermediate);
    if (!intermediate_cert.impl_->cert) {
        throw CryptoError("Failed to duplicate intermediate certificate for verification");
    }

    // Verify the full certificate chain (includes time validity checks via VerifyChain)
    if (!VerifyChainWithIntermediates(intermediate_cert, root_ca, trusted_time)) {
        throw CryptoError("Chain verification failed: cannot extract device metadata from untrusted certificate");
    }

    // Chain verified (signatures + time validity), extract the metadata
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
        throw CryptoError("Failed to get device metadata extension");
    }

    ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(ext);
    if (!data) {
        throw CryptoError("Failed to get device metadata extension data");
    }

    std::vector<uint8_t> proto_bytes(data->data, data->data + data->length);
    return DeviceMetadata::FromProtobuf(proto_bytes);
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

int64_t Certificate::GetIntermediateIssuanceTime() const {
    if (!impl_->intermediate) {
        throw CryptoError("No intermediate certificate embedded in this certificate");
    }

    const ASN1_TIME* not_before = X509_get0_notBefore(impl_->intermediate);
    if (!not_before) {
        throw CryptoError("Failed to get intermediate certificate notBefore time");
    }

    // Convert ASN1_TIME to time_t
    struct tm tm_time = {};
    if (!ASN1_TIME_to_tm(not_before, &tm_time)) {
        throw CryptoError("Failed to convert intermediate ASN1_TIME to tm");
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
