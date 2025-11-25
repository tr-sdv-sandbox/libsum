/**
 * @file x509_extension.cpp
 * @brief X.509 certificate extension handling
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum/common/manifest.h"
#include "sum/common/crypto.h"
#include "x509_constants.h"
#include "manifest.pb.h"
#include <openssl/x509v3.h>
#include <openssl/asn1.h>

namespace sum {

using namespace crypto::internal;  // For OID constants

// ============================================================================
// libsum OID Assignments (Experimental Arc)
// ============================================================================
//
// For production deployments, you should:
// 1. Register for a Private Enterprise Number (PEN) at:
//    https://www.iana.org/assignments/enterprise-numbers/
// 2. Replace these OIDs with your assigned arc: 1.3.6.1.4.1.{YOUR_PEN}.x
//
// Current assignments use experimental arc (1.3.6.1.3.x):
// - 1.3.6.1.3.1 - Device metadata extension
// - 1.3.6.1.3.2 - Secure update manifest extension
//
// See x509_constants.h for OID definitions

crypto::Certificate CreateCertificateWithManifest(
    const Manifest& manifest,
    const crypto::PrivateKey& signing_key,
    const crypto::PublicKey& subject_pubkey,
    const DeviceMetadata& device_metadata,
    const std::string& subject_name,
    int validity_days,
    const crypto::Certificate* issuer_cert
) {
    // Validate required fields
    if (device_metadata.hardware_id.empty()) {
        throw crypto::CryptoError("DeviceMetadata.hardware_id is required");
    }
    if (device_metadata.manufacturer.empty()) {
        throw crypto::CryptoError("DeviceMetadata.manufacturer is required (use 'CHANGEME' if testing)");
    }
    if (device_metadata.device_type.empty()) {
        throw crypto::CryptoError("DeviceMetadata.device_type is required (use 'CHANGEME' if testing)");
    }

    X509* cert = X509_new();
    if (!cert) {
        throw crypto::CryptoError("Failed to create X509 structure");
    }

    // Set version (X509 v3)
    X509_set_version(cert, 2);

    // Set serial number
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), validity_days * 24 * 3600);

    // Set subject name
    X509_NAME* subject = X509_NAME_new();
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                               (const unsigned char*)subject_name.c_str(), -1, -1, 0);
    X509_set_subject_name(cert, subject);

    // Set issuer name
    if (issuer_cert != nullptr) {
        // Certificate signed by issuer - use issuer's subject as our issuer
        // This is internal access, need to get the underlying X509*
        X509* issuer_x509 = static_cast<X509*>(
            const_cast<crypto::Certificate*>(issuer_cert)->GetNativeHandle()
        );
        X509_NAME* issuer_subject = X509_get_subject_name(issuer_x509);
        X509_set_issuer_name(cert, issuer_subject);
    } else {
        // Self-signed certificate - issuer = subject
        X509_set_issuer_name(cert, subject);
    }

    X509_NAME_free(subject);

    // Set public key
    EVP_PKEY* pub_pkey = static_cast<EVP_PKEY*>(
        const_cast<crypto::PublicKey&>(subject_pubkey).GetNativeHandle()
    );
    X509_set_pubkey(cert, pub_pkey);

    // Add standard X.509 v3 extensions
    // keyUsage: digitalSignature (for signing update manifests)
    X509_EXTENSION* key_usage = X509V3_EXT_conf_nid(
        nullptr, nullptr, NID_key_usage, "critical,digitalSignature"
    );
    if (!key_usage) {
        X509_free(cert);
        throw crypto::CryptoError("Failed to create keyUsage extension");
    }
    X509_add_ext(cert, key_usage, -1);
    X509_EXTENSION_free(key_usage);

    // extendedKeyUsage: codeSigning (for software update signing)
    X509_EXTENSION* ext_key_usage = X509V3_EXT_conf_nid(
        nullptr, nullptr, NID_ext_key_usage, "critical,codeSigning"
    );
    if (!ext_key_usage) {
        X509_free(cert);
        throw crypto::CryptoError("Failed to create extendedKeyUsage extension");
    }
    X509_add_ext(cert, ext_key_usage, -1);
    X509_EXTENSION_free(ext_key_usage);

    // Embed device metadata as custom extension (protobuf binary)
    std::vector<uint8_t> device_protobuf;
    try {
        device_protobuf = device_metadata.ToProtobuf();
    } catch (const std::exception& e) {
        X509_free(cert);
        throw crypto::CryptoError(std::string("Failed to serialize device metadata: ") + e.what());
    }

    ASN1_OCTET_STRING* device_data = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(device_data, device_protobuf.data(), device_protobuf.size());

    X509_EXTENSION* device_ext = X509_EXTENSION_create_by_OBJ(
        nullptr,
        OBJ_txt2obj(DEVICE_METADATA_OID, 1),
        1,  // critical - clients must understand device metadata
        device_data
    );

    ASN1_OCTET_STRING_free(device_data);

    if (!device_ext) {
        X509_free(cert);
        throw crypto::CryptoError("Failed to create device metadata extension");
    }

    X509_add_ext(cert, device_ext, -1);
    X509_EXTENSION_free(device_ext);

    // Embed manifest as custom extension (protobuf binary)
    auto manifest_protobuf = manifest.ToProtobuf();

    ASN1_OCTET_STRING* manifest_data = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(manifest_data, manifest_protobuf.data(), manifest_protobuf.size());

    X509_EXTENSION* ext = X509_EXTENSION_create_by_OBJ(
        nullptr,
        OBJ_txt2obj(MANIFEST_EXTENSION_OID, 1),
        1,  // critical - clients must understand manifest
        manifest_data
    );

    ASN1_OCTET_STRING_free(manifest_data);

    if (!ext) {
        X509_free(cert);
        throw crypto::CryptoError("Failed to create manifest extension");
    }

    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    // Sign the certificate
    EVP_PKEY* priv_pkey = static_cast<EVP_PKEY*>(
        const_cast<crypto::PrivateKey&>(signing_key).GetNativeHandle()
    );

    // Ed25519 uses its own internal hashing, so pass nullptr for the digest
    // For ECDSA (P-256/P-384), we would use EVP_sha256()
    if (!X509_sign(cert, priv_pkey, nullptr)) {
        X509_free(cert);
        throw crypto::CryptoError("Failed to sign certificate");
    }

    // Convert to DER and create Certificate object
    unsigned char* der = nullptr;
    int len = i2d_X509(cert, &der);
    X509_free(cert);

    if (len < 0) {
        throw crypto::CryptoError("Failed to encode certificate");
    }

    std::vector<uint8_t> der_vec(der, der + len);
    OPENSSL_free(der);

    return crypto::Certificate::LoadFromDER(der_vec);
}

} // namespace sum
