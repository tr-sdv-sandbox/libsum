/**
 * @file crypto_ed25519.cpp
 * @brief Ed25519 signing and verification implementation
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum/common/crypto.h"
#include "openssl_wrappers.h"
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace sum {
namespace crypto {

using namespace internal;

// ============================================================================
// Ed25519 Implementation
// ============================================================================

std::vector<uint8_t> Ed25519::Sign(
    const PrivateKey& private_key,
    const std::vector<uint8_t>& data
) {
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(private_key.GetNativeHandle());

    // Validate key type
    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
        throw CryptoError("Key is not an Ed25519 key");
    }

    // Create signature context
    EVP_MD_CTX_ptr md_ctx(EVP_MD_CTX_new());
    if (!md_ctx) {
        throw CryptoError("Failed to create signature context");
    }

    // Ed25519: Sign data directly (EdDSA handles its own hashing)
    if (EVP_DigestSignInit(md_ctx.get(), nullptr, nullptr, nullptr, pkey) != 1) {
        throw CryptoError("Failed to initialize Ed25519 signing");
    }

    // Get signature length
    size_t sig_len = 0;
    if (EVP_DigestSign(md_ctx.get(), nullptr, &sig_len, data.data(), data.size()) != 1) {
        throw CryptoError("Failed to get Ed25519 signature length");
    }

    // Create signature
    std::vector<uint8_t> signature(sig_len);
    if (EVP_DigestSign(md_ctx.get(), signature.data(), &sig_len, data.data(), data.size()) != 1) {
        throw CryptoError("Failed to create Ed25519 signature");
    }

    signature.resize(sig_len);
    return signature;
}

bool Ed25519::Verify(
    const PublicKey& public_key,
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& signature
) {
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(public_key.GetNativeHandle());

    // Validate key type
    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
        throw CryptoError("Key is not an Ed25519 public key");
    }

    // Validate signature size
    if (signature.size() != ED25519_SIGNATURE_SIZE) {
        throw CryptoError("Invalid Ed25519 signature size (expected 64 bytes)");
    }

    // Create verification context
    EVP_MD_CTX_ptr md_ctx(EVP_MD_CTX_new());
    if (!md_ctx) {
        throw CryptoError("Failed to create verification context");
    }

    // Initialize verification
    if (EVP_DigestVerifyInit(md_ctx.get(), nullptr, nullptr, nullptr, pkey) != 1) {
        throw CryptoError("Failed to initialize verification");
    }

    // Ed25519: Verify data directly (EdDSA handles its own hashing)
    int result = EVP_DigestVerify(md_ctx.get(), signature.data(), signature.size(), data.data(), data.size());

    if (result == 1) {
        return true;
    } else if (result == 0) {
        throw SignatureVerificationError();
    } else {
        throw CryptoError("Signature verification error");
    }
}

// ============================================================================
// SHA256 Implementation
// ============================================================================

std::vector<uint8_t> SHA256::Hash(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    ::SHA256(data.data(), data.size(), hash.data());
    return hash;
}

} // namespace crypto
} // namespace sum
