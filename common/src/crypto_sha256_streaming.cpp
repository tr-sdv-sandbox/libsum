/**
 * @file crypto_sha256_streaming.cpp
 * @brief SHA-256 streaming hash implementation
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum/common/crypto.h"
#include "openssl_wrappers.h"
#include <openssl/evp.h>

namespace sum {
namespace crypto {

using namespace internal;

// ============================================================================
// SHA-256 Streaming Hasher Implementation
// ============================================================================

class SHA256::Hasher::Impl {
public:
    EVP_MD_CTX_ptr ctx;
    bool finalized = false;

    Impl() {
        ctx = EVP_MD_CTX_ptr(EVP_MD_CTX_new());
        if (!ctx) {
            throw CryptoError("Failed to create hash context");
        }

        if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
            throw CryptoError("Failed to initialize SHA-256 hash");
        }
    }
};

SHA256::Hasher::Hasher()
    : impl_(std::make_unique<Impl>()) {}

SHA256::Hasher::~Hasher() = default;

SHA256::Hasher::Hasher(Hasher&&) noexcept = default;
SHA256::Hasher& SHA256::Hasher::operator=(Hasher&&) noexcept = default;

void SHA256::Hasher::Update(const std::vector<uint8_t>& chunk) {
    if (impl_->finalized) {
        throw CryptoError("Hasher already finalized");
    }

    if (chunk.empty()) {
        return;
    }

    if (EVP_DigestUpdate(impl_->ctx.get(), chunk.data(), chunk.size()) != 1) {
        throw CryptoError("Failed to update hash");
    }
}

std::vector<uint8_t> SHA256::Hasher::Finalize() {
    if (impl_->finalized) {
        throw CryptoError("Hasher already finalized");
    }

    std::vector<uint8_t> hash(SHA256_HASH_SIZE);
    unsigned int hash_len = 0;

    if (EVP_DigestFinal_ex(impl_->ctx.get(), hash.data(), &hash_len) != 1) {
        throw CryptoError("Failed to finalize hash");
    }

    if (hash_len != SHA256_HASH_SIZE) {
        throw CryptoError("Unexpected hash size");
    }

    impl_->finalized = true;
    return hash;
}

} // namespace crypto
} // namespace sum
