/**
 * @file crypto_aes_streaming.cpp
 * @brief AES-128-GCM streaming decryption implementation
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum/common/crypto.h"
#include "openssl_wrappers.h"
#include <openssl/evp.h>
#include <cstring>

namespace sum {
namespace crypto {

using namespace internal;

// ============================================================================
// AES-128-GCM Streaming Decryptor Implementation
// ============================================================================

class AES128GCM::Decryptor::Impl {
public:
    EVP_CIPHER_CTX_ptr ctx;
    std::vector<uint8_t> tag;
    bool finalized = false;

    Impl(const SecureVector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& tag_param)
        : tag(tag_param) {
        if (key.size() != AES_128_KEY_SIZE) {
            throw CryptoError("AES-128 key must be exactly 16 bytes");
        }
        if (iv.size() != AES_GCM_IV_SIZE) {
            throw CryptoError("IV must be exactly 12 bytes for GCM");
        }
        if (tag.size() != AES_GCM_TAG_SIZE) {
            throw CryptoError("GCM tag must be exactly 16 bytes");
        }

        ctx = EVP_CIPHER_CTX_ptr(EVP_CIPHER_CTX_new());
        if (!ctx) {
            throw CryptoError("Failed to create cipher context");
        }

        // Initialize GCM decryption
        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1) {
            throw CryptoError("Failed to initialize AES-128-GCM decryption");
        }

        // Set IV length
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, nullptr) != 1) {
            throw CryptoError("Failed to set GCM IV length");
        }

        // Set key and IV
        if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
            throw CryptoError("Failed to set key and IV for GCM decryption");
        }
    }
};

AES128GCM::Decryptor::Decryptor(
    const SecureVector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& tag
) : impl_(std::make_unique<Impl>(key, iv, tag)) {}

AES128GCM::Decryptor::~Decryptor() = default;

AES128GCM::Decryptor::Decryptor(Decryptor&&) noexcept = default;
AES128GCM::Decryptor& AES128GCM::Decryptor::operator=(Decryptor&&) noexcept = default;

std::vector<uint8_t> AES128GCM::Decryptor::Update(const std::vector<uint8_t>& ciphertext_chunk) {
    if (impl_->finalized) {
        throw CryptoError("Decryptor already finalized");
    }

    if (ciphertext_chunk.empty()) {
        return {};
    }

    std::vector<uint8_t> plaintext(ciphertext_chunk.size() + EVP_CIPHER_block_size(EVP_aes_128_gcm()));
    int len = 0;

    if (EVP_DecryptUpdate(impl_->ctx.get(), plaintext.data(), &len,
                          ciphertext_chunk.data(), ciphertext_chunk.size()) != 1) {
        throw CryptoError("Failed to decrypt chunk");
    }

    plaintext.resize(len);
    return plaintext;
}

std::vector<uint8_t> AES128GCM::Decryptor::Finalize() {
    if (impl_->finalized) {
        throw CryptoError("Decryptor already finalized");
    }

    // Set expected authentication tag
    if (EVP_CIPHER_CTX_ctrl(impl_->ctx.get(), EVP_CTRL_GCM_SET_TAG,
                            AES_GCM_TAG_SIZE, impl_->tag.data()) != 1) {
        throw CryptoError("Failed to set expected GCM tag");
    }

    std::vector<uint8_t> final_plaintext(EVP_CIPHER_block_size(EVP_aes_128_gcm()));
    int len = 0;

    // This verifies the tag and finalizes decryption
    int ret = EVP_DecryptFinal_ex(impl_->ctx.get(), final_plaintext.data(), &len);
    impl_->finalized = true;

    if (ret != 1) {
        throw CryptoError("GCM tag verification failed - data has been tampered with!");
    }

    final_plaintext.resize(len);
    return final_plaintext;
}

} // namespace crypto
} // namespace sum
