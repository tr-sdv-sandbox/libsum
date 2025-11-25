/**
 * @file crypto_aes.cpp
 * @brief AES-128-GCM encryption implementation
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
// AES-128-GCM Implementation
// ============================================================================

AES128GCMResult AES128GCM::Encrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& plaintext
) {
    if (key.size() != AES_128_KEY_SIZE) {
        throw CryptoError("AES-128 key must be exactly 16 bytes");
    }
    if (iv.size() != AES_GCM_IV_SIZE) {
        throw CryptoError("IV must be exactly 12 bytes for GCM");
    }

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw CryptoError("Failed to create cipher context");
    }

    // Initialize GCM encryption
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw CryptoError("Failed to initialize AES-128-GCM");
    }

    // Set IV length (12 bytes for GCM)
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, nullptr) != 1) {
        throw CryptoError("Failed to set GCM IV length");
    }

    // Set key and IV
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
        throw CryptoError("Failed to set key and IV");
    }

    // Encrypt plaintext
    std::vector<uint8_t> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_128_gcm()));
    int len = 0;

    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len,
                          plaintext.data(), plaintext.size()) != 1) {
        throw CryptoError("Failed to encrypt data");
    }

    int ciphertext_len = len;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) != 1) {
        throw CryptoError("Failed to finalize encryption");
    }
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);

    // Get authentication tag (16 bytes)
    std::vector<uint8_t> tag(AES_GCM_TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag.data()) != 1) {
        throw CryptoError("Failed to get GCM authentication tag");
    }

    return {ciphertext, tag};
}

} // namespace crypto
} // namespace sum
