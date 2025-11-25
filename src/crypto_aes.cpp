/**
 * @file crypto_aes.cpp
 * @brief AES-128-CTR encryption implementation
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum/crypto.h"
#include "openssl_wrappers.h"
#include <openssl/evp.h>
#include <cstring>

namespace sum {
namespace crypto {

using namespace internal;

// ============================================================================
// AES-128-CTR Implementation
// ============================================================================

std::vector<uint8_t> AES128CTR::Encrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& plaintext
) {
    if (key.size() != AES_128_KEY_SIZE) {
        throw CryptoError("AES-128 key must be exactly 16 bytes");
    }
    if (iv.size() != AES_CTR_IV_SIZE) {
        throw CryptoError("IV must be exactly 12 bytes");
    }

    // Pad IV to 16 bytes (CTR mode uses 128-bit counter)
    std::vector<uint8_t> padded_iv(AES_CTR_PADDED_IV_SIZE, 0);
    std::memcpy(padded_iv.data(), iv.data(), AES_CTR_IV_SIZE);

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw CryptoError("Failed to create cipher context");
    }

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_ctr(), nullptr,
                           key.data(), padded_iv.data()) != 1) {
        throw CryptoError("Failed to initialize AES-128-CTR encryption");
    }

    std::vector<uint8_t> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_128_ctr()));
    int len = 0;

    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len,
                          plaintext.data(), plaintext.size()) != 1) {
        throw CryptoError("Failed to encrypt data");
    }

    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) != 1) {
        throw CryptoError("Failed to finalize encryption");
    }
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

std::vector<uint8_t> AES128CTR::Decrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& ciphertext
) {
    if (key.size() != AES_128_KEY_SIZE) {
        throw CryptoError("AES-128 key must be exactly 16 bytes");
    }
    if (iv.size() != AES_CTR_IV_SIZE) {
        throw CryptoError("IV must be exactly 12 bytes");
    }

    // Pad IV to 16 bytes (CTR mode uses 128-bit counter)
    std::vector<uint8_t> padded_iv(AES_CTR_PADDED_IV_SIZE, 0);
    std::memcpy(padded_iv.data(), iv.data(), AES_CTR_IV_SIZE);

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw CryptoError("Failed to create cipher context");
    }

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_ctr(), nullptr,
                           key.data(), padded_iv.data()) != 1) {
        throw CryptoError("Failed to initialize AES-128-CTR decryption");
    }

    std::vector<uint8_t> plaintext(ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_128_ctr()));
    int len = 0;

    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len,
                          ciphertext.data(), ciphertext.size()) != 1) {
        throw CryptoError("Failed to decrypt data");
    }

    int plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len) != 1) {
        throw CryptoError("Failed to finalize decryption");
    }
    plaintext_len += len;

    plaintext.resize(plaintext_len);
    return plaintext;
}

} // namespace crypto
} // namespace sum
