/**
 * @file crypto_x25519.cpp
 * @brief X25519 key wrapping implementation
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum/common/crypto.h"
#include "openssl_wrappers.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <cstring>

namespace sum {
namespace crypto {

using namespace internal;

// Key wrapping format: [ephemeral_pubkey(32) || nonce(12) || encrypted_key(16) || tag(16)]
constexpr size_t WRAPPED_KEY_SIZE = X25519_KEY_SIZE + CHACHA20_POLY1305_NONCE_SIZE + AES_128_KEY_SIZE + CHACHA20_POLY1305_TAG_SIZE;

// ============================================================================
// X25519 Key Wrapping Implementation
// ============================================================================

std::vector<uint8_t> X25519::WrapKey(
    const std::vector<uint8_t>& aes_key,
    const PublicKey& recipient_pubkey
) {
    // Validate AES key size
    if (aes_key.size() != AES_128_KEY_SIZE) {
        throw CryptoError("AES key must be exactly 16 bytes");
    }

    // Validate recipient key type
    EVP_PKEY* recipient_pkey = static_cast<EVP_PKEY*>(recipient_pubkey.GetNativeHandle());
    if (EVP_PKEY_id(recipient_pkey) != EVP_PKEY_X25519) {
        throw CryptoError("Recipient key is not an X25519 public key");
    }

    // SECURITY: Verify PRNG is properly seeded before generating ephemeral keys
    if (RAND_status() != 1) {
        throw CryptoError("OpenSSL PRNG not properly seeded - insufficient entropy");
    }

    // Generate ephemeral X25519 key pair
    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "X25519", nullptr));
    if (!ctx) {
        throw CryptoError("Failed to create X25519 context");
    }

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        throw CryptoError("Failed to initialize X25519 keygen");
    }

    EVP_PKEY* ephemeral_pkey_raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &ephemeral_pkey_raw) <= 0) {
        throw CryptoError("Failed to generate ephemeral X25519 key");
    }
    EVP_PKEY_ptr ephemeral_pkey(ephemeral_pkey_raw);

    // Get ephemeral public key bytes
    size_t ephemeral_pubkey_len = 0;
    if (!EVP_PKEY_get_raw_public_key(ephemeral_pkey.get(), nullptr, &ephemeral_pubkey_len)) {
        throw CryptoError("Failed to get ephemeral public key length");
    }
    if (ephemeral_pubkey_len != X25519_KEY_SIZE) {
        throw CryptoError("Unexpected X25519 public key size");
    }

    std::vector<uint8_t> ephemeral_pubkey_bytes(X25519_KEY_SIZE);
    if (!EVP_PKEY_get_raw_public_key(ephemeral_pkey.get(), ephemeral_pubkey_bytes.data(), &ephemeral_pubkey_len)) {
        throw CryptoError("Failed to get ephemeral public key");
    }

    // Perform X25519 key agreement with recipient's public key
    EVP_PKEY_CTX_ptr derive_ctx(EVP_PKEY_CTX_new(ephemeral_pkey.get(), nullptr));
    if (!derive_ctx) {
        throw CryptoError("Failed to create derive context");
    }

    if (EVP_PKEY_derive_init(derive_ctx.get()) <= 0) {
        throw CryptoError("Failed to initialize key derivation");
    }

    if (EVP_PKEY_derive_set_peer(derive_ctx.get(), recipient_pkey) <= 0) {
        throw CryptoError("Failed to set peer key");
    }

    // Get shared secret
    size_t shared_secret_len = 0;
    if (EVP_PKEY_derive(derive_ctx.get(), nullptr, &shared_secret_len) <= 0) {
        throw CryptoError("Failed to get shared secret length");
    }

    std::vector<uint8_t> shared_secret(shared_secret_len);
    if (EVP_PKEY_derive(derive_ctx.get(), shared_secret.data(), &shared_secret_len) <= 0) {
        throw CryptoError("Failed to derive shared secret");
    }

    // Derive encryption key from shared secret using HKDF-SHA256
    std::vector<uint8_t> wrapping_key(CHACHA20_POLY1305_KEY_SIZE);

    EVP_PKEY_CTX_ptr kdf_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    if (!kdf_ctx) {
        throw CryptoError("Failed to create HKDF context");
    }

    if (EVP_PKEY_derive_init(kdf_ctx.get()) <= 0) {
        throw CryptoError("Failed to initialize HKDF");
    }

    if (EVP_PKEY_CTX_set_hkdf_md(kdf_ctx.get(), EVP_sha256()) <= 0) {
        throw CryptoError("Failed to set HKDF hash");
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(kdf_ctx.get(), shared_secret.data(), shared_secret.size()) <= 0) {
        throw CryptoError("Failed to set HKDF key");
    }

    const char* info = "libsum-x25519-aes-wrap";
    if (EVP_PKEY_CTX_add1_hkdf_info(kdf_ctx.get(), (const unsigned char*)info, strlen(info)) <= 0) {
        throw CryptoError("Failed to set HKDF info");
    }

    size_t wrapping_key_len = wrapping_key.size();
    if (EVP_PKEY_derive(kdf_ctx.get(), wrapping_key.data(), &wrapping_key_len) <= 0) {
        throw CryptoError("Failed to derive wrapping key");
    }

    // SECURITY: Verify PRNG is properly seeded before generating nonce
    if (RAND_status() != 1) {
        throw CryptoError("OpenSSL PRNG not properly seeded - insufficient entropy");
    }

    // Generate random nonce
    std::vector<uint8_t> nonce(CHACHA20_POLY1305_NONCE_SIZE);
    if (RAND_bytes(nonce.data(), CHACHA20_POLY1305_NONCE_SIZE) != 1) {
        throw CryptoError("Failed to generate random nonce");
    }

    // Encrypt AES key with ChaCha20-Poly1305
    EVP_CIPHER_CTX_ptr cipher_ctx(EVP_CIPHER_CTX_new());
    if (!cipher_ctx) {
        throw CryptoError("Failed to create cipher context");
    }

    if (EVP_EncryptInit_ex(cipher_ctx.get(), EVP_chacha20_poly1305(), nullptr,
                           wrapping_key.data(), nonce.data()) != 1) {
        throw CryptoError("Failed to initialize ChaCha20-Poly1305 encryption");
    }

    std::vector<uint8_t> encrypted_key(AES_128_KEY_SIZE + CHACHA20_POLY1305_TAG_SIZE);
    int len = 0;

    if (EVP_EncryptUpdate(cipher_ctx.get(), encrypted_key.data(), &len,
                          aes_key.data(), aes_key.size()) != 1) {
        throw CryptoError("Failed to encrypt AES key");
    }

    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(cipher_ctx.get(), encrypted_key.data() + len, &len) != 1) {
        throw CryptoError("Failed to finalize encryption");
    }
    ciphertext_len += len;

    // Get authentication tag
    if (EVP_CIPHER_CTX_ctrl(cipher_ctx.get(), EVP_CTRL_AEAD_GET_TAG, CHACHA20_POLY1305_TAG_SIZE,
                            encrypted_key.data() + AES_128_KEY_SIZE) != 1) {
        throw CryptoError("Failed to get authentication tag");
    }

    // Assemble wrapped key: ephemeral_pubkey || nonce || encrypted_key || tag
    std::vector<uint8_t> wrapped_key;
    wrapped_key.reserve(WRAPPED_KEY_SIZE);
    wrapped_key.insert(wrapped_key.end(), ephemeral_pubkey_bytes.begin(), ephemeral_pubkey_bytes.end());
    wrapped_key.insert(wrapped_key.end(), nonce.begin(), nonce.end());
    wrapped_key.insert(wrapped_key.end(), encrypted_key.begin(), encrypted_key.end());

    return wrapped_key;
}

SecureVector<uint8_t> X25519::UnwrapKey(
    const std::vector<uint8_t>& wrapped_key,
    const PrivateKey& recipient_privkey
) {
    // Validate wrapped key size
    if (wrapped_key.size() != WRAPPED_KEY_SIZE) {
        throw CryptoError("Invalid wrapped key size");
    }

    // Validate recipient key type
    EVP_PKEY* recipient_pkey = static_cast<EVP_PKEY*>(recipient_privkey.GetNativeHandle());
    if (EVP_PKEY_id(recipient_pkey) != EVP_PKEY_X25519) {
        throw CryptoError("Recipient key is not an X25519 private key");
    }

    // Parse wrapped key components
    size_t offset = 0;

    std::vector<uint8_t> ephemeral_pubkey_bytes(wrapped_key.begin(),
                                                  wrapped_key.begin() + X25519_KEY_SIZE);
    offset += X25519_KEY_SIZE;

    std::vector<uint8_t> nonce(wrapped_key.begin() + offset,
                                wrapped_key.begin() + offset + CHACHA20_POLY1305_NONCE_SIZE);
    offset += CHACHA20_POLY1305_NONCE_SIZE;

    std::vector<uint8_t> encrypted_key(wrapped_key.begin() + offset,
                                        wrapped_key.end());

    // Reconstruct ephemeral public key
    EVP_PKEY_ptr ephemeral_pubkey(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                                                ephemeral_pubkey_bytes.data(),
                                                                ephemeral_pubkey_bytes.size()));
    if (!ephemeral_pubkey) {
        throw CryptoError("Failed to create ephemeral public key");
    }

    // Perform X25519 key agreement
    EVP_PKEY_CTX_ptr derive_ctx(EVP_PKEY_CTX_new(recipient_pkey, nullptr));
    if (!derive_ctx) {
        throw CryptoError("Failed to create derive context");
    }

    if (EVP_PKEY_derive_init(derive_ctx.get()) <= 0) {
        throw CryptoError("Failed to initialize key derivation");
    }

    if (EVP_PKEY_derive_set_peer(derive_ctx.get(), ephemeral_pubkey.get()) <= 0) {
        throw CryptoError("Failed to set peer key");
    }

    // Get shared secret
    size_t shared_secret_len = 0;
    if (EVP_PKEY_derive(derive_ctx.get(), nullptr, &shared_secret_len) <= 0) {
        throw CryptoError("Failed to get shared secret length");
    }

    std::vector<uint8_t> shared_secret(shared_secret_len);
    if (EVP_PKEY_derive(derive_ctx.get(), shared_secret.data(), &shared_secret_len) <= 0) {
        throw CryptoError("Failed to derive shared secret");
    }

    // Derive decryption key from shared secret using HKDF-SHA256
    std::vector<uint8_t> wrapping_key(CHACHA20_POLY1305_KEY_SIZE);

    EVP_PKEY_CTX_ptr kdf_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    if (!kdf_ctx) {
        throw CryptoError("Failed to create HKDF context");
    }

    if (EVP_PKEY_derive_init(kdf_ctx.get()) <= 0) {
        throw CryptoError("Failed to initialize HKDF");
    }

    if (EVP_PKEY_CTX_set_hkdf_md(kdf_ctx.get(), EVP_sha256()) <= 0) {
        throw CryptoError("Failed to set HKDF hash");
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(kdf_ctx.get(), shared_secret.data(), shared_secret.size()) <= 0) {
        throw CryptoError("Failed to set HKDF key");
    }

    const char* info = "libsum-x25519-aes-wrap";
    if (EVP_PKEY_CTX_add1_hkdf_info(kdf_ctx.get(), (const unsigned char*)info, strlen(info)) <= 0) {
        throw CryptoError("Failed to set HKDF info");
    }

    size_t wrapping_key_len = wrapping_key.size();
    if (EVP_PKEY_derive(kdf_ctx.get(), wrapping_key.data(), &wrapping_key_len) <= 0) {
        throw CryptoError("Failed to derive wrapping key");
    }

    // Decrypt AES key with ChaCha20-Poly1305
    EVP_CIPHER_CTX_ptr cipher_ctx(EVP_CIPHER_CTX_new());
    if (!cipher_ctx) {
        throw CryptoError("Failed to create cipher context");
    }

    if (EVP_DecryptInit_ex(cipher_ctx.get(), EVP_chacha20_poly1305(), nullptr,
                           wrapping_key.data(), nonce.data()) != 1) {
        throw CryptoError("Failed to initialize ChaCha20-Poly1305 decryption");
    }

    // Set authentication tag
    if (EVP_CIPHER_CTX_ctrl(cipher_ctx.get(), EVP_CTRL_AEAD_SET_TAG, CHACHA20_POLY1305_TAG_SIZE,
                            const_cast<uint8_t*>(encrypted_key.data() + AES_128_KEY_SIZE)) != 1) {
        throw CryptoError("Failed to set authentication tag");
    }

    SecureVector<uint8_t> aes_key(AES_128_KEY_SIZE);
    int len = 0;

    if (EVP_DecryptUpdate(cipher_ctx.get(), aes_key.data(), &len,
                          encrypted_key.data(), AES_128_KEY_SIZE) != 1) {
        throw KeyUnwrapError();
    }

    int plaintext_len = len;

    if (EVP_DecryptFinal_ex(cipher_ctx.get(), aes_key.data() + len, &len) != 1) {
        throw KeyUnwrapError();
    }
    plaintext_len += len;

    if (plaintext_len != AES_128_KEY_SIZE) {
        throw CryptoError("Unexpected decrypted key size");
    }

    return aes_key;
}

} // namespace crypto
} // namespace sum
