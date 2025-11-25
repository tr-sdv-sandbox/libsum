/**
 * @file crypto_test.cpp
 * @brief Unit tests for cryptographic primitives
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "sum/common/crypto.h"
#include <vector>
#include <string>

using namespace sum::crypto;

// ============================================================================
// Key Generation Tests
// ============================================================================

TEST(CryptoTest, GeneratePrivateKey) {
    auto key = PrivateKey::Generate(KeyType::Ed25519);

    // Verify PEM export/import
    std::string pem = key.ToPEM();
    EXPECT_FALSE(pem.empty());
    EXPECT_NE(pem.find("BEGIN"), std::string::npos);
}

TEST(CryptoTest, DerivePublicKey) {
    auto privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto pubkey = PublicKey::FromPrivateKey(privkey);

    // Verify PEM export
    std::string pem = pubkey.ToPEM();
    EXPECT_FALSE(pem.empty());
}

TEST(CryptoTest, LoadPrivateKeyFromPEM) {
    auto key = PrivateKey::Generate(KeyType::Ed25519);
    std::string pem = key.ToPEM();

    // Load from PEM
    auto loaded_key = PrivateKey::LoadFromPEM(pem);

    // Verify loaded key works for signing
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    auto sig = Ed25519::Sign(loaded_key, data);
    EXPECT_FALSE(sig.empty());
}

// ============================================================================
// Ed25519 Signature Tests
// ============================================================================

TEST(CryptoTest, Ed25519SignVerify) {
    auto privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto pubkey = PublicKey::FromPrivateKey(privkey);

    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};

    // Sign
    auto signature = Ed25519::Sign(privkey, data);
    EXPECT_FALSE(signature.empty());
    EXPECT_EQ(signature.size(), 64);  // Ed25519 signatures are always 64 bytes

    // Verify
    EXPECT_TRUE(Ed25519::Verify(pubkey, data, signature));
}

TEST(CryptoTest, Ed25519VerifyFailsOnWrongData) {
    auto privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto pubkey = PublicKey::FromPrivateKey(privkey);

    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> wrong_data = {0x01, 0x02, 0x03, 0x04, 0x06};

    auto signature = Ed25519::Sign(privkey, data);

    // Should throw SignatureVerificationError
    EXPECT_THROW(Ed25519::Verify(pubkey, wrong_data, signature), SignatureVerificationError);
}

TEST(CryptoTest, Ed25519VerifyFailsOnWrongKey) {
    auto privkey1 = PrivateKey::Generate(KeyType::Ed25519);
    auto privkey2 = PrivateKey::Generate(KeyType::Ed25519);
    auto pubkey2 = PublicKey::FromPrivateKey(privkey2);

    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};

    auto signature = Ed25519::Sign(privkey1, data);

    // Should throw SignatureVerificationError
    EXPECT_THROW(Ed25519::Verify(pubkey2, data, signature), SignatureVerificationError);
}

TEST(CryptoTest, Ed25519Deterministic) {
    // Ed25519 signatures are deterministic
    auto privkey = PrivateKey::Generate(KeyType::Ed25519);

    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};

    auto sig1 = Ed25519::Sign(privkey, data);
    auto sig2 = Ed25519::Sign(privkey, data);

    // Same data with same key should produce identical signatures
    EXPECT_EQ(sig1, sig2);
}

TEST(CryptoTest, Ed25519LargeData) {
    auto privkey = PrivateKey::Generate(KeyType::Ed25519);
    auto pubkey = PublicKey::FromPrivateKey(privkey);

    // Test with large data
    std::vector<uint8_t> data(10000, 0x42);

    auto signature = Ed25519::Sign(privkey, data);
    EXPECT_TRUE(Ed25519::Verify(pubkey, data, signature));
}

// ============================================================================
// X25519 Key Wrapping Tests
// ============================================================================

TEST(CryptoTest, X25519WrapUnwrapKey) {
    auto device_privkey = PrivateKey::Generate(KeyType::X25519);
    auto device_pubkey = PublicKey::FromPrivateKey(device_privkey);

    std::vector<uint8_t> aes_key(16, 0xAA);

    // Wrap key
    auto wrapped_key = X25519::WrapKey(aes_key, device_pubkey);
    EXPECT_GT(wrapped_key.size(), aes_key.size());

    // Unwrap key
    auto unwrapped_key = X25519::UnwrapKey(wrapped_key, device_privkey);
    EXPECT_EQ(aes_key, unwrapped_key);
}

TEST(CryptoTest, X25519UnwrapFailsOnWrongKey) {
    auto device1_privkey = PrivateKey::Generate(KeyType::X25519);
    auto device1_pubkey = PublicKey::FromPrivateKey(device1_privkey);
    auto device2_privkey = PrivateKey::Generate(KeyType::X25519);

    std::vector<uint8_t> aes_key(16, 0xAA);

    auto wrapped_key = X25519::WrapKey(aes_key, device1_pubkey);

    // Should throw KeyUnwrapError
    EXPECT_THROW(X25519::UnwrapKey(wrapped_key, device2_privkey), KeyUnwrapError);
}

TEST(CryptoTest, X25519UnwrapFailsOnTamperedData) {
    auto device_privkey = PrivateKey::Generate(KeyType::X25519);
    auto device_pubkey = PublicKey::FromPrivateKey(device_privkey);

    std::vector<uint8_t> aes_key(16, 0xAA);

    auto wrapped_key = X25519::WrapKey(aes_key, device_pubkey);

    // Tamper with wrapped key
    wrapped_key[50] ^= 0xFF;

    // Should throw KeyUnwrapError
    EXPECT_THROW(X25519::UnwrapKey(wrapped_key, device_privkey), KeyUnwrapError);
}

TEST(CryptoTest, X25519WrongKeySize) {
    auto device_privkey = PrivateKey::Generate(KeyType::X25519);
    auto device_pubkey = PublicKey::FromPrivateKey(device_privkey);

    std::vector<uint8_t> wrong_key(15, 0xAA);  // Should be 16 bytes

    EXPECT_THROW(X25519::WrapKey(wrong_key, device_pubkey), CryptoError);
}

// ============================================================================
// AES-128-GCM Tests (AEAD with authentication)
// ============================================================================

TEST(CryptoTest, AES128GCMEncryptDecrypt) {
    std::vector<uint8_t> key(16, 0xAA);
    std::vector<uint8_t> iv(12, 0xBB);
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};

    // Encrypt
    auto result = AES128GCM::Encrypt(key, iv, plaintext);
    EXPECT_EQ(result.tag.size(), 16);  // GCM tag is 16 bytes

    // Decrypt using streaming API
    SecureVector<uint8_t> key_secure(key);
    AES128GCM::Decryptor decryptor(key_secure, iv, result.tag);
    auto decrypted = decryptor.Update(result.ciphertext);
    auto final = decryptor.Finalize();  // Tag verification happens here
    decrypted.insert(decrypted.end(), final.begin(), final.end());

    EXPECT_EQ(plaintext, decrypted);
}

TEST(CryptoTest, AES128GCMCiphertextSize) {
    std::vector<uint8_t> key(16, 0xAA);
    std::vector<uint8_t> iv(12, 0xBB);
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};

    auto result = AES128GCM::Encrypt(key, iv, plaintext);

    // GCM ciphertext is same size as plaintext (tag is separate)
    EXPECT_EQ(result.ciphertext.size(), plaintext.size());
    EXPECT_EQ(result.tag.size(), 16);
}

TEST(CryptoTest, AES128GCMWrongKeySize) {
    std::vector<uint8_t> key(15, 0xAA);  // Wrong size
    std::vector<uint8_t> iv(12, 0xBB);
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};

    EXPECT_THROW(AES128GCM::Encrypt(key, iv, plaintext), CryptoError);
}

TEST(CryptoTest, AES128GCMWrongIVSize) {
    std::vector<uint8_t> key(16, 0xAA);
    std::vector<uint8_t> iv(11, 0xBB);  // Wrong size
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};

    EXPECT_THROW(AES128GCM::Encrypt(key, iv, plaintext), CryptoError);

    // Also test decryptor constructor
    SecureVector<uint8_t> key_secure(key);
    std::vector<uint8_t> tag(16, 0xCC);
    EXPECT_THROW(AES128GCM::Decryptor(key_secure, iv, tag), CryptoError);
}

TEST(CryptoTest, AES128GCMLargeData) {
    std::vector<uint8_t> key(16, 0xAA);
    std::vector<uint8_t> iv(12, 0xBB);
    std::vector<uint8_t> plaintext(100000, 0x42);

    auto result = AES128GCM::Encrypt(key, iv, plaintext);

    // Decrypt using streaming API
    SecureVector<uint8_t> key_secure(key);
    AES128GCM::Decryptor decryptor(key_secure, iv, result.tag);
    auto decrypted = decryptor.Update(result.ciphertext);
    auto final = decryptor.Finalize();
    decrypted.insert(decrypted.end(), final.begin(), final.end());

    EXPECT_EQ(plaintext, decrypted);
}

TEST(CryptoTest, AES128GCMStreamingChunks) {
    std::vector<uint8_t> key(16, 0xAA);
    std::vector<uint8_t> iv(12, 0xBB);
    std::vector<uint8_t> plaintext(10000, 0x42);

    // Encrypt
    auto result = AES128GCM::Encrypt(key, iv, plaintext);

    // Decrypt in chunks (simulating streaming)
    SecureVector<uint8_t> key_secure(key);
    AES128GCM::Decryptor decryptor(key_secure, iv, result.tag);

    std::vector<uint8_t> decrypted;
    size_t chunk_size = 1024;
    for (size_t offset = 0; offset < result.ciphertext.size(); offset += chunk_size) {
        size_t size = std::min(chunk_size, result.ciphertext.size() - offset);
        std::vector<uint8_t> chunk(result.ciphertext.begin() + offset, result.ciphertext.begin() + offset + size);
        auto dec_chunk = decryptor.Update(chunk);
        decrypted.insert(decrypted.end(), dec_chunk.begin(), dec_chunk.end());
    }

    auto final = decryptor.Finalize();
    decrypted.insert(decrypted.end(), final.begin(), final.end());

    EXPECT_EQ(plaintext, decrypted);
}

TEST(CryptoTest, AES128GCMTamperedCiphertextDetected) {
    std::vector<uint8_t> key(16, 0xAA);
    std::vector<uint8_t> iv(12, 0xBB);
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};

    // Encrypt
    auto result = AES128GCM::Encrypt(key, iv, plaintext);

    // Tamper with ciphertext
    result.ciphertext[0] ^= 0xFF;

    // Decryption should fail tag verification
    SecureVector<uint8_t> key_secure(key);
    AES128GCM::Decryptor decryptor(key_secure, iv, result.tag);
    decryptor.Update(result.ciphertext);
    EXPECT_THROW(decryptor.Finalize(), CryptoError);
}

TEST(CryptoTest, AES128GCMTamperedTagDetected) {
    std::vector<uint8_t> key(16, 0xAA);
    std::vector<uint8_t> iv(12, 0xBB);
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};

    // Encrypt
    auto result = AES128GCM::Encrypt(key, iv, plaintext);

    // Tamper with tag
    result.tag[0] ^= 0xFF;

    // Decryption should fail tag verification
    SecureVector<uint8_t> key_secure(key);
    AES128GCM::Decryptor decryptor(key_secure, iv, result.tag);
    decryptor.Update(result.ciphertext);
    EXPECT_THROW(decryptor.Finalize(), CryptoError);
}

// ============================================================================
// SHA-256 Tests
// ============================================================================

TEST(CryptoTest, SHA256Hash) {
    std::vector<uint8_t> data = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    auto hash = SHA256::Hash(data);

    EXPECT_EQ(hash.size(), 32);

    // Hash should be deterministic
    auto hash2 = SHA256::Hash(data);
    EXPECT_EQ(hash, hash2);
}

TEST(CryptoTest, SHA256DifferentDataDifferentHash) {
    std::vector<uint8_t> data1 = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    std::vector<uint8_t> data2 = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21};

    auto hash1 = SHA256::Hash(data1);
    auto hash2 = SHA256::Hash(data2);

    EXPECT_NE(hash1, hash2);
}

TEST(CryptoTest, SHA256EmptyData) {
    std::vector<uint8_t> data;
    auto hash = SHA256::Hash(data);

    EXPECT_EQ(hash.size(), 32);
}

TEST(CryptoTest, SHA256LargeData) {
    std::vector<uint8_t> data(1000000, 0x42);
    auto hash = SHA256::Hash(data);

    EXPECT_EQ(hash.size(), 32);
}
