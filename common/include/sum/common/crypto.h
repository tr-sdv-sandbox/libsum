/**
 * @file crypto.h
 * @brief Cryptographic primitives for secure update manifests
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SUM_CRYPTO_H
#define SUM_CRYPTO_H

#include "sum/common/secure_vector.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

namespace sum {

// Forward declaration
struct DeviceMetadata;

namespace crypto {

/**
 * @brief Cryptographic exceptions
 */
class CryptoError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class SignatureVerificationError : public CryptoError {
public:
    SignatureVerificationError() : CryptoError("Signature verification failed") {}
};

class MACVerificationError : public CryptoError {
public:
    MACVerificationError() : CryptoError("MAC verification failed") {}
};

class KeyUnwrapError : public CryptoError {
public:
    KeyUnwrapError() : CryptoError("Key unwrapping failed") {}
};

/**
 * @brief Cryptographic size constants
 */
// AES-128-GCM constants
constexpr size_t AES_128_KEY_SIZE = 16;          // 128 bits
constexpr size_t AES_GCM_IV_SIZE = 12;           // 96-bit nonce (recommended for GCM)
constexpr size_t AES_GCM_TAG_SIZE = 16;          // 128-bit authentication tag

// Ed25519 constants
constexpr size_t ED25519_KEY_SIZE = 32;          // Public and private key size
constexpr size_t ED25519_SIGNATURE_SIZE = 64;    // Signature size

// X25519 constants
constexpr size_t X25519_KEY_SIZE = 32;           // Public and private key size

// ChaCha20-Poly1305 constants
constexpr size_t CHACHA20_POLY1305_KEY_SIZE = 32;   // 256 bits
constexpr size_t CHACHA20_POLY1305_NONCE_SIZE = 12; // 96 bits
constexpr size_t CHACHA20_POLY1305_TAG_SIZE = 16;   // 128 bits

// SHA-256 constants
constexpr size_t SHA256_HASH_SIZE = 32;          // 256 bits

// Certificate chain depth: Leaf → Intermediate → Root
constexpr size_t REQUIRED_CERT_CHAIN_DEPTH = 2;

/**
 * @brief Key type for generation
 */
enum class KeyType {
    Ed25519,  // For signing/verification
    X25519    // For key wrapping/unwrapping
};

/**
 * @brief ECC private key wrapper
 */
class PrivateKey {
public:
    PrivateKey();
    ~PrivateKey();

    PrivateKey(PrivateKey&&) noexcept;
    PrivateKey& operator=(PrivateKey&&) noexcept;
    PrivateKey(const PrivateKey&) = delete;
    PrivateKey& operator=(const PrivateKey&) = delete;

    /**
     * @brief Load private key from PEM file
     * @param path Path to PEM-encoded private key
     * @return Loaded private key
     * @throws CryptoError on parse error
     */
    static PrivateKey LoadFromFile(const std::string& path);

    /**
     * @brief Load private key from PEM buffer
     * @param pem PEM-encoded private key
     * @return Loaded private key
     * @throws CryptoError on parse error
     */
    static PrivateKey LoadFromPEM(const std::string& pem);

    /**
     * @brief Generate new key pair
     * @param type Key type (Ed25519 for signing, X25519 for key wrapping)
     * @return Generated private key
     * @throws CryptoError on generation error
     */
    static PrivateKey Generate(KeyType type);

    /**
     * @brief Export to PEM format
     * @return PEM-encoded private key
     */
    std::string ToPEM() const;

    void* GetNativeHandle() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief ECC public key wrapper
 */
class PublicKey {
public:
    PublicKey();
    ~PublicKey();

    PublicKey(PublicKey&&) noexcept;
    PublicKey& operator=(PublicKey&&) noexcept;
    PublicKey(const PublicKey&) = delete;
    PublicKey& operator=(const PublicKey&) = delete;

    /**
     * @brief Load public key from PEM file
     * @param path Path to PEM-encoded public key
     * @return Loaded public key
     * @throws CryptoError on parse error
     */
    static PublicKey LoadFromFile(const std::string& path);

    /**
     * @brief Load public key from PEM buffer
     * @param pem PEM-encoded public key
     * @return Loaded public key
     * @throws CryptoError on parse error
     */
    static PublicKey LoadFromPEM(const std::string& pem);

    /**
     * @brief Derive public key from private key
     * @param privkey Private key
     * @return Corresponding public key
     */
    static PublicKey FromPrivateKey(const PrivateKey& privkey);

    /**
     * @brief Export to PEM format
     * @return PEM-encoded public key
     */
    std::string ToPEM() const;

    void* GetNativeHandle() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief X.509 certificate wrapper
 */
class Certificate {
public:
    Certificate();
    ~Certificate();

    Certificate(Certificate&&) noexcept;
    Certificate& operator=(Certificate&&) noexcept;
    Certificate(const Certificate&) = delete;
    Certificate& operator=(const Certificate&) = delete;

    /**
     * @brief Load certificate from file
     * @param path Path to certificate (PEM or DER)
     * @return Loaded certificate
     * @throws CryptoError on parse error
     */
    static Certificate LoadFromFile(const std::string& path);

    /**
     * @brief Load certificate chain from PEM file
     *
     * Loads multiple certificates from a single PEM file (certificate bundle).
     * Certificates are returned in order: [leaf, intermediate(s)...]
     * This is the standard format for distributing certificate chains (like TLS).
     *
     * @param path Path to PEM file containing certificate chain
     * @return Vector of certificates in chain order
     * @throws CryptoError on parse error
     */
    static std::vector<Certificate> LoadChainFromFile(const std::string& path);

    /**
     * @brief Load certificate chain from PEM string
     *
     * Loads multiple certificates from a single PEM string (certificate bundle).
     * Certificates are returned in order: [leaf, intermediate(s)...]
     *
     * @param pem PEM string containing multiple certificates
     * @return Vector of certificates in chain order
     * @throws CryptoError on parse error
     */
    static std::vector<Certificate> LoadChainFromPEM(const std::string& pem);

    /**
     * @brief Load certificate from DER buffer
     * @param der DER-encoded certificate
     * @return Loaded certificate
     * @throws CryptoError on parse error
     */
    static Certificate LoadFromDER(const std::vector<uint8_t>& der);

    /**
     * @brief Export to DER format
     * @return DER-encoded certificate
     */
    std::vector<uint8_t> ToDER() const;

    /**
     * @brief Export to PEM format
     * @return PEM-encoded certificate
     */
    std::string ToPEM() const;

    /**
     * @brief Create PEM bundle from certificate chain
     *
     * Combines multiple certificates into a single PEM string (certificate bundle).
     * This is the standard format for distributing certificate chains (like TLS).
     * Order: [leaf, intermediate(s)...]
     *
     * @param chain Vector of certificates to bundle
     * @return PEM string containing all certificates
     */
    static std::string CreateChainPEM(const std::vector<Certificate>& chain);

    /**
     * @brief Get public key from certificate
     * @return Public key
     */
    PublicKey GetPublicKey() const;

    /**
     * @brief Verify certificate chain
     * @param issuer Issuing CA certificate
     * @param trusted_time Trusted timestamp for validity check (Unix epoch seconds, REQUIRED - use time(nullptr) for current time)
     * @return true if chain is valid
     */
    bool VerifyChain(const Certificate& issuer, int64_t trusted_time) const;

    /**
     * @brief Verify certificate chain with intermediate CAs
     *
     * Verifies a certificate chain: this cert → intermediates[0] → ... → root_ca
     * Each certificate in the chain must be signed by the next one.
     * All certificates in the chain must be within validity period.
     *
     * @param intermediates Vector of intermediate CA certificates (ordered from leaf to root)
     * @param root_ca Root CA certificate (trust anchor)
     * @param trusted_time Trusted timestamp for validity check (Unix epoch seconds, REQUIRED - use time(nullptr) for current time)
     * @return true if entire chain is valid
     * @throws CryptoError if chain validation fails
     */
    bool VerifyChainWithIntermediates(
        const std::vector<Certificate>& intermediates,
        const Certificate& root_ca,
        int64_t trusted_time
    ) const;

    /**
     * @brief Check if certificate has embedded manifest extension
     * @return true if manifest extension is present
     */
    bool HasManifestExtension() const;

    /**
     * @brief Alias for HasManifestExtension()
     * @return true if manifest extension is present
     */
    inline bool HasManifest() const { return HasManifestExtension(); }

    /**
     * @brief Extract and verify manifest from certificate X.509 extension
     *
     * This method REQUIRES certificate verification before extraction.
     * It ensures the manifest data has not been tampered with.
     *
     * @param ca_cert CA certificate to verify against
     * @param trusted_time Trusted timestamp for validity check (Unix epoch seconds, REQUIRED - use time(nullptr) for current time)
     * @return Verified manifest data (Protocol Buffer format)
     * @throws CryptoError if no manifest extension present
     * @throws CryptoError if certificate verification fails
     */
    std::vector<uint8_t> GetVerifiedManifest(const Certificate& ca_cert, int64_t trusted_time) const;

    /**
     * @brief Extract and verify manifest with intermediate CA chain
     *
     * Verifies the certificate chain before extracting manifest data.
     * This is the recommended method for production PKI hierarchies.
     *
     * @param intermediates Vector of intermediate CA certificates (ordered from leaf to root)
     * @param root_ca Root CA certificate (trust anchor)
     * @param trusted_time Trusted timestamp for validity check (Unix epoch seconds, REQUIRED - use time(nullptr) for current time)
     * @return Verified manifest data (Protocol Buffer format)
     * @throws CryptoError if no manifest extension present
     * @throws CryptoError if chain verification fails
     */
    std::vector<uint8_t> GetVerifiedManifestWithChain(
        const std::vector<Certificate>& intermediates,
        const Certificate& root_ca,
        int64_t trusted_time
    ) const;

    /**
     * @brief Check if certificate has embedded device metadata extension
     * @return true if device metadata extension is present
     */
    bool HasDeviceMetadata() const;

    /**
     * @brief Get device metadata from certificate X.509 extension (UNVERIFIED)
     *
     * WARNING: This returns unverified metadata for quick filtering only.
     * Use this to check if an update MIGHT be for your device before verification.
     * After filtering, use GetVerifiedDeviceMetadata() to get verified data.
     *
     * @return Device metadata (UNVERIFIED)
     * @throws CryptoError if no device metadata extension present
     */
    DeviceMetadata GetDeviceMetadata() const;

    /**
     * @brief Get and verify device metadata from certificate X.509 extension
     *
     * This method REQUIRES certificate verification before extraction.
     * Use this after initial filtering to get cryptographically verified metadata.
     *
     * @param ca_cert CA certificate to verify against
     * @param trusted_time Trusted timestamp for validity check (Unix epoch seconds, REQUIRED - use time(nullptr) for current time)
     * @return Verified device metadata
     * @throws CryptoError if no device metadata extension present
     * @throws CryptoError if certificate verification fails
     */
    DeviceMetadata GetVerifiedDeviceMetadata(const Certificate& ca_cert, int64_t trusted_time) const;

    /**
     * @brief Get certificate notBefore timestamp (for revocation checking)
     * @return Unix epoch seconds when certificate becomes valid
     * @throws CryptoError if certificate is invalid
     */
    int64_t GetNotBefore() const;

    /**
     * @brief Get certificate subject distinguished name
     * @return Subject DN string (e.g., "CN=Device-12345")
     */
    std::string GetSubject() const;

    /**
     * @brief Get certificate issuer distinguished name
     * @return Issuer DN string (e.g., "CN=Root CA")
     */
    std::string GetIssuer() const;

    /**
     * @brief Get certificate validity period
     * @return Pair of (notBefore, notAfter) timestamps in Unix epoch seconds
     */
    std::pair<int64_t, int64_t> GetValidityPeriod() const;

    /**
     * @brief Extract manifest from certificate X.509 extension (UNVERIFIED)
     *
     * WARNING: This returns unverified manifest data.
     * Use GetVerifiedManifest() or GetVerifiedManifestWithChain() for production.
     *
     * @return Manifest data (Protocol Buffer format, UNVERIFIED)
     * @throws CryptoError if no manifest extension present
     */
    std::vector<uint8_t> ExtractManifest() const;

    /**
     * @brief Verify certificate signature with public key
     *
     * Low-level signature verification. For full chain validation,
     * use VerifyChain() or VerifyChainWithIntermediates() instead.
     *
     * @param issuer_pubkey Public key of the issuer
     * @return true if signature is valid
     */
    bool VerifySignature(const PublicKey& issuer_pubkey) const;

    void* GetNativeHandle() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief X25519 key agreement and key wrapping
 *
 * Uses X25519 (Curve25519 Diffie-Hellman) for wrapping AES keys.
 * Companion to Ed25519 for encryption.
 */
class X25519 {
public:
    /**
     * @brief Wrap AES key using X25519 key agreement
     *
     * Creates ephemeral X25519 key pair, performs DH with recipient's
     * public key, and encrypts the AES key with the shared secret.
     *
     * @param aes_key AES key to wrap (16 bytes)
     * @param recipient_pubkey Recipient's Ed25519/X25519 public key
     * @return Wrapped key blob containing [ephemeral_pubkey || encrypted_key || nonce]
     * @throws CryptoError on wrapping failure
     */
    static std::vector<uint8_t> WrapKey(
        const std::vector<uint8_t>& aes_key,
        const PublicKey& recipient_pubkey
    );

    /**
     * @brief Unwrap AES key using X25519 key agreement
     *
     * Extracts ephemeral public key from wrapped blob, performs DH with
     * recipient's private key, and decrypts the AES key.
     *
     * @param wrapped_key Wrapped key blob from WrapKey()
     * @param recipient_privkey Recipient's Ed25519/X25519 private key
     * @return Unwrapped AES key (16 bytes) - automatically zeroized on destruction
     * @throws CryptoError on unwrapping failure
     * @throws KeyUnwrapError if decryption fails
     */
    static SecureVector<uint8_t> UnwrapKey(
        const std::vector<uint8_t>& wrapped_key,
        const PrivateKey& recipient_privkey
    );
};

/**
 * @brief Ed25519 signing/verification
 */
class Ed25519 {
public:
    /**
     * @brief Sign data with Ed25519
     * @param private_key Ed25519 private key
     * @param data Data to sign
     * @return 64-byte signature
     * @throws CryptoError on signing failure
     */
    static std::vector<uint8_t> Sign(
        const PrivateKey& private_key,
        const std::vector<uint8_t>& data
    );

    /**
     * @brief Verify Ed25519 signature
     * @param public_key Ed25519 public key
     * @param data Original data
     * @param signature 64-byte signature
     * @return true if signature is valid
     * @throws SignatureVerificationError if signature is invalid
     */
    static bool Verify(
        const PublicKey& public_key,
        const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& signature
    );
};

/**
 * @brief AES-128-GCM authenticated encryption result
 */
struct AES128GCMResult {
    std::vector<uint8_t> ciphertext;  ///< Encrypted data
    std::vector<uint8_t> tag;         ///< Authentication tag (16 bytes)
};

/**
 * @brief AES-128-GCM AEAD encryption/decryption
 */
class AES128GCM {
public:
    /**
     * @brief Encrypt data with AES-128-GCM (single-shot, for backend use)
     * @param key 128-bit key (16 bytes)
     * @param iv Nonce (12 bytes recommended for GCM)
     * @param plaintext Data to encrypt
     * @return Encrypted data with authentication tag
     * @throws CryptoError if key/IV size is invalid
     */
    static AES128GCMResult Encrypt(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& plaintext
    );

    /**
     * @brief Streaming decryptor for AES-128-GCM
     *
     * Use this for decrypting large firmware that doesn't fit in RAM.
     * Process data in chunks, writing directly to flash storage.
     * IMPORTANT: Tag verification happens in Finalize() - data is not authenticated until then!
     */
    class Decryptor {
    public:
        /**
         * @brief Create streaming decryptor
         * @param key 128-bit AES key (16 bytes)
         * @param iv Nonce (12 bytes)
         * @param tag Authentication tag (16 bytes) - verified in Finalize()
         * @throws CryptoError if key/IV/tag size is invalid
         */
        Decryptor(
            const SecureVector<uint8_t>& key,
            const std::vector<uint8_t>& iv,
            const std::vector<uint8_t>& tag
        );
        ~Decryptor();

        Decryptor(const Decryptor&) = delete;
        Decryptor& operator=(const Decryptor&) = delete;
        Decryptor(Decryptor&&) noexcept;
        Decryptor& operator=(Decryptor&&) noexcept;

        /**
         * @brief Decrypt a chunk of ciphertext
         * @param ciphertext_chunk Chunk of encrypted data
         * @return Decrypted plaintext chunk (same size as input)
         * @throws CryptoError on decryption failure
         */
        std::vector<uint8_t> Update(const std::vector<uint8_t>& ciphertext_chunk);

        /**
         * @brief Finalize decryption and verify authentication tag
         * @return Any remaining plaintext bytes (usually empty)
         * @throws CryptoError on finalization failure or tag verification failure
         */
        std::vector<uint8_t> Finalize();

    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };
};

/**
 * @brief SHA-256 hashing
 */
class SHA256 {
public:
    /**
     * @brief Compute SHA-256 hash (single-shot, convenience method)
     * @param data Data to hash
     * @return 32-byte hash
     */
    static std::vector<uint8_t> Hash(const std::vector<uint8_t>& data);

    /**
     * @brief Streaming hasher for SHA-256
     *
     * Use this for hashing large firmware that doesn't fit in RAM.
     * Hash data incrementally as you decrypt/write it.
     */
    class Hasher {
    public:
        /**
         * @brief Create streaming hasher
         */
        Hasher();
        ~Hasher();

        Hasher(const Hasher&) = delete;
        Hasher& operator=(const Hasher&) = delete;
        Hasher(Hasher&&) noexcept;
        Hasher& operator=(Hasher&&) noexcept;

        /**
         * @brief Add data to hash
         * @param chunk Chunk of data to hash
         */
        void Update(const std::vector<uint8_t>& chunk);

        /**
         * @brief Finalize hash and get result
         * @return 32-byte SHA-256 hash
         * @throws CryptoError if already finalized
         */
        std::vector<uint8_t> Finalize();

    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };
};

} // namespace crypto
} // namespace sum

#endif // SUM_CRYPTO_H
