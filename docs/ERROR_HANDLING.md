# Error Handling Strategy

## Overview

libsum uses a combination of exceptions and return values for error handling. This document describes when to use each approach and which exception types to use.

## Exception Hierarchy

```
std::runtime_error
└── crypto::CryptoError              // Base class for all crypto errors
    ├── SignatureVerificationError   // Signature verification failed
    ├── MACVerificationError         // MAC/AEAD tag verification failed
    └── KeyUnwrapError               // Key unwrapping failed (wrong key or tampered data)
```

## When to Throw Exceptions

### Always Throw for:

1. **Programming Errors** (should never happen in correct code)
   - Invalid parameters (nullptr, wrong sizes, empty required fields)
   - Invalid state (uninitialized objects)
   - Internal errors (memory allocation failures, OpenSSL errors)

2. **Unrecoverable Errors**
   - File I/O failures
   - Parse errors (invalid PEM/DER, malformed JSON)
   - Cryptographic primitive failures (key generation, random number generation)

3. **Security Violations**
   - Certificate chain validation failures (untrusted signer)
   - Expired/not-yet-valid certificates
   - Wrong key types (Ed25519 key used where X25519 expected)
   - DN mismatch in certificate chains
   - Invalid sizes (signature not 64 bytes, key not 32 bytes)

### Example:
```cpp
// Input validation - throw if invalid
if (aes_key.size() != AES_128_KEY_SIZE) {
    throw CryptoError("AES key must be exactly 16 bytes");
}

// Key type validation - throw if wrong type
if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
    throw CryptoError("Key is not an Ed25519 key");
}
```

## When to Return false

### Return false for:

1. **Expected Verification Failures** (adversary-controlled data)
   - Signature verification (`Ed25519::Verify` → throws on error, returns false would be design mistake)
   - Software hash mismatch
   - MAC/tag verification

2. **Validation Checks** (user might want to handle gracefully)
   - `ManifestValidator::VerifyManifest()` returns false
   - `ManifestValidator::VerifySoftware()` returns false
   - `Certificate::VerifyChain()` returns false (but throws for malformed data)

### Example:
```cpp
// Expected verification failure - return false
bool ManifestValidator::VerifySoftware(
    const std::vector<uint8_t>& software,
    const Manifest& manifest
) {
    auto computed_hash = crypto::SHA256::Hash(software);
    if (computed_hash != artifact.expected_hash) {
        return false;  // Hash mismatch - expected failure case
    }
    // ...
}
```

## Specific Exception Types

### CryptoError (Base Class)
**Use for:** General cryptographic errors that don't fit other categories

```cpp
throw CryptoError("Failed to create cipher context");
throw CryptoError("AES key must be exactly 16 bytes");
throw CryptoError("Chain validation failed: root CA is not self-signed");
```

### SignatureVerificationError
**Use for:** Digital signature verification failures

**Important:** Ed25519::Verify() throws this exception rather than returning false because signature verification failure in libsum always indicates either:
- Attack in progress (tampered data)
- Misconfiguration (wrong key)

Both cases should be caught and logged explicitly, not silently ignored.

```cpp
bool Ed25519::Verify(...) {
    int result = EVP_DigestVerify(...);
    if (result == 1) {
        return true;
    } else if (result == 0) {
        throw SignatureVerificationError();  // Invalid signature
    } else {
        throw CryptoError("Signature verification error");  // OpenSSL error
    }
}
```

### MACVerificationError
**Use for:** AEAD tag or MAC verification failures

```cpp
if (EVP_DecryptFinal_ex(...) != 1) {
    throw MACVerificationError();  // AEAD tag mismatch
}
```

### KeyUnwrapError
**Use for:** Key unwrapping/decryption failures (ChaCha20-Poly1305 AEAD in X25519::UnwrapKey)

```cpp
if (EVP_DecryptUpdate(...) != 1) {
    throw KeyUnwrapError();  // Wrong key or tampered wrapped key
}
```

## Error Handling Patterns

### Pattern 1: Crypto Operations (Throw on Failure)
```cpp
std::vector<uint8_t> AES128CTR::Encrypt(...) {
    if (key.size() != AES_128_KEY_SIZE) {
        throw CryptoError("AES-128 key must be exactly 16 bytes");
    }

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw CryptoError("Failed to create cipher context");
    }

    if (EVP_EncryptInit_ex(...) != 1) {
        throw CryptoError("Failed to initialize AES-128-CTR encryption");
    }
    // ...
}
```

### Pattern 2: Verification (Return bool, Throw on Error)
```cpp
bool ManifestValidator::VerifyManifest(const Manifest& manifest) {
    // Get data - throw if malformed
    const auto& signature = manifest.GetSignature();
    if (signature.empty()) {
        return false;  // No signature - expected case
    }

    const auto& cert_der = manifest.GetSigningCertificate();
    if (cert_der.empty()) {
        return false;  // No cert - expected case
    }

    // Load cert - throw if malformed DER
    crypto::Certificate signing_cert = crypto::Certificate::LoadFromDER(cert_der);

    // Verify chain - throws CryptoError if chain is invalid
    if (!signing_cert.VerifyChain(impl_->backend_ca, 0)) {
        return false;
    }

    // Verify signature - throws SignatureVerificationError if invalid
    try {
        return crypto::Ed25519::Verify(signing_pubkey, manifest_data, signature);
    } catch (const crypto::SignatureVerificationError&) {
        return false;  // Convert exception to return value for API consistency
    }
}
```

### Pattern 3: Chain Validation (Throw with Context)
```cpp
bool Certificate::VerifyChainWithIntermediates(...) {
    // Validate structure - throw with detailed context
    if (!root_subject || !root_issuer || X509_NAME_cmp(root_subject, root_issuer) != 0) {
        throw CryptoError("Chain validation failed: root CA is not self-signed");
    }

    // Verify signatures
    if (!VerifyChain(*current_issuer, trusted_time)) {
        throw CryptoError("Chain verification failed: update certificate not signed by intermediate CA");
    }

    // Validate DN linkage
    if (X509_NAME_cmp(subject_issuer, issuer_subject) != 0) {
        throw CryptoError("Chain validation failed: update certificate issuer DN does not match " +
                        std::string(intermediates.empty() ? "root CA" : "intermediate CA") + " subject DN");
    }

    return true;
}
```

## Caller Responsibilities

### Application Code
```cpp
try {
    // Load and verify certificate atomically
    auto root_ca = crypto::Certificate::LoadFromFile("ca.crt");
    auto update_cert = crypto::UpdateCertificate::LoadFromFile(
        "update.crt",
        root_ca,
        time(nullptr),
        reject_before
    );
    // ✅ Certificate verified - all extensions are trustworthy

    // Validate and extract manifest
    ManifestValidator validator(root_ca, device_key);
    validator.SetLastInstalledVersion(LoadFromFlash("last_version", 0));
    auto manifest = validator.ValidateCertificate(update_cert, time(nullptr));

    // Unwrap key and create decryptor
    size_t artifact_index = 0;
    auto key = validator.UnwrapEncryptionKey(manifest, artifact_index);
    auto decryptor = validator.CreateDecryptor(key, manifest, artifact_index);

    // Stream decrypt and hash
    crypto::SHA256::Hasher hasher;
    // ... (streaming loop)
    auto computed_hash = hasher.Finalize();

    // Verify signature
    if (!validator.VerifySignature(computed_hash, manifest, artifact_index)) {
        LOG(ERROR) << "Software verification failed - hash or signature mismatch";
        return 1;
    }
} catch (const crypto::KeyUnwrapError& e) {
    LOG(ERROR) << "Wrong device key or tampered update package";
    return 1;
} catch (const crypto::SignatureVerificationError& e) {
    LOG(ERROR) << "Signature verification failed - possible attack";
    return 1;
} catch (const crypto::CryptoError& e) {
    LOG(ERROR) << "Cryptographic error: " << e.what();
    return 1;
} catch (const std::exception& e) {
    LOG(ERROR) << "Error: " << e.what();
    return 1;
}
```

## Best Practices

1. **Be Specific:** Use the most specific exception type that fits
2. **Add Context:** Include relevant information in error messages (which certificate, which field, expected vs actual)
3. **Don't Catch and Ignore:** If you catch an exception, either handle it properly or re-throw
4. **Document Exceptions:** Document which exceptions each function can throw
5. **Fail Secure:** When in doubt, throw - don't silently ignore potential security issues
6. **Validate Early:** Check inputs at API boundaries before doing expensive operations

## Common Mistakes to Avoid

❌ **Don't:** Catch exceptions and return false without logging
```cpp
bool BadExample() {
    try {
        ValidateCertificate();
    } catch (...) {
        return false;  // Lost all error information!
    }
}
```

❌ **Don't:** Return false for programming errors
```cpp
bool BadExample(const std::vector<uint8_t>& key) {
    if (key.size() != 32) {
        return false;  // Should throw - this is a programming error
    }
}
```

❌ **Don't:** Throw for expected validation failures in high-level APIs
```cpp
void BadExample() {
    if (hash_mismatch) {
        throw CryptoError("Hash mismatch");  // Should return false from VerifySoftware()
    }
}
```

✅ **Do:** Validate inputs and throw immediately
```cpp
std::vector<uint8_t> GoodExample(const std::vector<uint8_t>& key) {
    if (key.size() != AES_128_KEY_SIZE) {
        throw CryptoError("AES key must be exactly 16 bytes");
    }
    // ... proceed with operation
}
```

✅ **Do:** Provide context in error messages
```cpp
throw CryptoError("Chain validation failed: intermediate CA " + std::to_string(i) +
                " issuer DN does not match next CA subject DN");
```

✅ **Do:** Use try-catch only when you can handle the error meaningfully
```cpp
bool VerifyManifest() {
    try {
        return crypto::Ed25519::Verify(pubkey, data, sig);
    } catch (const crypto::SignatureVerificationError&) {
        // Convert to return false for API consistency
        return false;
    }
    // Let other exceptions propagate
}
```
