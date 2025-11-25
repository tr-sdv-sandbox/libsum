/**
 * @file openssl_wrappers.h
 * @brief RAII wrappers for OpenSSL resources
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SUM_OPENSSL_WRAPPERS_H
#define SUM_OPENSSL_WRAPPERS_H

#include <memory>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/params.h>
#include <openssl/param_build.h>

namespace sum {
namespace crypto {
namespace internal {

// Custom deleters for OpenSSL types
struct EVP_PKEY_Deleter {
    void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); }
};

struct EVP_PKEY_CTX_Deleter {
    void operator()(EVP_PKEY_CTX* p) const { if (p) EVP_PKEY_CTX_free(p); }
};

struct BIO_Deleter {
    void operator()(BIO* p) const { if (p) BIO_free(p); }
};

struct OSSL_PARAM_Deleter {
    void operator()(OSSL_PARAM* p) const { if (p) OSSL_PARAM_free(p); }
};

struct OSSL_PARAM_BLD_Deleter {
    void operator()(OSSL_PARAM_BLD* p) const { if (p) OSSL_PARAM_BLD_free(p); }
};

struct EVP_CIPHER_CTX_Deleter {
    void operator()(EVP_CIPHER_CTX* p) const { if (p) EVP_CIPHER_CTX_free(p); }
};

struct EVP_MD_CTX_Deleter {
    void operator()(EVP_MD_CTX* p) const { if (p) EVP_MD_CTX_free(p); }
};

struct X509_Deleter {
    void operator()(X509* p) const { if (p) X509_free(p); }
};

// RAII wrappers using unique_ptr
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;
using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter>;
using BIO_ptr = std::unique_ptr<BIO, BIO_Deleter>;
using OSSL_PARAM_ptr = std::unique_ptr<OSSL_PARAM, OSSL_PARAM_Deleter>;
using OSSL_PARAM_BLD_ptr = std::unique_ptr<OSSL_PARAM_BLD, OSSL_PARAM_BLD_Deleter>;
using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter>;
using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter>;
using X509_ptr = std::unique_ptr<X509, X509_Deleter>;

} // namespace internal
} // namespace crypto
} // namespace sum

#endif // SUM_OPENSSL_WRAPPERS_H
