/**
 * @file secure_vector.h
 * @brief Secure vector container that zeros memory on destruction
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <cstdint>
#include <vector>
#include <cstring>
#include <algorithm>

namespace sum {
namespace crypto {

/**
 * @brief Vector container that zeros memory on destruction
 *
 * Use this for storing sensitive data like cryptographic keys, plaintext,
 * nonces, and other secrets. The memory is securely erased when the object
 * is destroyed to prevent information leakage through memory dumps, swap,
 * or core files.
 *
 * This is a thin wrapper around std::vector with secure erasure.
 *
 * @tparam T Element type (typically uint8_t)
 */
template<typename T = uint8_t>
class SecureVector {
private:
    std::vector<T> data_;

    /**
     * @brief Securely zero memory
     *
     * Uses platform-specific secure memory clearing:
     * - Linux/BSD/macOS: explicit_bzero (if available) or manual clearing
     * - Windows: SecureZeroMemory
     * - Fallback: volatile pointer technique to prevent compiler optimization
     */
    void secure_zero() {
        if (data_.empty()) {
            return;
        }

        size_t size = data_.size() * sizeof(T);
        void* ptr = data_.data();

#if defined(_WIN32)
        // Windows: Use SecureZeroMemory
        SecureZeroMemory(ptr, size);
#elif defined(__GLIBC__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 25
        // glibc 2.25+ has explicit_bzero
        explicit_bzero(ptr, size);
#elif defined(__OpenBSD__) || defined(__FreeBSD__)
        // BSD systems have explicit_bzero
        explicit_bzero(ptr, size);
#else
        // Fallback: Use volatile pointer to prevent compiler optimization
        // This ensures memset is not optimized away
        volatile unsigned char* volatile_ptr = static_cast<volatile unsigned char*>(ptr);
        for (size_t i = 0; i < size; ++i) {
            volatile_ptr[i] = 0;
        }

        // Memory barrier to prevent reordering
        __asm__ __volatile__("" ::: "memory");
#endif
    }

public:
    // Constructors
    SecureVector() = default;

    explicit SecureVector(size_t size) : data_(size) {}

    SecureVector(size_t size, const T& value) : data_(size, value) {}

    template<typename InputIt>
    SecureVector(InputIt first, InputIt last) : data_(first, last) {}

    SecureVector(std::initializer_list<T> init) : data_(init) {}

    // Destructor - securely zeros memory
    ~SecureVector() {
        secure_zero();
    }

    // Copy constructor - creates a copy of sensitive data
    SecureVector(const SecureVector& other) : data_(other.data_) {}

    // Copy assignment
    SecureVector& operator=(const SecureVector& other) {
        if (this != &other) {
            secure_zero();  // Zero old data before overwriting
            data_ = other.data_;
        }
        return *this;
    }

    // Move constructor
    SecureVector(SecureVector&& other) noexcept : data_(std::move(other.data_)) {
        // other.data_ is now empty, so its destructor won't zero anything meaningful
    }

    // Move assignment
    SecureVector& operator=(SecureVector&& other) noexcept {
        if (this != &other) {
            secure_zero();  // Zero old data before overwriting
            data_ = std::move(other.data_);
        }
        return *this;
    }

    // Conversion from std::vector
    explicit SecureVector(const std::vector<T>& vec) : data_(vec) {}
    explicit SecureVector(std::vector<T>&& vec) : data_(std::move(vec)) {}

    // Conversion to std::vector (creates a copy)
    std::vector<T> to_vector() const {
        return data_;
    }

    // Vector interface methods
    T* data() { return data_.data(); }
    const T* data() const { return data_.data(); }

    size_t size() const { return data_.size(); }
    bool empty() const { return data_.empty(); }

    void resize(size_t size) { data_.resize(size); }
    void resize(size_t size, const T& value) { data_.resize(size, value); }
    void reserve(size_t capacity) { data_.reserve(capacity); }
    void clear() {
        secure_zero();
        data_.clear();
    }

    void push_back(const T& value) { data_.push_back(value); }
    void push_back(T&& value) { data_.push_back(std::move(value)); }

    template<typename... Args>
    void emplace_back(Args&&... args) {
        data_.emplace_back(std::forward<Args>(args)...);
    }

    // Element access
    T& operator[](size_t index) { return data_[index]; }
    const T& operator[](size_t index) const { return data_[index]; }

    T& at(size_t index) { return data_.at(index); }
    const T& at(size_t index) const { return data_.at(index); }

    // Iterators
    typename std::vector<T>::iterator begin() { return data_.begin(); }
    typename std::vector<T>::const_iterator begin() const { return data_.begin(); }
    typename std::vector<T>::iterator end() { return data_.end(); }
    typename std::vector<T>::const_iterator end() const { return data_.end(); }

    // Comparison operators
    bool operator==(const SecureVector& other) const {
        return data_ == other.data_;
    }

    bool operator!=(const SecureVector& other) const {
        return data_ != other.data_;
    }

    // Comparison with std::vector
    bool operator==(const std::vector<T>& other) const {
        return data_ == other;
    }

    bool operator!=(const std::vector<T>& other) const {
        return data_ != other;
    }

    // Friend functions for reverse comparison (std::vector == SecureVector)
    friend bool operator==(const std::vector<T>& lhs, const SecureVector<T>& rhs) {
        return lhs == rhs.data_;
    }

    friend bool operator!=(const std::vector<T>& lhs, const SecureVector<T>& rhs) {
        return lhs != rhs.data_;
    }
};

} // namespace crypto
} // namespace sum
