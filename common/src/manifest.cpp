/**
 * @file manifest.cpp
 * @brief Secure Update Manifest implementation (Protocol Buffer based)
 *
 * Clean implementation using protobuf - no JSON backward compatibility.
 *
 * Copyright 2025 libsum contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sum/common/manifest.h"
#include "manifest.pb.h"
#include <glog/logging.h>
#include <google/protobuf/util/json_util.h>
#include <stdexcept>

namespace sum {

// ============================================================================
// SemVer Implementation
// ============================================================================

std::string SemVer::ToString() const {
    std::string result = std::to_string(major) + "." + std::to_string(minor) + "." + std::to_string(patch);
    if (!prerelease.empty()) {
        result += "-" + prerelease;
    }
    if (!build_metadata.empty()) {
        result += "+" + build_metadata;
    }
    return result;
}

int SemVer::Compare(const SemVer& other) const {
    if (major != other.major) return major < other.major ? -1 : 1;
    if (minor != other.minor) return minor < other.minor ? -1 : 1;
    if (patch != other.patch) return patch < other.patch ? -1 : 1;
    return 0;  // Equal (ignoring prerelease/build metadata per semver spec)
}

// ============================================================================
// Conversion Helpers (between public API structs and protobuf messages)
// ============================================================================

namespace {

// Convert public Source struct to protobuf message
void ToProto(const Source& src, ::sum::proto::Source* proto) {
    proto->set_uri(src.uri);
    proto->set_priority(src.priority);
    proto->set_type(src.type);
}

// Convert protobuf message to public Source struct
Source FromProto(const ::sum::proto::Source& proto) {
    Source src;
    src.uri = proto.uri();
    src.priority = proto.priority();
    src.type = proto.type();
    return src;
}

// Convert public SoftwareArtifact struct to protobuf message
void ToProto(const SoftwareArtifact& artifact, ::sum::proto::Artifact* proto) {
    proto->set_name(artifact.name);
    proto->set_type(artifact.type);
    proto->set_target_ecu(artifact.target_ecu);
    proto->set_install_order(artifact.install_order);

    proto->set_hash_algorithm(artifact.hash_algorithm);
    proto->set_expected_hash(artifact.expected_hash.data(), artifact.expected_hash.size());
    proto->set_size(artifact.size);

    proto->set_ciphertext_hash(artifact.ciphertext_hash.data(), artifact.ciphertext_hash.size());
    proto->set_ciphertext_size(artifact.ciphertext_size);

    proto->set_signature_algorithm(artifact.signature_algorithm);
    proto->set_signature(artifact.signature.data(), artifact.signature.size());

    for (const auto& source : artifact.sources) {
        ToProto(source, proto->add_sources());
    }
    proto->set_content_addressable(artifact.content_addressable);
}

// Convert protobuf message to public SoftwareArtifact struct
SoftwareArtifact FromProto(const ::sum::proto::Artifact& proto) {
    SoftwareArtifact artifact;
    artifact.name = proto.name();
    artifact.type = proto.type();
    artifact.target_ecu = proto.target_ecu();
    artifact.install_order = proto.install_order();

    artifact.hash_algorithm = proto.hash_algorithm();
    artifact.expected_hash.assign(proto.expected_hash().begin(), proto.expected_hash().end());
    artifact.size = proto.size();

    artifact.ciphertext_hash.assign(proto.ciphertext_hash().begin(), proto.ciphertext_hash().end());
    artifact.ciphertext_size = proto.ciphertext_size();

    artifact.signature_algorithm = proto.signature_algorithm();
    artifact.signature.assign(proto.signature().begin(), proto.signature().end());

    for (const auto& src_proto : proto.sources()) {
        artifact.sources.push_back(FromProto(src_proto));
    }
    artifact.content_addressable = proto.content_addressable();

    return artifact;
}

// Convert public EncryptionParams struct to protobuf message
void ToProto(const EncryptionParams& params, ::sum::proto::EncryptionParams* proto) {
    proto->set_artifact_name(params.artifact_name);
    proto->set_device_id(params.device_id);

    proto->set_algorithm(params.algorithm);
    proto->set_iv(params.iv.data(), params.iv.size());
    proto->set_tag(params.tag.data(), params.tag.size());

    proto->set_key_wrapping_algorithm(params.key_wrapping_algorithm);
    proto->set_wrapped_key(params.wrapped_key.data(), params.wrapped_key.size());
}

// Convert protobuf message to public EncryptionParams struct
EncryptionParams FromProto(const ::sum::proto::EncryptionParams& proto) {
    EncryptionParams params;
    params.artifact_name = proto.artifact_name();
    params.device_id = proto.device_id();

    params.algorithm = proto.algorithm();
    params.iv.assign(proto.iv().begin(), proto.iv().end());
    params.tag.assign(proto.tag().begin(), proto.tag().end());

    params.key_wrapping_algorithm = proto.key_wrapping_algorithm();
    params.wrapped_key.assign(proto.wrapped_key().begin(), proto.wrapped_key().end());

    return params;
}

} // anonymous namespace

// ============================================================================
// Manifest::Impl - Uses protobuf message internally
// ============================================================================

class Manifest::Impl {
public:
    ::sum::proto::Manifest proto_;  // Internal protobuf representation

    // Cached copies of artifacts/encryption (for public API that returns const ref)
    mutable std::vector<SoftwareArtifact> artifacts_cache_;
    mutable std::vector<EncryptionParams> encryption_cache_;
    mutable bool artifacts_cache_valid_ = false;
    mutable bool encryption_cache_valid_ = false;

    // Cached copies of byte fields (protobuf uses std::string for bytes)
    mutable std::vector<uint8_t> manifest_hash_cache_;
    mutable std::vector<uint8_t> signature_cache_;
    mutable std::vector<uint8_t> signing_cert_cache_;

    void InvalidateCaches() {
        artifacts_cache_valid_ = false;
        encryption_cache_valid_ = false;
    }

    const std::vector<SoftwareArtifact>& GetArtifacts() const {
        if (!artifacts_cache_valid_) {
            artifacts_cache_.clear();
            for (const auto& artifact_proto : proto_.artifacts()) {
                artifacts_cache_.push_back(FromProto(artifact_proto));
            }
            artifacts_cache_valid_ = true;
        }
        return artifacts_cache_;
    }

    const std::vector<EncryptionParams>& GetEncryption() const {
        if (!encryption_cache_valid_) {
            encryption_cache_.clear();
            for (const auto& enc_proto : proto_.encryption()) {
                encryption_cache_.push_back(FromProto(enc_proto));
            }
            encryption_cache_valid_ = true;
        }
        return encryption_cache_;
    }
};

// ============================================================================
// Manifest Implementation
// ============================================================================

Manifest::Manifest() : impl_(std::make_unique<Impl>()) {
    impl_->proto_.set_version(1);  // Current schema version
}

Manifest::~Manifest() = default;

Manifest::Manifest(Manifest&&) noexcept = default;
Manifest& Manifest::operator=(Manifest&&) noexcept = default;

// Serialization

Manifest Manifest::LoadFromProtobuf(const std::vector<uint8_t>& data) {
    Manifest manifest;
    if (!manifest.impl_->proto_.ParseFromArray(data.data(), data.size())) {
        throw std::runtime_error("Failed to parse protobuf manifest");
    }
    manifest.impl_->InvalidateCaches();
    return manifest;
}

std::vector<uint8_t> Manifest::ToProtobuf() const {
    std::vector<uint8_t> result(impl_->proto_.ByteSizeLong());
    if (!impl_->proto_.SerializeToArray(result.data(), result.size())) {
        throw std::runtime_error("Failed to serialize protobuf manifest");
    }
    return result;
}

std::vector<uint8_t> Manifest::ToProtobufForSigning() const {
    // Create a copy without signature field
    ::sum::proto::Manifest proto_copy = impl_->proto_;
    proto_copy.clear_signature();

    std::vector<uint8_t> result(proto_copy.ByteSizeLong());
    if (!proto_copy.SerializeToArray(result.data(), result.size())) {
        throw std::runtime_error("Failed to serialize protobuf manifest for signing");
    }
    return result;
}

std::string Manifest::ToDebugJSON() const {
    std::string json_string;
    google::protobuf::util::JsonPrintOptions options;
    options.add_whitespace = true;
    options.always_print_primitive_fields = true;

    auto status = google::protobuf::util::MessageToJsonString(impl_->proto_, &json_string, options);
    if (!status.ok()) {
        throw std::runtime_error("Failed to convert protobuf to JSON: " + std::string(status.message()));
    }
    return json_string;
}

// Accessors

uint32_t Manifest::GetVersion() const {
    return impl_->proto_.version();
}

uint64_t Manifest::GetManifestVersion() const {
    return impl_->proto_.manifest_version();
}

std::optional<SemVer> Manifest::GetSoftwareVersion() const {
    if (!impl_->proto_.has_software_version()) {
        return std::nullopt;
    }

    const auto& proto_ver = impl_->proto_.software_version();
    SemVer version;
    version.major = proto_ver.major();
    version.minor = proto_ver.minor();
    version.patch = proto_ver.patch();
    version.prerelease = proto_ver.prerelease();
    version.build_metadata = proto_ver.build_metadata();
    return version;
}

uint64_t Manifest::GetReleaseCounter() const {
    return impl_->proto_.release_counter();
}

const std::vector<uint8_t>& Manifest::GetManifestHash() const {
    const std::string& hash_str = impl_->proto_.manifest_hash();
    impl_->manifest_hash_cache_.assign(
        reinterpret_cast<const uint8_t*>(hash_str.data()),
        reinterpret_cast<const uint8_t*>(hash_str.data()) + hash_str.size()
    );
    return impl_->manifest_hash_cache_;
}

const std::vector<SoftwareArtifact>& Manifest::GetArtifacts() const {
    return impl_->GetArtifacts();
}

const std::vector<EncryptionParams>& Manifest::GetEncryptionParams() const {
    return impl_->GetEncryption();
}

const std::vector<uint8_t>& Manifest::GetSignature() const {
    const std::string& sig_str = impl_->proto_.signature();
    impl_->signature_cache_.assign(
        reinterpret_cast<const uint8_t*>(sig_str.data()),
        reinterpret_cast<const uint8_t*>(sig_str.data()) + sig_str.size()
    );
    return impl_->signature_cache_;
}

const std::vector<uint8_t>& Manifest::GetSigningCertificate() const {
    const std::string& cert_str = impl_->proto_.signing_cert();
    impl_->signing_cert_cache_.assign(
        reinterpret_cast<const uint8_t*>(cert_str.data()),
        reinterpret_cast<const uint8_t*>(cert_str.data()) + cert_str.size()
    );
    return impl_->signing_cert_cache_;
}

std::optional<std::string> Manifest::GetMetadata(const std::string& key) const {
    const auto& metadata_map = impl_->proto_.metadata();
    auto it = metadata_map.find(key);
    if (it != metadata_map.end()) {
        return it->second;
    }
    return std::nullopt;
}

const SoftwareArtifact* Manifest::GetArtifactByName(const std::string& name) const {
    const auto& artifacts = GetArtifacts();
    for (const auto& artifact : artifacts) {
        if (artifact.name == name) {
            return &artifact;
        }
    }
    return nullptr;
}

std::optional<size_t> Manifest::GetArtifactIndex(const std::string& name) const {
    const auto& artifacts = GetArtifacts();
    for (size_t i = 0; i < artifacts.size(); i++) {
        if (artifacts[i].name == name) {
            return i;
        }
    }
    return std::nullopt;
}

const EncryptionParams* Manifest::GetEncryptionParamsFor(
    const std::string& artifact_name,
    const std::string& device_id
) const {
    const auto& encryption = GetEncryptionParams();
    for (const auto& params : encryption) {
        if (params.artifact_name == artifact_name && params.device_id == device_id) {
            return &params;
        }
    }
    return nullptr;
}

// Mutators

void Manifest::SetManifestVersion(uint64_t version) {
    impl_->proto_.set_manifest_version(version);
}

void Manifest::SetSoftwareVersion(const SemVer& version) {
    auto* proto_ver = impl_->proto_.mutable_software_version();
    proto_ver->set_major(version.major);
    proto_ver->set_minor(version.minor);
    proto_ver->set_patch(version.patch);
    proto_ver->set_prerelease(version.prerelease);
    proto_ver->set_build_metadata(version.build_metadata);
}

void Manifest::SetReleaseCounter(uint64_t counter) {
    impl_->proto_.set_release_counter(counter);
}

void Manifest::SetManifestHash(const std::vector<uint8_t>& hash) {
    impl_->proto_.set_manifest_hash(hash.data(), hash.size());
}

void Manifest::AddArtifact(SoftwareArtifact artifact) {
    ToProto(artifact, impl_->proto_.add_artifacts());
    impl_->InvalidateCaches();
}

void Manifest::AddEncryptionParams(EncryptionParams params) {
    ToProto(params, impl_->proto_.add_encryption());
    impl_->InvalidateCaches();
}

void Manifest::SetSignature(const std::vector<uint8_t>& signature) {
    impl_->proto_.set_signature(signature.data(), signature.size());
}

void Manifest::SetSigningCertificate(const std::vector<uint8_t>& cert) {
    impl_->proto_.set_signing_cert(cert.data(), cert.size());
}

void Manifest::SetMetadata(const std::string& key, const std::string& value) {
    (*impl_->proto_.mutable_metadata())[key] = value;
}

// ============================================================================
// DeviceMetadata Implementation
// ============================================================================

DeviceMetadata DeviceMetadata::FromProtobuf(const std::vector<uint8_t>& data) {
    ::sum::proto::DeviceMetadata proto;
    if (!proto.ParseFromArray(data.data(), data.size())) {
        throw std::runtime_error("Failed to parse DeviceMetadata protobuf");
    }

    DeviceMetadata metadata;
    metadata.hardware_id = proto.hardware_id();
    metadata.manufacturer = proto.manufacturer();
    metadata.device_type = proto.device_type();
    metadata.hardware_version = proto.hardware_version();
    return metadata;
}

std::vector<uint8_t> DeviceMetadata::ToProtobuf() const {
    ::sum::proto::DeviceMetadata proto;
    proto.set_hardware_id(hardware_id);
    proto.set_manufacturer(manufacturer);
    proto.set_device_type(device_type);
    if (!hardware_version.empty()) {
        proto.set_hardware_version(hardware_version);
    }

    std::vector<uint8_t> data(proto.ByteSizeLong());
    if (!proto.SerializeToArray(data.data(), data.size())) {
        throw std::runtime_error("Failed to serialize DeviceMetadata protobuf");
    }
    return data;
}

} // namespace sum
