#!/bin/bash
#
# Integration test for sum-generate and sum-verify tools
# Tests complete certificate-based update workflow
#
# Copyright 2025 libsum contributors
# SPDX-License-Identifier: Apache-2.0

set -e  # Exit on error

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_DIR="${SCRIPT_DIR}/../../build"
TOOLS_DIR="${BUILD_DIR}/tools"
TEST_DIR="${BUILD_DIR}/test-tools-integration"

echo "=== libsum Tools Integration Test ==="
echo ""

# Create clean test directory
rm -rf "${TEST_DIR}"
mkdir -p "${TEST_DIR}"
cd "${TEST_DIR}"

echo "Working directory: $(pwd)"
echo ""

# Step 1: Generate CA key pair
echo "Step 1: Generating CA key pair..."
${BUILD_DIR}/backend/sum-keygen --output ca.key > /dev/null 2>&1
${BUILD_DIR}/backend/sum-keygen --public ca.key --output ca.pub > /dev/null 2>&1
echo "  ✅ CA keys created"

# Step 2: Create root CA certificate
echo "Step 2: Creating root CA certificate..."
${BUILD_DIR}/backend/sum-create-ca \
  --ca-key ca.key \
  --subject-key ca.pub \
  --common-name "Test Root CA" \
  --output ca.crt > /dev/null 2>&1
echo "  ✅ Root CA certificate created"

# Step 2.5: Create intermediate CA (PRODUCTION BEST PRACTICE)
echo "Step 2.5: Creating intermediate CA..."
${BUILD_DIR}/backend/sum-keygen --type ed25519 --output intermediate.key > /dev/null 2>&1
${BUILD_DIR}/backend/sum-keygen --public intermediate.key --output intermediate.pub > /dev/null 2>&1
${BUILD_DIR}/backend/sum-create-ca \
  --ca-key ca.key \
  --subject-key intermediate.pub \
  --common-name "Test Intermediate CA" \
  --sign-with ca.crt \
  --output intermediate.crt > /dev/null 2>&1
echo "  ✅ Intermediate CA certificate created (signed by root CA)"

# Step 3: Generate device key pair (X25519 for encryption)
echo "Step 3: Generating device key pair..."
${BUILD_DIR}/backend/sum-keygen --type x25519 --output device.key > /dev/null 2>&1
${BUILD_DIR}/backend/sum-keygen --public device.key --output device.pub > /dev/null 2>&1
echo "  ✅ Device keys created"

# Step 4: Create test firmware
echo "Step 4: Creating test firmware..."
echo "Test firmware v1.0 - Integration Test" > firmware.bin
ORIGINAL_SIZE=$(stat -c%s firmware.bin)
echo "  ✅ Test firmware created (${ORIGINAL_SIZE} bytes)"

# Step 5: Generate update certificate chain (using intermediate CA)
echo "Step 5: Generating update certificate chain (PEM bundle)..."
${BUILD_DIR}/backend/sum-generate \
  --software firmware.bin \
  --device-pubkey device.pub \
  --backend-key intermediate.key \
  --backend-cert intermediate.crt \
  --hardware-id DEVICE-TEST-12345 \
  --manufacturer "Integration Test Corp" \
  --device-type "TestDevice" \
  --hardware-version "v1.0" \
  --artifact-name firmware \
  --artifact-type firmware \
  --target-ecu primary \
  --sw-version "1.0.0" \
  --sw-security-version 42 \
  --manifest-version 1 \
  --validity-days 90 \
  --output update.crt \
  --encrypted-output firmware.enc > /dev/null 2>&1

if [ ! -f update.crt ] || [ ! -f firmware.enc ]; then
    echo "  ❌ Failed to generate certificate chain"
    exit 1
fi
echo "  ✅ Certificate chain generated: update.crt (PEM bundle)"
echo "      Contains: update cert + intermediate cert"

# Step 6: Verify and decrypt update
echo "Step 6: Verifying certificate and decrypting..."
${BUILD_DIR}/client/sum-verify \
  --certificate update.crt \
  --encrypted-software firmware.enc \
  --device-key device.key \
  --backend-ca ca.crt \
  --output firmware_decrypted.bin > /dev/null 2>&1

if [ ! -f firmware_decrypted.bin ]; then
    echo "  ❌ Failed to decrypt firmware"
    exit 1
fi
echo "  ✅ Firmware decrypted successfully"

# Step 7: Verify decrypted matches original
echo "Step 7: Verifying integrity..."
if ! diff -q firmware.bin firmware_decrypted.bin > /dev/null; then
    echo "  ❌ Decrypted firmware does not match original!"
    exit 1
fi
DECRYPTED_SIZE=$(stat -c%s firmware_decrypted.bin)
echo "  ✅ Decrypted firmware matches original (${DECRYPTED_SIZE} bytes)"

# Step 8: Test metadata extraction (including operational fields)
echo "Step 8: Testing device metadata extraction..."
METADATA=$(${BUILD_DIR}/client/sum-inspect --cert update.crt --json)
echo "$METADATA" | grep -q "DEVICE-TEST-12345" || { echo "  ❌ Wrong hardware_id"; exit 1; }
echo "$METADATA" | grep -q "Integration Test Corp" || { echo "  ❌ Wrong manufacturer"; exit 1; }
echo "$METADATA" | grep -q "TestDevice" || { echo "  ❌ Wrong device_type"; exit 1; }
echo "  ✅ Basic device metadata extraction successful"

echo "Step 8b: Verifying operational metadata fields..."
# Verify manifest_version is present and correct
echo "$METADATA" | grep -q "Manifest Version:.*1" || { echo "  ❌ Wrong manifest_version"; exit 1; }

# Verify manifest_type is FULL
echo "$METADATA" | grep -q "Manifest Type:.*FULL" || { echo "  ❌ Wrong manifest_type"; exit 1; }

# Verify provides array contains artifact info
echo "$METADATA" | grep -q "Provides.*1 artifact" || { echo "  ❌ Missing provides array"; exit 1; }
echo "$METADATA" | grep -q "firmware@primary" || { echo "  ❌ Wrong artifact in provides"; exit 1; }
echo "$METADATA" | grep -q "Security Version: 42" || { echo "  ❌ Wrong security version in provides"; exit 1; }
echo "$METADATA" | grep -q "Version: 1.0.0" || { echo "  ❌ Wrong version in provides"; exit 1; }

echo "  ✅ Operational metadata fields verified (manifest_version, manifest_type, provides)"

# Step 9: Test wrong device key
echo "Step 9: Testing wrong device key rejection..."
${BUILD_DIR}/backend/sum-keygen --type x25519 --output wrong_device.key > /dev/null 2>&1

if ${BUILD_DIR}/client/sum-verify \
  --certificate update.crt \
  --encrypted-software firmware.enc \
  --device-key wrong_device.key \
  --backend-ca ca.crt \
  --output firmware_wrong.bin > /dev/null 2>&1; then
    echo "  ❌ Wrong device key was accepted!"
    exit 1
fi
echo "  ✅ Wrong device key correctly rejected"

# Cleanup
echo ""
echo "Cleaning up..."
cd ..
rm -rf "${TEST_DIR}"

echo ""
echo "=== All Tests Passed ✅ ==="
echo ""
exit 0
