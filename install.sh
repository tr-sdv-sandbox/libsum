#!/bin/bash
set -e

echo "Installing libsum dependencies..."

# Update package list
sudo apt-get update

# Install build tools
sudo apt-get install -y \
    build-essential \
    cmake \
    git

# Install OpenSSL 3.x development libraries
sudo apt-get install -y \
    libssl-dev \
    openssl

# Install Google Log (glog)
sudo apt-get install -y \
    libgoogle-glog-dev

# Install nlohmann-json
sudo apt-get install -y \
    nlohmann-json3-dev

# Install Google Test
sudo apt-get install -y \
    libgtest-dev \
    googletest

echo "All dependencies installed successfully!"
echo ""
echo "To build libsum:"
echo "  mkdir build && cd build"
echo "  cmake .."
echo "  make"
echo "  sudo make install"
