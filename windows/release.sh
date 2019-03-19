#!/bin/bash -eux

CMAKE=$(realpath '/mnt/c/Program Files (x86)/Microsoft Visual Studio/2017/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/')
export PATH=${PATH}:"${CMAKE}"

cd ~
rm -rf /mnt/c/stage /mnt/c/root /mnt/c/release
mkdir -p /mnt/c/stage /mnt/c/root /mnt/c/release

# libressl
cd /mnt/c/stage
curl -LO https://ftp.eu.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.8.3.tar.gz
curl -LO https://ftp.eu.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.8.3.tar.gz.asc
gpg --verify libressl-2.8.3.tar.gz.asc
tar -zxf libressl-2.8.3.tar.gz
cd libressl-2.8.3
mkdir build
cd build
cmake.exe -DCMAKE_INSTALL_PREFIX=/root -DBUILD_SHARED_LIBS=ON ..
cmake.exe --build .
cmake.exe --build . --target install

# libcbor
# XXX no signature verification possible
cd /mnt/c/stage
git clone https://github.com/pjk/libcbor libcbor-0.5.0
cd libcbor-0.5.0
git checkout v0.5.0
mkdir build
cd build
cmake.exe -DCMAKE_INSTALL_PREFIX=/root ..
cmake.exe --build .
cmake.exe --build . --target install

# libfido2
cd /mnt/c/stage
git clone https://github.com/yubico/libfido2
cd libfido2
mkdir build
cd build
cmake.exe -DCBOR_INCLUDE_DIRS=/root/include -DCBOR_LIBRARY_DIRS=/root/lib \
	-DCRYPTO_INCLUDE_DIRS=/root/include -DCRYPTO_LIBRARY_DIRS=/root/lib \
	-DCMAKE_INSTALL_PREFIX=/release ..
cmake.exe --build .
cmake.exe --build . --target install

cp /mnt/c/root/lib/cbor.lib /mnt/c/release/lib
cp /mnt/c/root/lib/crypto-44.lib /mnt/c/release/lib
