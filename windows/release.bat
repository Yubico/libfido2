set "PATH=%PATH%;C:\Program Files\Git\bin"
set "PATH=%PATH%;C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\MSBuild\15.0\Bin"
set "PATH=%PATH%;C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
set "PATH=%PATH%;C:\Program Files (x86)\Windows Kits\8.1\bin\x64"

mkdir C:\workdir
cd /d C:\workdir

echo "building libressl"
cd C:\workdir
curl -LO https://ftp.eu.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.8.3.tar.gz
tar -zxvf libressl-2.8.3.tar.gz
cd C:\workdir\libressl-2.8.3
mkdir build
cd build
cmake .. -G "Visual Studio 15 2017 Win64" -DCMAKE_INSTALL_PREFIX=C:\workdir\libressl-2.8.3-Win64 -DBUILD_SHARED_LIBS=ON
cmake --build .
cmake --build . --target install

echo "building libcbor"
git clone --branch v0.5.0 https://github.com/pjk/libcbor C:\workdir\libcbor
cd C:\workdir\libcbor
mkdir build
cd build
cmake .. -G "Visual Studio 15 2017 Win64" -DCMAKE_INSTALL_PREFIX=C:\workdir\libcbor-0.5.0-Win64
cmake --build .
cmake --build . --target install

echo "building libfido2"
cd C:\projects\libfido2
mkdir build
cd build
cmake .. -G "Visual Studio 15 2017 Win64" -DCBOR_INCLUDE_DIRS=C:\workdir\libcbor-0.5.0-Win64\include -DCBOR_LIBRARY_DIRS=C:\workdir\libcbor-0.5.0-Win64\lib -DCRYPTO_INCLUDE_DIRS=C:\workdir\libressl-2.8.3-Win64\include -DCRYPTO_LIBRARY_DIRS=C:\workdir\libressl-2.8.3-Win64\lib -DCMAKE_INSTALL_PREFIX=C:\workdir\libfido2-Win64
cmake --build .
cmake --build . --target install

echo "copying dependencies"
copy C:\workdir\libcbor-0.5.0-Win64\lib\cbor.lib C:\workdir\libfido2-Win64\lib
copy C:\workdir\libressl-2.8.3-Win64\lib\crypto-44.lib C:\workdir\libfido2-Win64\lib
