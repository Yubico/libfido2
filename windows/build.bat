set "PATH=%PATH%;C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\MSBuild\15.0\Bin"

echo "building hidapi"
git clone --branch hidapi-0.8.0-rc1 https://github.com/signal11/hidapi C:\hidapi-Win64
copy /y C:\projects\libfido2\windows\* C:\hidapi-Win64\windows
MSBuild C:\hidapi-Win64\windows\hidapi.sln /property:Configuration=Debug /property:Platform=x64

echo "building libcbor"
git clone --branch v0.5.0 https://github.com/pjk/libcbor C:\libcbor
cd C:\libcbor
mkdir build
cd build
cmake .. -G "Visual Studio 15 2017 Win64" -DCMAKE_INSTALL_PREFIX=C:\libcbor-0.5.0-Win64
cmake --build .
cmake --build . --target install

echo "building libfido2"
cd C:\projects\libfido2
mkdir build
cd build
cmake .. -G "Visual Studio 15 2017 Win64" -DCBOR_INCLUDE_DIRS=C:\libcbor-0.5.0-Win64\include -DCBOR_LIBRARY_DIRS=C:\libcbor-0.5.0-Win64\lib -DCRYPTO_INCLUDE_DIRS=C:\OpenSSL-v11-Win64\include -DCRYPTO_LIBRARY_DIRS=C:\OpenSSL-v11-Win64\lib -DHIDAPI_INCLUDE_DIRS=C:\hidapi-Win64\hidapi -DHIDAPI_LIBRARY_DIRS=C:\hidapi-Win64\windows\x64\Debug -DCMAKE_INSTALL_PREFIX=C:\libfido2-Win64
cmake --build .
cmake --build . --target install
