param(
    [string]$CMakePath = "C:\Program Files\CMake\bin\cmake.exe",
    [string]$GitPath = "C:\Program Files\Git\bin\git.exe",
    [string]$7zPath
)

$CMake = ($(Get-Command cmake -ErrorAction Ignore | Select-Object -ExpandProperty Source), $CMakePath -ne $null)[0]
$Git = ($(Get-Command git -ErrorAction Ignore | Select-Object -ExpandProperty Source), $GitPath -ne $null)[0]
$7z = $(Get-Command 7z -ErrorAction Ignore | Select-Object -ExpandProperty Source)
if($null -eq $7z -and $null -eq $7zPath) {
    throw "Unable to locate 7z.exe"
} elseif($null -eq $7z) {
    $7z = $7zPath
}

if(-Not (Test-Path $CMake)) {
    throw "Unable to find CMake at $CMake"
}

if(-Not (Test-Path $Git)) {
    throw "Unable to find Git at $Git"
}

if(-Not (Test-Path $7z)) {
    throw "Unable to find 7z at $7z"
}

Write-Host "Git: $Git"
Write-Host "CMake: $CMake"
Write-Host "7z: $7z"

New-Item -Type Directory $PSScriptRoot\..\build -ErrorAction Ignore
New-Item -Type Directory $PSScriptRoot\..\output -ErrorAction Ignore
New-Item -Type Directory $PSScriptRoot\..\output\libressl-2.8.3-Win64 -ErrorAction Ignore
New-Item -Type Directory $PSScriptRoot\..\output\libcbor-0.5.0-Win64 -ErrorAction Ignore
New-Item -Type Directory $PSScriptRoot\..\output\libfido2-Win64 -ErrorAction Ignore

Push-Location $PSScriptRoot\..\build

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    Write-Host "Building LibreSSL..."
    if(-Not (Test-Path libressl-2.8.3)) {
        Invoke-WebRequest https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.8.3.tar.gz -OutFile libressl-2.8.3.tar.gz 
        & $7z e .\libressl-2.8.3.tar.gz 
        & $7z x .\libressl-2.8.3.tar
        Remove-Item -Force .\libressl-2.8.3.tar.gz
        Remove-Item -Force .\libressl-2.8.3.tar
    }

    if(-Not (Test-Path .\libressl-2.8.3\build)) {
        New-Item -Type Directory .\libressl-2.8.3\build
    }

    Push-Location libressl-2.8.3\build
    & $CMake .. -G "Visual Studio 15 2017 Win64" -DCMAKE_INSTALL_PREFIX="$PSScriptRoot\..\output\libressl-2.8.3-Win64" -DBUILD_SHARED_LIBS=ON
    & $CMake --build . --config Release
    & $CMake --build . --config Release --target install
    Pop-Location

    Write-host "Building libcbor..."
    if(-Not (Test-Path libcbor)) {
        & $Git clone --branch v0.5.0 https://github.com/pjk/libcbor
    }

    if(-Not (Test-Path .\libcbor\build)) {
        New-Item -Type Directory .\libcbor\build
    }

    Push-Location libcbor\build
    & $CMake .. -G "Visual Studio 15 2017 Win64" -DCMAKE_INSTALL_PREFIX="$PSScriptRoot\..\output\libcbor-0.5.0-Win64"
    & $CMake --build . --config Release
    & $CMake --build . --config Release --target install
    Pop-Location

    Write-Host "Building libfido2..."
    & $CMake .. -G "Visual Studio 15 2017 Win64" -DCBOR_INCLUDE_DIRS="$PSScriptRoot\..\output\libcbor-0.5.0-Win64\include" -DCBOR_LIBRARY_DIRS="$PSScriptRoot\..\output\libcbor-0.5.0-Win64\lib" -DCRYPTO_INCLUDE_DIRS="$PSScriptRoot\..\output\libressl-2.8.3-Win64\include" -DCRYPTO_LIBRARY_DIRS="$PSScriptRoot\..\output\libressl-2.8.3-Win64\lib" -DCMAKE_INSTALL_PREFIX="$PSScriptRoot\..\output\libfido2-Win64"
    & $CMake --build . --config Release
    & $CMake --build . --config Release --target install
} finally {
    Pop-Location
}