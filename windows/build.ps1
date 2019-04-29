param(
	[string]$CMakePath = "C:\Program Files\CMake\bin\cmake.exe",
	[string]$GitPath = "C:\Program Files\Git\bin\git.exe",
	[string]$SevenZPath = "C:\Program Files\7-Zip\7z.exe",
	[string]$GPGPath = "C:\Program Files (x86)\GnuPG\bin\gpg.exe"
)

# LibreSSL coordinates.
New-Variable -Name 'LIBRESSL_URL' `
	-Value 'https://ftp.openbsd.org/pub/OpenBSD/LibreSSL' -Option Constant
New-Variable -Name 'LIBRESSL' -Value 'libressl-2.9.1' -Option Constant

# libcbor coordinates.
New-Variable -Name 'LIBCBOR' -Value 'libcbor-0.5.0' -Option Constant
New-Variable -Name 'LIBCBOR_BRANCH' -Value 'v0.5.0' -Option Constant
New-Variable -Name 'LIBCBOR_GIT' -Value 'https://github.com/pjk/libcbor' `
	-Option Constant

# Work directories.
New-Variable -Name 'BUILD' -Value "$PSScriptRoot\..\build" -Option Constant
New-Variable -Name 'OUTPUT' -Value "$PSScriptRoot\..\output" -Option Constant

# Find CMake.
$CMake = $(Get-Command cmake -ErrorAction Ignore | Select-Object -ExpandProperty Source)
if([string]::IsNullOrEmpty($CMake)) {
	$CMake = $CMakePath
}

# Find Git.
$Git = $(Get-Command git -ErrorAction Ignore | Select-Object -ExpandProperty Source)
if([string]::IsNullOrEmpty($Git)) {
	$Git = $GitPath
}

# Find 7z.
$SevenZ = $(Get-Command 7z -ErrorAction Ignore | Select-Object -ExpandProperty Source)
if([string]::IsNullOrEmpty($SevenZ)) {
	$SevenZ = $SevenZPath
}

# Find GPG.
$GPG = $(Get-Command gpg -ErrorAction Ignore | Select-Object -ExpandProperty Source)
if([string]::IsNullOrEmpty($GPG)) {
	$GPG = $GPGPath
}

if(-Not (Test-Path $CMake)) {
	throw "Unable to find CMake at $CMake"
}

if(-Not (Test-Path $Git)) {
	throw "Unable to find Git at $Git"
}

if(-Not (Test-Path $SevenZ)) {
	throw "Unable to find 7z at $SevenZ"
}

if(-Not (Test-Path $GPG)) {
	throw "Unable to find GPG at $GPG"
}

Write-Host "Git: $Git"
Write-Host "CMake: $CMake"
Write-Host "7z: $SevenZ"
Write-Host "GPG: $GPG"

New-Item -Type Directory ${BUILD} -ErrorAction Ignore
New-Item -Type Directory ${OUTPUT} -ErrorAction Ignore

Push-Location ${BUILD}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
	Write-Host "Building LibreSSL..."

	# Fetch, verify, and unpack LibreSSL.
	if(-Not (Test-Path ${LIBRESSL})) {
		Invoke-WebRequest `
			${LIBRESSL_URL}/${LIBRESSL}.tar.gz `
			-OutFile .\${LIBRESSL}.tar.gz
		& Invoke-WebRequest `
			${LIBRESSL_URL}/${LIBRESSL}.tar.gz.asc `
			-OutFile .\${LIBRESSL}.tar.gz.asc
		& Copy-Item "$PSScriptRoot\libressl.gpg" -Destination "${BUILD}"
		& $GPG --list-keys
		& $GPG -v --no-default-keyring --keyring ./libressl.gpg `
			--verify .\${LIBRESSL}.tar.gz.asc .\${LIBRESSL}.tar.gz
		if ($LastExitCode -ne 0) {
			throw "gpg signature verification failed"
		}
		& $SevenZ e .\${LIBRESSL}.tar.gz
		& $SevenZ x .\${LIBRESSL}.tar
		Remove-Item -Force .\${LIBRESSL}.tar.gz
		Remove-Item -Force .\${LIBRESSL}.tar
	}

	# Build LibreSSL.
	if(-Not (Test-Path .\${LIBRESSL}\build)) {
		New-Item -Type Directory .\${LIBRESSL}\build
	}
	Push-Location .\${LIBRESSL}\build
	& $CMake .. -G "Visual Studio 15 2017 Win64" `
		-DCMAKE_C_FLAGS_RELEASE="/Zi" `
		-DCMAKE_INSTALL_PREFIX="${OUTPUT}" -DBUILD_SHARED_LIBS=ON `
		-DLIBRESSL_TESTS=OFF
	& $CMake --build . --config Release
	& $CMake --build . --config Release --target install
	Pop-Location

	Write-Host "Building libcbor..."

	# Fetch libcbor; XXX no signature verification possible
	if(-Not (Test-Path libcbor)) {
		& $Git clone --branch ${LIBCBOR_BRANCH} ${LIBCBOR_GIT}
	}

	# Build libcbor.
	if(-Not (Test-Path .\libcbor\build)) {
		New-Item -Type Directory .\libcbor\build
	}
	Push-Location libcbor\build
	& $CMake .. -G "Visual Studio 15 2017 Win64" `
		-DCMAKE_C_FLAGS_RELEASE="/Zi" `
		-DCMAKE_INSTALL_PREFIX="${OUTPUT}"
	& $CMake --build . --config Release
	& $CMake --build . --config Release --target install
	Pop-Location

	Write-Host "Building libfido2..."
	& $CMake .. -G "Visual Studio 15 2017 Win64" `
		-DCBOR_INCLUDE_DIRS="${OUTPUT}\include" `
		-DCBOR_LIBRARY_DIRS="${OUTPUT}\lib" `
		-DCRYPTO_INCLUDE_DIRS="${OUTPUT}\include" `
		-DCRYPTO_LIBRARY_DIRS="${OUTPUT}\lib" `
		-DCMAKE_INSTALL_PREFIX="${OUTPUT}"
	& $CMake --build . --config Release
	& $CMake --build . --config Release --target install
	& Copy-Item "${OUTPUT}\bin\cbor.dll" `
		-Destination "${BUILD}\examples\Release"
	& Copy-Item "${OUTPUT}\bin\crypto-45.dll" `
		-Destination "${BUILD}\examples\Release"
} finally {
	Pop-Location
}
