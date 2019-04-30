param(
	[string]$CMakePath = "C:\Program Files\CMake\bin\cmake.exe",
	[string]$GitPath = "C:\Program Files\Git\bin\git.exe",
	[string]$SevenZPath = "C:\Program Files\7-Zip\7z.exe",
	[string]$GPGPath = "C:\Program Files (x86)\GnuPG\bin\gpg.exe"
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

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
New-Item -Type Directory ${BUILD}/32 -ErrorAction Ignore
New-Item -Type Directory ${BUILD}/64 -ErrorAction Ignore
New-Item -Type Directory ${OUTPUT} -ErrorAction Ignore

Push-Location ${BUILD}

try {
	if (Test-Path .\${LIBRESSL}) {
		Remove-Item .\${LIBRESSL} -Recurse
	}

	if(-Not (Test-Path .\${LIBRESSL}.tar.gz -PathType leaf)) {
		Invoke-WebRequest ${LIBRESSL_URL}/${LIBRESSL}.tar.gz `
			-OutFile .\${LIBRESSL}.tar.gz
	}
	if(-Not (Test-Path .\${LIBRESSL}.tar.gz.asc -PathType leaf)) {
		Invoke-WebRequest ${LIBRESSL_URL}/${LIBRESSL}.tar.gz.asc `
			-OutFile .\${LIBRESSL}.tar.gz.asc
	}

	Copy-Item "$PSScriptRoot\libressl.gpg" -Destination "${BUILD}"
	& $GPG --list-keys
	& $GPG -v --no-default-keyring --keyring ./libressl.gpg `
		--verify .\${LIBRESSL}.tar.gz.asc .\${LIBRESSL}.tar.gz
	if ($LastExitCode -ne 0) {
		throw "GPG signature verification failed"
	}

	& $SevenZ e .\${LIBRESSL}.tar.gz
	& $SevenZ x .\${LIBRESSL}.tar
	Remove-Item -Force .\${LIBRESSL}.tar

	if(-Not (Test-Path .\${LIBCBOR})) {
		Write-Host "Cloning ${LIBCBOR}..."
		& $Git clone --branch ${LIBCBOR_BRANCH} ${LIBCBOR_GIT} `
			.\${LIBCBOR}
	}
} finally {
	Pop-Location
}

Function Build(${OUTPUT}, ${GENERATOR}) {
	if(-Not (Test-Path .\${LIBRESSL})) {
		New-Item -Type Directory .\${LIBRESSL}
	}

	Push-Location .\${LIBRESSL}
	& $CMake ..\..\${LIBRESSL} -G "${GENERATOR}" `
		-DCMAKE_C_FLAGS_RELEASE="/Zi" `
		-DCMAKE_INSTALL_PREFIX="${OUTPUT}" -DBUILD_SHARED_LIBS=ON `
		-DLIBRESSL_TESTS=OFF
	& $CMake --build . --config Release
	& $CMake --build . --config Release --target install
	Pop-Location

	if(-Not (Test-Path .\${LIBCBOR})) {
		New-Item -Type Directory .\${LIBCBOR}
	}

	Push-Location .\${LIBCBOR}
	& $CMake ..\..\${LIBCBOR} -G "${GENERATOR}" `
		-DCMAKE_C_FLAGS_RELEASE="/Zi" `
		-DCMAKE_INSTALL_PREFIX="${OUTPUT}"
	& $CMake --build . --config Release
	& $CMake --build . --config Release --target install
	Pop-Location

	& $CMake ..\.. -G "${GENERATOR}" `
		-DCBOR_INCLUDE_DIRS="${OUTPUT}\include" `
		-DCBOR_LIBRARY_DIRS="${OUTPUT}\lib" `
		-DCRYPTO_INCLUDE_DIRS="${OUTPUT}\include" `
		-DCRYPTO_LIBRARY_DIRS="${OUTPUT}\lib" `
		-DCMAKE_INSTALL_PREFIX="${OUTPUT}"
	& $CMake --build . --config Release
	& $CMake --build . --config Release --target install
	"cbor.dll", "crypto-45.dll" | %{ Copy-Item "${OUTPUT}\bin\$_" `
		-Destination "examples\Release" }
}

Push-Location ${BUILD}\64
Build ${OUTPUT}\64 "Visual Studio 15 2017 Win64"
Pop-Location

Push-Location ${BUILD}\32
Build ${OUTPUT}\32 "Visual Studio 15 2017"
Pop-Location
