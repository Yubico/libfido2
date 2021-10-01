# Copyright (c) 2021 Yubico AB. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

$ErrorActionPreference = "Stop"

./build.ps1 -Arch x64 -Type dynamic -Config Release
./build.ps1 -Arch x64 -Type static -Config Release
./build.ps1 -Arch Win32 -Type dynamic -Config Release
./build.ps1 -Arch Win32 -Type static -Config Release

. "$PSScriptRoot\const.ps1"

New-Item -Type Directory ${OUTPUT}\pkg\Win64\Release\v142\dynamic
New-Item -Type Directory ${OUTPUT}\pkg\Win32\Release\v142\dynamic
New-Item -Type Directory ${OUTPUT}\pkg\Win64\Release\v142\static
New-Item -Type Directory ${OUTPUT}\pkg\Win32\Release\v142\static

Function Package-Headers() {
	Copy-Item "${OUTPUT}\x64\dynamic\include" -Destination "${OUTPUT}\pkg" `
	    -Recurse -ErrorAction Stop
}

Function Package-Dynamic(${SRC}, ${DEST}) {
	Copy-Item "${SRC}\bin\cbor.dll" "${DEST}"
	Copy-Item "${SRC}\lib\cbor.lib" "${DEST}"
	Copy-Item "${SRC}\bin\zlib1.dll" "${DEST}"
	Copy-Item "${SRC}\lib\zlib.lib" "${DEST}"
	Copy-Item "${SRC}\bin\crypto-46.dll" "${DEST}"
	Copy-Item "${SRC}\lib\crypto-46.lib" "${DEST}"
	Copy-Item "${SRC}\bin\fido2.dll" "${DEST}"
	Copy-Item "${SRC}\lib\fido2.lib" "${DEST}"
}

Function Package-Static(${SRC}, ${DEST}) {
	Copy-Item "${SRC}/lib/cbor.lib" "${DEST}"
	Copy-Item "${SRC}/lib/zlib.lib" "${DEST}"
	Copy-Item "${SRC}/lib/crypto-46.lib" "${DEST}"
	Copy-Item "${SRC}/lib/fido2_static.lib" "${DEST}/fido2.lib"
}

Function Package-PDBs(${SRC}, ${DEST}) {
	Copy-Item "${SRC}\${LIBRESSL}\crypto\crypto.dir\Release\vc142.pdb" `
	    "${DEST}\crypto-46.pdb"
	Copy-Item "${SRC}\${LIBCBOR}\src\cbor.dir\Release\vc142.pdb" `
	    "${DEST}\cbor.pdb"
	Copy-Item "${SRC}\${ZLIB}\zlib.dir\Release\vc142.pdb" `
	    "${DEST}\zlib.pdb"
	Copy-Item "${SRC}\src\fido2_shared.dir\Release\vc142.pdb" `
	    "${DEST}\fido2.pdb"
}

Function Package-Tools(${SRC}, ${DEST}) {
	Copy-Item "${SRC}\tools\Release\fido2-assert.exe" `
	    "${DEST}\fido2-assert.exe"
	Copy-Item "${SRC}\tools\Release\fido2-cred.exe" "${DEST}\fido2-cred.exe"
	Copy-Item "${SRC}\tools\Release\fido2-token.exe" `
	    "${DEST}\fido2-token.exe"
}

Package-Headers

Package-Dynamic ${OUTPUT}\x64\dynamic ${OUTPUT}\pkg\Win64\Release\v142\dynamic
Package-PDBs ${BUILD}\x64\dynamic ${OUTPUT}\pkg\Win64\Release\v142\dynamic
Package-Tools ${BUILD}\x64\dynamic ${OUTPUT}\pkg\Win64\Release\v142\dynamic

Package-Dynamic ${OUTPUT}\Win32\dynamic ${OUTPUT}\pkg\Win32\Release\v142\dynamic
Package-PDBs ${BUILD}\Win32\dynamic ${OUTPUT}\pkg\Win32\Release\v142\dynamic
Package-Tools ${BUILD}\Win32\dynamic ${OUTPUT}\pkg\Win32\Release\v142\dynamic

Package-Static ${OUTPUT}\x64\static ${OUTPUT}\pkg\Win64\Release\v142\static
Package-Static ${OUTPUT}\Win32\static ${OUTPUT}\pkg\Win32\Release\v142\static
