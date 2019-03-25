/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#pragma once

#ifdef _MSC_VER
#ifdef fido2_shared_EXPORTS
#define FIDO_PUBLIC_API __declspec(dllexport)
#elif !FIDO2_NO_EXPORT
#define FIDO_PUBLIC_API __declspec(dllimport)
#else
#define FIDO_PUBLIC_API
#endif
#else
#define FIDO_PUBLIC_API
#endif