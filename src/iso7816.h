/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _ISO7816_H
#define _ISO7816_H

typedef struct iso7816_apdu iso7816_apdu_t;

const unsigned char *iso7816_ptr(const iso7816_apdu_t *);
int iso7816_add(iso7816_apdu_t *, const void *, size_t);
iso7816_apdu_t *iso7816_new(uint8_t, uint8_t, uint16_t);
size_t iso7816_len(const iso7816_apdu_t *);
void iso7816_free(iso7816_apdu_t **);

#endif /* !_ISO7816_H */
