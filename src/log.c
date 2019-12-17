/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "fido.h"

#ifndef FIDO_NO_DIAGNOSTIC

#ifndef TLS
#define TLS
#endif

#define  MAX_SINGLE_LOG_LINE_LENGTH 5000

static TLS fido_log_handler_t logger = NULL;

static void
default_log(const char *fmt)
{
	fprintf(stderr, "%s", fmt);
	fflush(stderr);
}

void
fido_log_init(fido_log_handler_t log_fp)
{
	if (log_fp != NULL)
		logger = log_fp;
	else
		logger = &default_log;
}

void
fido_log_xxd(const void *buf, size_t count)
{
	const uint8_t	*ptr = buf;
	size_t		 i;

	if (logger == NULL)
		return;

	fido_log_debug("  ");

	for (i = 0; i < count; i++) {
		fido_log_debug("%02x ", *ptr++);
		if ((i + 1) % 16 == 0 && i + 1 < count)
			fido_log_debug("\n  ");
	}

	fido_log_debug("\n");
}

void
fido_log_debug(const char *fmt, ...)
{
	if (logger == NULL)
		return;
	char log_line[MAX_SINGLE_LOG_LINE_LENGTH];
	va_list	 ap;
	va_start(ap, fmt);
	snprintf(log_line, MAX_SINGLE_LOG_LINE_LENGTH, fmt, ap);
	va_end(ap);
	logger(log_line);
}

#endif /* !FIDO_NO_DIAGNOSTIC */
