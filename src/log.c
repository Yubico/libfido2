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

#define MSGBUFSIZ 1024

#ifndef TLS
#define TLS
#endif

static TLS int logging;
static TLS fido_log_handler_t *log_handler;

static void
log_on_stderr(const char *str)
{
	fprintf(stderr, "%s", str);
	fflush(stderr);
}

void
fido_log_init(void)
{
	logging = 1;
	log_handler = log_on_stderr;
}

void
fido_log_xxd(const void *buf, size_t count)
{
	const uint8_t	*ptr = buf;
	size_t		 i;

	if (!logging || log_handler == NULL)
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
	char    msgbuf[MSGBUFSIZ];
	va_list ap;

	if (!logging || log_handler == NULL)
		return;

	va_start(ap, fmt);
	snprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	va_end(ap);

	log_handler(log_line);
}

void
fido_set_log_handler(int flags, fido_log_handler_t *handler)
{
	if (handler != NULL)
		log_handler = handler;
}

#endif /* !FIDO_NO_DIAGNOSTIC */
