/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fido.h"

#ifndef FIDO_NO_DIAGNOSTIC

#define XXD_LEN	8
#define FMT_LEN	1024

#ifndef TLS
#define TLS
#endif

static TLS int logging;
static TLS fido_log_handler_t *log_handler;

static void
log_on_stderr(const char *str)
{
	fprintf(stderr, "%s", str);
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
	char		 log_line_buf[XXD_LEN * 16] = "  ";
	size_t		 i;

	if (!logging || log_handler == NULL)
		return;

	for (i = 0; i < count; i++) {
		char c[XXD_LEN] = "\0";
		snprintf(c, sizeof(c), "%02x ", *ptr++);
		strcat(log_line_buf, c);
		if ((i + 1) % 16 == 0 && i + 1 < count) {
			strcat(log_line_buf, "\n");
			log_handler(log_line_buf);
			strcpy(log_line_buf, "  ");
		}
	}
	strcat(log_line_buf, "\n");
	log_handler(log_line_buf);
}

void
fido_log_debug(const char *fmt, ...)
{
	char    fmtbuf[FMT_LEN];
	va_list ap;

	if (!logging || log_handler == NULL)
		return;

	va_start(ap, fmt);
	size_t n = vsnprintf(fmtbuf, sizeof(fmtbuf), fmt, ap);
	va_end(ap);

	if (n + 1 < sizeof(fmtbuf)) {
		strncpy(fmtbuf + n, "\n", sizeof(fmtbuf) - n);
	}
	log_handler(fmtbuf);
}

void
fido_set_log_handler(fido_log_handler_t *handler)
{
	if (handler != NULL)
		log_handler = handler;
}

#endif /* !FIDO_NO_DIAGNOSTIC */
