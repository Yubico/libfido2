/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <fido.h>

#include "../openbsd-compat/openbsd-compat.h"
#include "extern.h"

static void
format_flags(char *ret, size_t retlen, uint8_t flags)
{
	memset(ret, 0, retlen);

	if (flags & FIDO_CAP_WINK) {
		if (strlcat(ret, "wink,", retlen) >= retlen)
			goto toolong;
	} else {
		if (strlcat(ret, "nowink,", retlen) >= retlen)
			goto toolong;
	}

	if (flags & FIDO_CAP_CBOR) {
		if (strlcat(ret, " cbor,", retlen) >= retlen)
			goto toolong;
	} else {
		if (strlcat(ret, " nocbor,", retlen) >= retlen)
			goto toolong;
	}

	if (flags & FIDO_CAP_NMSG) {
		if (strlcat(ret, " nomsg", retlen) >= retlen)
			goto toolong;
	} else {
		if (strlcat(ret, " msg", retlen) >= retlen)
			goto toolong;
	}

	return;
toolong:
	strlcpy(ret, "toolong", retlen);
}

static void
print_attr(const fido_dev_t *dev)
{
	char flags_txt[128];

	printf("proto: 0x%02x\n", fido_dev_protocol(dev));
	printf("major: 0x%02x\n", fido_dev_major(dev));
	printf("minor: 0x%02x\n", fido_dev_minor(dev));
	printf("build: 0x%02x\n", fido_dev_build(dev));

	format_flags(flags_txt, sizeof(flags_txt), fido_dev_flags(dev));
	printf("caps: 0x%02x (%s)\n", fido_dev_flags(dev), flags_txt);
}

static void
print_str_array(const char *label, char * const *sa, size_t len)
{
	if (len == 0)
		return;

	printf("%s strings: ", label);

	for (size_t i = 0; i < len; i++)
		printf("%s%s", i > 0 ? ", " : "", sa[i]);

	printf("\n");
}

static void
print_opt_array(const char *label, char * const *name, const bool *value,
    size_t len)
{
	if (len == 0)
		return;

	printf("%s: ", label);

	for (size_t i = 0; i < len; i++)
		printf("%s%s%s", i > 0 ? ", " : "",
		    value[i] ? "" : "no", name[i]);

	printf("\n");
}

static void
print_aaguid(const unsigned char *buf, size_t buflen)
{
	printf("aaguid: ");

	while (buflen--)
		printf("%02x", *buf++);

	printf("\n");
}

static void
print_maxmsgsiz(uint64_t maxmsgsiz)
{
	printf("maxmsgsiz: %d\n", (int)maxmsgsiz);
}

static void
print_byte_array(const char *label, const uint8_t *ba, size_t len)
{
	if (len == 0)
		return;

	printf("%s: ", label);

	for (size_t i = 0; i < len; i++)
		printf("%s%u", i > 0 ? ", " : "", (unsigned)ba[i]);

	printf("\n");
}

int
token_info(int argc, char **argv)
{
	fido_dev_t *dev = NULL;
	fido_cbor_info_t *ci = NULL;
	bool debug = false;
	int retrycnt;
	int ch;
	int r;

	while ((ch = getopt(argc, argv, "d")) != -1) {
		switch (ch) {
		case 'd':
			debug = true;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	fido_init(debug ? FIDO_DEBUG : 0);

	dev = open_dev(argc, argv);
	print_attr(dev);

	if (fido_dev_is_fido2(dev) == false)
		goto end;
	if ((ci = fido_cbor_info_new()) == NULL)
		errx(1, "fido_cbor_info_new");
	if ((r = fido_dev_get_cbor_info(dev, ci)) != FIDO_OK)
		errx(1, "fido_dev_get_cbor_info: %s (0x%x)", fido_strerr(r), r);

	/* print supported protocol versions */
	print_str_array("version", fido_cbor_info_versions_ptr(ci),
	    fido_cbor_info_versions_len(ci));

	/* print supported extensions */
	print_str_array("extension", fido_cbor_info_extensions_ptr(ci),
	    fido_cbor_info_extensions_len(ci));

	/* print aaguid */
	print_aaguid(fido_cbor_info_aaguid_ptr(ci),
	    fido_cbor_info_aaguid_len(ci));

	/* print supported options */
	print_opt_array("options", fido_cbor_info_options_name_ptr(ci),
	    fido_cbor_info_options_value_ptr(ci),
	    fido_cbor_info_options_len(ci));

	/* print maximum message size */
	print_maxmsgsiz(fido_cbor_info_maxmsgsiz(ci));

	/* print supported pin protocols */
	print_byte_array("pin protocols", fido_cbor_info_protocols_ptr(ci),
	    fido_cbor_info_protocols_len(ci));

	if ((r = fido_dev_get_retry_count(dev, &retrycnt)) != FIDO_OK)
		printf("pin retries: undefined\n");
	else
		printf("pin retries: %d\n", retrycnt);

	fido_cbor_info_free(&ci);
end:
	fido_dev_close(dev);
	fido_dev_free(&dev);

	exit(0);
}

int
token_reset(int argc, char **argv)
{
	fido_dev_t *dev = NULL;
	bool debug = false;
	int ch;
	int r;

	while ((ch = getopt(argc, argv, "d")) != -1) {
		switch (ch) {
		case 'd':
			debug = true;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	fido_init(debug ? FIDO_DEBUG : 0);
	dev = open_dev(argc, argv);
	if ((r = fido_dev_reset(dev)) != FIDO_OK)
		errx(1, "fido_dev_reset: %s", fido_strerr(r));

	fido_dev_close(dev);
	fido_dev_free(&dev);

	exit(0);
}

int
token_list(int argc, char **argv)
{
	fido_dev_info_t *devlist;
	size_t ndevs;
	bool debug = false;
	int ch;
	int r;

	while ((ch = getopt(argc, argv, "d")) != -1) {
		switch (ch) {
		case 'd':
			debug = true;
			break;
		default:
			usage();
		}
	}

	fido_init(debug ? FIDO_DEBUG : 0);

	if ((devlist = fido_dev_info_new(64)) == NULL)
		errx(1, "fido_dev_info_new");

	if ((r = fido_dev_info_manifest(devlist, 64, &ndevs)) != FIDO_OK)
		errx(1, "fido_dev_info_manifest: %s (0x%x)", fido_strerr(r), r);

	for (size_t i = 0; i < ndevs; i++) {
		const fido_dev_info_t *di = fido_dev_info_ptr(devlist, i);
		printf("%s: vendor=0x%04x, product=0x%04x (%s %s)\n",
		    fido_dev_info_path(di),
		    (uint16_t)fido_dev_info_vendor(di),
		    (uint16_t)fido_dev_info_product(di),
		    fido_dev_info_manufacturer_string(di),
		    fido_dev_info_product_string(di));
	}

	fido_dev_info_free(&devlist, ndevs);

	exit(0);
}
