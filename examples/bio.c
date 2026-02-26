/*
 * Copyright (c) 2026 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "../openbsd-compat/openbsd-compat.h"

#include <stdio.h>

#include <fido.h>
#include <fido/bio.h>

#define TIMEOUT_MS    10000
#define TEMPLATE_NAME "bio-example"

struct context {
	fido_bio_template_t *our;
	bool                 found;
};

enum list_bio_action {
	LIST_BIO_CONTINUE,
	LIST_BIO_STOP,
};

typedef enum list_bio_action list_bio_templates_cb_t(
	const fido_bio_template_t *, void *opaq);

static int
list_bio_templates(fido_dev_t *dev, list_bio_templates_cb_t *cb, void *opaq)
{
	fido_bio_template_array_t	*templates;
	int				 r;

	if ((templates = fido_bio_template_array_new()) == NULL)
		errx(1, "fido_bio_template_array_new");

	if ((r = fido_bio_dev_get_template_array(dev, templates,
	    NULL)) != FIDO_OK) {
		warnx("fido_bio_dev_get_template_array: %s", fido_strerr(r));
		goto exit;
	}

	for (size_t idx = 0; idx < fido_bio_template_array_count(templates);
	    idx++) {
		const fido_bio_template_t *templ;

		if ((templ = fido_bio_template(templates, idx)) == NULL) {
			warnx("fido_bio_template %zu -> NULL", idx);
			goto exit;
		}

		if (cb(templ, opaq) == LIST_BIO_STOP)
			break;
	}

	r = 0;
exit:
	fido_bio_template_array_free(&templates);
	return r;
}

static int
remove_bio_template(fido_dev_t *dev, const fido_bio_template_t *our)
{
	int r;

	if ((r = fido_bio_dev_enroll_remove(dev, our, NULL)) != FIDO_OK)
		warnx("fido_bio_dev_enroll_remove: %s", fido_strerr(r));
	return r;
}

static int
rename_bio_template(fido_dev_t *dev, fido_bio_template_t *templ,
    const char *name)
{
	int r;

	if ((r = fido_bio_template_set_name(templ, name)) != FIDO_OK)
		warnx("fido_bio_template_set_name: %s", fido_strerr(r));

	if ((r = fido_bio_dev_set_template_name(dev, templ, NULL)) != FIDO_OK)
		warnx("fido_bio_dev_set_template_name: %s", fido_strerr(r));

	return r;
}

static int
enroll_new(fido_dev_t *dev, fido_bio_template_t **templ_out)
{
	fido_bio_template_t	*templ = NULL;
	fido_bio_enroll_t	*enroll = NULL;
	int			 r;

	if ((templ = fido_bio_template_new()) == NULL)
		errx(1, "fido_bio_template_new");

	if ((enroll = fido_bio_enroll_new()) == NULL)
		errx(1, "fido_bio_enroll_new");

	warnx("Touch your authenticator.");
	if ((r = fido_bio_dev_enroll_begin(dev, templ, enroll, TIMEOUT_MS,
	    NULL)) != FIDO_OK) {
		warnx("fido_bio_dev_enroll_begin: %s", fido_strerr(r));
		goto exit;
	}

	while (fido_bio_enroll_remaining_samples(enroll) > 0) {
		warnx("Touch your authenticator (%hhu sample(s) left).",
		    fido_bio_enroll_remaining_samples(enroll));

		if ((r = fido_bio_dev_enroll_continue(dev, templ, enroll,
		    TIMEOUT_MS)) != FIDO_OK) {
			fido_dev_cancel(dev);
			warnx("fido_bio_dev_enroll_continue: %s",
			    fido_strerr(r));
			goto exit;
		}

		if ((r = fido_bio_enroll_last_status(
		    enroll)) != FIDO_BIO_ENROLL_FP_GOOD)
			warnx("fido_bio_enroll_last_status: %d", r);
	}

exit:
	fido_bio_enroll_free(&enroll);
	if (r == FIDO_OK)
		*templ_out = templ;
	else
		fido_bio_template_free(&templ);
	return r;
}

static enum list_bio_action
search_template(const fido_bio_template_t *t, void *opaq)
{
	struct context *c = opaq;
	size_t len;
	const char *our_name;

	len = fido_bio_template_id_len(t);
	if (len != fido_bio_template_id_len(c->our) || memcmp(
	    fido_bio_template_id_ptr(t), fido_bio_template_id_ptr(c->our),
	    len))
		return LIST_BIO_CONTINUE;

	if ((our_name = fido_bio_template_name(c->our)) != NULL &&
	    our_name[0] != '\0') {
		const char *their_name;

		if ((their_name = fido_bio_template_name(t)) == NULL ||
		    strcmp(their_name, our_name) != 0)
			return LIST_BIO_CONTINUE;
	}

	c->found = true;
	return LIST_BIO_STOP;
}

static int
run(fido_dev_t *dev, const char *pin)
{
	int r;
	struct context ctx;

	if ((r = fido_dev_get_puat(dev, FIDO_PUAT_BIOENROLL, NULL,
	    pin)) != FIDO_OK) {
		warnx("could not get puat: %s", fido_strerr(r));
		return r;
	}

	memset(&ctx, 0, sizeof(ctx));

	warnx("1. Enrollment...");
	if ((r = enroll_new(dev, &ctx.our)) != FIDO_OK)
		goto exit;

	warnx("2. Rename");
	if ((r = rename_bio_template(dev, ctx.our, TEMPLATE_NAME)) != FIDO_OK)
		goto exit;

	warnx("3. Scan");
	if ((r = list_bio_templates(dev, search_template, &ctx)) != FIDO_OK)
		goto exit;
	if (!ctx.found) {
		warnx("unexpectedly missing template");
		r = -1;
		goto exit;
	}

	warnx("4. Remove");
	r = remove_bio_template(dev, ctx.our);
exit:
	fido_bio_template_free(&ctx.our);
	return r;
}

static void
usage(void)
{
	fprintf(stderr, "usage: bio [-P pin] <device>\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	fido_dev_t	*dev = NULL;
	int		 r, ch;
	const char	*path, *pin = NULL;

	while ((ch = getopt(argc, argv, "P:")) != -1) {
		switch (ch) {
		case 'P':
			pin = optarg;
			break;
		default:
			usage();
		}
	}

	if (argc - optind < 1)
		usage();
	path = argv[optind];

	fido_init(0);

	if ((dev = fido_dev_new()) == NULL)
		return 1;

	if ((r = fido_dev_open(dev, path)) != FIDO_OK) {
		warnx("could not open %s: %s", path, fido_strerr(r));
		goto quit;
	}

	r = run(dev, pin);
quit:
	fido_dev_close(dev);
	fido_dev_free(&dev);
	return r != FIDO_OK;
}
