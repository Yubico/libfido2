/*
 * Copyright (c) 2020 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "fido.h"

static void
xstrerror(int errnum, char *buf, size_t len)
{
	if (len < 1)
		return;

	memset(buf, 0, len);

	if (strerror_r(errnum, buf, len - 1) != 0)
		snprintf(buf, len - 1, "error %d", errnum);
}

static int
timespec_to_ms(const struct timespec *ts, int upper_bound)
{
	int64_t x;
	int64_t y;

	if (ts->tv_sec < 0 || (uint64_t)ts->tv_sec > INT64_MAX / 1000LL ||
	    ts->tv_nsec < 0 || (uint64_t)ts->tv_nsec / 1000000LL > INT64_MAX)
		return (upper_bound);

	x = ts->tv_sec * 1000LL;
	y = ts->tv_nsec / 1000000LL;

	if (INT64_MAX - x < y || x + y > upper_bound)
		return (upper_bound);

	return (int)(x + y);
}

int
fido_hid_unix_open(const char *path)
{
	char ebuf[128];
	int fd;
	struct stat st;

	if ((fd = open(path, O_RDWR)) == -1) {
		if (errno != ENOENT && errno != ENXIO) {
			xstrerror(errno, ebuf, sizeof(ebuf));
			fido_log_debug("%s: open %s: %s", __func__, path, ebuf);
		}
		return (-1);
	}

	if (fstat(fd, &st) == -1) {
		xstrerror(errno, ebuf, sizeof(ebuf));
		fido_log_debug("%s: fstat %s: %s", __func__, path, ebuf);
		close(fd);
		return (-1);
	}

	if (S_ISCHR(st.st_mode) == 0) {
		fido_log_debug("%s: S_ISCHR %s", __func__, path);
		close(fd);
		return (-1);
	}

	return (fd);
}

int
fido_hid_unix_wait(int fd, int ms)
{
	char		ebuf[128];
	struct timespec	ts_start;
	struct timespec	ts_now;
	struct timespec	ts_delta;
	struct pollfd	pfd;
	int		ms_remain;
	int		r;

	if (ms < 0)
		return (0);

	memset(&pfd, 0, sizeof(pfd));
	pfd.events = POLLIN;
	pfd.fd = fd;

	if (clock_gettime(CLOCK_MONOTONIC, &ts_start) != 0) {
		xstrerror(errno, ebuf, sizeof(ebuf));
		fido_log_debug("%s: clock_gettime: %s", __func__, ebuf);
		return (-1);
	}

	for (ms_remain = ms; ms_remain > 0;) {
		if ((r = poll(&pfd, 1, ms_remain)) > 0)
			return (0);
		else if (r == 0)
			break;
		else if (errno != EINTR) {
			xstrerror(errno, ebuf, sizeof(ebuf));
			fido_log_debug("%s: poll: %s", __func__, ebuf);
			return (-1);
		}
		/* poll interrupted - subtract time already waited */
		if (clock_gettime(CLOCK_MONOTONIC, &ts_now) != 0) {
			xstrerror(errno, ebuf, sizeof(ebuf));
			fido_log_debug("%s: clock_gettime: %s", __func__, ebuf);
			return (-1);
		}
		timespecsub(&ts_now, &ts_start, &ts_delta);
		ms_remain = ms - timespec_to_ms(&ts_delta, ms);
	}

	return (-1);
}
