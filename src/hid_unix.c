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
fido_hid_unix_wait(int fd, short events, int ms, const sigset_t *sigmask)
{
	char		ebuf[128];
	struct timespec	ts_start;
	struct timespec	ts_now;
	struct timespec	ts_delta;
	struct timespec	ts_deadline;
	struct pollfd	pfd;
	int		r;

	memset(&pfd, 0, sizeof(pfd));
	pfd.events = events;
	pfd.fd = fd;

	if (ms > 0) {
		if (clock_gettime(CLOCK_MONOTONIC, &ts_start) != 0) {
			xstrerror(errno, ebuf, sizeof(ebuf));
			fido_log_debug("%s: clock_gettime: %s", __func__,
			    ebuf);
			return (-1);
		}
		ts_delta.tv_sec = ms / 1000;
		ts_delta.tv_nsec = (ms % 1000) * 1000000;
		timespecadd(&ts_start, &ts_delta, &ts_deadline);
	}

	for (;;) {
		if (ms > 0) {
			if (clock_gettime(CLOCK_MONOTONIC, &ts_now) != 0) {
				xstrerror(errno, ebuf, sizeof(ebuf));
				fido_log_debug("%s: clock_gettime: %s",
				    __func__, ebuf);
				return (-1);
			}
			if (timespeccmp(&ts_deadline, &ts_now, <=)) {
				errno = ETIMEDOUT;
				return (-1);
			}
			timespecsub(&ts_deadline, &ts_now, &ts_delta);
			r = pollts(&pfd, 1, &ts_delta, sigmask);
		} else if (ms == 0) {
			ts_delta.tv_sec = 0;
			ts_delta.tv_nsec = 0;
			r = pollts(&pfd, 1, &ts_delta, sigmask);
		} else {
			r = pollts(&pfd, 1, NULL, sigmask);
		}
		if (r > 0)
			return (0);
		else if (r == 0)
			break;
		else {
			xstrerror(errno, ebuf, sizeof(ebuf));
			fido_log_debug("%s: poll: %s", __func__, ebuf);
			return (-1);
		}
	}

	return (-1);
}
