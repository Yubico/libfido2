/*
 * Copyright (c) 2020 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include "fido.h"

#ifdef __NetBSD__
#define	ppoll	pollts
#endif

int
fido_hid_unix_open(const char *path)
{
	int fd;
	struct stat st;

	if ((fd = open(path, O_RDWR)) == -1) {
		if (errno != ENOENT && errno != ENXIO)
			fido_log_error(errno, "%s: open %s", __func__, path);
		return (-1);
	}

	if (fstat(fd, &st) == -1) {
		fido_log_error(errno, "%s: fstat %s", __func__, path);
		if (close(fd) == -1)
			fido_log_error(errno, "%s: close", __func__);
		return (-1);
	}

	if (S_ISCHR(st.st_mode) == 0) {
		fido_log_debug("%s: S_ISCHR %s", __func__, path);
		if (close(fd) == -1)
			fido_log_error(errno, "%s: close", __func__);
		return (-1);
	}

	return (fd);
}

int
fido_hid_unix_wait(int fd, int ms, const fido_sigset_t *sigmask)
{
	struct timespec ts, ts_end, ts_now;
	struct pollfd pfd;
	int r;

	memset(&pfd, 0, sizeof(pfd));
	pfd.events = POLLIN;
	pfd.fd = fd;

#ifdef FIDO_FUZZ
	return (0);
#endif

	if (ms > -1) {
		// Calculate the absolute time at which the timeout expires
		if (clock_gettime(CLOCK_MONOTONIC, &ts_end) == -1) {
			fido_log_error(errno, "%s: clock_gettime", __func__);
			return (-1);
		}
		ts_end.tv_sec += ms / 1000;
		ts_end.tv_nsec += (ms % 1000) * 1000000;
		if (ts_end.tv_nsec >= 1000000000L) {
			ts_end.tv_sec += 1;
			ts_end.tv_nsec -= 1000000000L;
		}
	}

	do {
		if (ms > -1) {
			// Calculate the remaining timeout
			if (clock_gettime(CLOCK_MONOTONIC, &ts_now) == -1) {
				fido_log_error(errno, "%s: clock_gettime", __func__);
				return (-1);
			}
			ts.tv_sec = ts_end.tv_sec - ts_now.tv_sec;
			ts.tv_nsec = ts_end.tv_nsec - ts_now.tv_nsec;
			if (ts.tv_nsec < 0) {
				ts.tv_sec -= 1;
				ts.tv_nsec += 1000000000L;
			}
			if (ts.tv_sec < 0) {
				return (-1); // Timeout expired
			}
		}
		r = ppoll(&pfd, 1, ms > -1 ? &ts : NULL, sigmask);
	} while (r == -1 && errno == EINTR);

	if (r < 1) {
		if (r == -1)
			fido_log_error(errno, "%s: ppoll", __func__);
		return (-1);
	}

	return (0);
}
