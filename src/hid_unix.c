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
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "fido.h"

#ifdef __NetBSD__
/*
 * NetBSD introduced pollts as the natural extension of poll with
 * sigmask and struct timespec in the early 2000s; later everyone else
 * adopted the name ppoll for exactly the same signature and semantics,
 * and NetBSD will soon support the name ppoll too, but not today.
 */
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
fido_hid_unix_wait(int fd, int ms, const fido_sigset_t *sigmask)
{
	struct timespec	ts_start;
	struct timespec	ts_now;
	struct timespec	ts_delta;
	struct timespec	ts_deadline;
	struct pollfd	pfd;
	int		r;

	memset(&pfd, 0, sizeof(pfd));
	pfd.events = POLLIN;
	pfd.fd = fd;

#ifdef FIDO_FUZZ
	if (ms < 0)
		return (0);
#endif

	if (ms > 0) {
		if (clock_gettime(CLOCK_MONOTONIC, &ts_start) != 0) {
			fido_log_error(errno, "%s: clock_gettime", __func__);
			return (-1);
		}
		ts_delta.tv_sec = ms / 1000;
		ts_delta.tv_nsec = (ms % 1000) * 1000000;
		timespecadd(&ts_start, &ts_delta, &ts_deadline);
	}

	for (;;) {
		if (ms > 0) {
			if (clock_gettime(CLOCK_MONOTONIC, &ts_now) != 0) {
				fido_log_error(errno, "%s: clock_gettime",
				    __func__);
				return (-1);
			}
			if (timespeccmp(&ts_deadline, &ts_now, <=)) {
				errno = ETIMEDOUT;
				return (-1);
			}
			timespecsub(&ts_deadline, &ts_now, &ts_delta);
			r = ppoll(&pfd, 1, &ts_delta, sigmask);
		} else if (ms == 0) {
			ts_delta.tv_sec = 0;
			ts_delta.tv_nsec = 0;
			r = ppoll(&pfd, 1, &ts_delta, sigmask);
		} else {
			r = ppoll(&pfd, 1, NULL, sigmask);
		}
		if (r > 0)
			return (0);
		else if (r == 0)
			break;
		else {
			fido_log_error(errno, "%s: poll", __func__);
			return (-1);
		}
	}

	return (-1);
}
