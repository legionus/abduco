// SPDX-License-Identifier: ISC
#include <errno.h>
#include <stddef.h>
#include <unistd.h>

#include "io.h"

ssize_t write_all(int fd, const char *buf, size_t len) {
	size_t remaining = len;
	while (remaining > 0) {
		ssize_t res = write(fd, buf, remaining);
		if (res < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
				continue;
			return -1;
		}
		if (res == 0)
			return (ssize_t)(len - remaining);
		buf += res;
		remaining -= (size_t)res;
	}
	return (ssize_t)len;
}

ssize_t read_all(int fd, char *buf, size_t len) {
	size_t remaining = len;
	while (remaining > 0) {
		ssize_t res = read(fd, buf, remaining);
		if (res < 0) {
			if (errno == EWOULDBLOCK)
				return (ssize_t)(len - remaining);
			if (errno == EAGAIN || errno == EINTR)
				continue;
			return -1;
		}
		if (res == 0)
			return (ssize_t)(len - remaining);
		buf += res;
		remaining -= (size_t)res;
	}
	return (ssize_t)len;
}
