// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2013-2018 Marc André Tanner <mat at brain-dump.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef ABDUCO_H
#define ABDUCO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/types.h>

#if defined CTRL && defined _AIX
  #undef CTRL
#endif
#ifndef CTRL
  #define CTRL(k)   ((k) & 0x1F)
#endif

#define countof(arr) (sizeof(arr) / sizeof((arr)[0]))

typedef struct Client Client;
struct Client {
	int socket;
	enum {
		STATE_CONNECTED,
		STATE_ATTACHED,
		STATE_DETACHED,
		STATE_DISCONNECTED,
	} state;
	bool need_resize;
	enum {
		CLIENT_READONLY = 1 << 0,
		CLIENT_LOWPRIORITY = 1 << 1,
	} flags;
	bool msg_exit_sent;
	Client *next;
};

struct entry {
	char *data;
	uint32_t len;
	bool complete;
	TAILQ_ENTRY(entry) entries;
};

TAILQ_HEAD(screenhead, entry);

typedef struct {
	Client *clients;
	int socket;
	int pty;
	int exit_status;
	struct termios *term;
	struct winsize winsize;
	struct screenhead screen;
	int screen_rows;
	int screen_max_rows;
	pid_t pid;
	volatile sig_atomic_t running;
	const char *name;
	const char *session_name;
	char host[255];
	bool read_pty;
} Server;

#if defined(_AIX) || defined(__sun)
pid_t forkpty(int *master, char *name, struct termios *tio,
              struct winsize *ws);
#endif

void die(const char *s);

#endif
