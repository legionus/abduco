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
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <libgen.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/wait.h>
#if defined(HAVE_PTY_H)
# include <pty.h>
#elif defined(HAVE_LIBUTIL_H)
# include <libutil.h>
#elif defined(HAVE_UTIL_H)
# include <util.h>
#endif

#include "abduco.h"
#include "client.h"
#include "config.h"
#include "io.h"
#include "packet.h"
#include "session.h"
#include "server.h"

static bool quiet;

static void info(const Server *srv, const char *str, ...) {
	va_list ap;
	va_start(ap, str);
	if (str && !quiet) {
		fprintf(stderr, "%s: %s: ", srv->name, srv->session_name);
		vfprintf(stderr, str, ap);
		fprintf(stderr, "\r\n");
		fflush(stderr);
	}
	va_end(ap);
}

void die(const char *s) {
	perror(s);
	exit(EXIT_FAILURE);
}

static void usage(void) {
	fprintf(stderr, "usage: abduco [-a|-A|-c|-n] [-p] [-r] [-q] [-l] [-f] [-e detachkey] [-L num] name command\n");
	fprintf(stderr, "Try 'abduco -h' for more information.\n");
	exit(EXIT_FAILURE);
}

static void help(void) {
	puts("abduco - terminal session manager\n");
	puts("usage: abduco [-a|-A|-c|-d|-n] [options] name [command]\n");
	puts("Actions (roles are mutually exclusive):");
	puts("  -a          Attach to an existing session");
	puts("  -A          Attach to existing session or create a new one");
	puts("  -c          Create a new session and attach to it");
	puts("  -d          Detect if session exists (exit status 0 if true)");
	puts("  -n          Create a new session but do not attach to it\n");
	puts("Options:");
	puts("  -e <key>    Set detach key (default: ^\\)");
	puts("  -f          Force create session when terminated session exists");
	puts("  -l          Attach with lowest priority (last to control terminal size)");
	puts("  -L <num>    Set screen buffer size in lines (default: 120, 0 to disable)");
	puts("  -p          Pass through mode (implies -q and -l)");
	puts("  -q          Quiet, do not print informative messages");
	puts("  -r          Read-only session, user input is ignored");
	puts("  -v          Print version information and exit");
	puts("  -h          Show this help message and exit\n");
	puts("Environment variables:");
	puts("  ABDUCO_CMD         Default command if none specified (default: dvtm)");
	puts("  ABDUCO_SOCKET_DIR  Directory for session sockets");
	puts("  ABDUCO_SESSION     Session name (set by abduco for child process)");
	puts("  ABDUCO_SOCKET      Socket path (set by abduco for child process)\n");
	puts("Session sockets are stored in (first existing is used):");
	puts("  $ABDUCO_SOCKET_DIR/abduco/");
	puts("  $HOME/.abduco/");
	puts("  $TMPDIR/abduco/$USER/");
	puts("  /tmp/abduco/$USER/\n");
	puts("Detach key: Press the detach key (default Ctrl-\\) to detach from session.");
	puts("List sessions: Run abduco without arguments to list active sessions.");
	exit(EXIT_SUCCESS);
}

static int session_connect(const Server *srv, const char *name) {
	int fd;
	struct stat sb;
	if (!session_set_socket_name(srv, name) || (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		return -1;
	if (session_socket_connect(fd) == -1) {
		if (errno == ECONNREFUSED && stat(session_socket_path(), &sb) == 0 && S_ISSOCK(sb.st_mode))
			session_unlink_socket();
		close(fd);
		return -1;
	}
	return fd;
}

static pid_t session_exists(Server *srv, const char *name) {
	Packet pkt;
	pid_t pid = 0;
	if ((srv->socket = session_connect(srv, name)) == -1)
		return pid;
	if (client_recv_packet(srv, &pkt) && pkt.type == MSG_PID) {
		/* pkt.u.l is uint64_t; clamp to valid pid_t range */
		if (pkt.u.l <= (uint64_t)INT_MAX)
			pid = (pid_t)pkt.u.l;
	}
	close(srv->socket);
	return pid;
}

static bool session_alive(Server *srv, const char *name) {
	struct stat sb;
	return session_exists(srv, name) &&
	       stat(session_socket_path(), &sb) == 0 &&
	       S_ISSOCK(sb.st_mode) && (sb.st_mode & S_IXGRP) == 0;
}

static bool create_session(Server *srv, const char *name, char * const argv[]) {
	/* this uses the well known double fork strategy as described in section 1.7 of
	 *
	 *  http://www.faqs.org/faqs/unix-faq/programmer/faq/
	 *
	 * pipes are used for synchronization and error reporting i.e. the child sets
	 * the close on exec flag before calling execvp(3) the parent blocks on a read(2)
	 * in case of failure the error message is written to the pipe, success is
	 * indicated by EOF on the pipe.
	 */
	int client_pipe[2], server_pipe[2];
	pid_t pid;
	char errormsg[255];
	struct sigaction sa;

	if (session_exists(srv, name)) {
		errno = EADDRINUSE;
		return false;
	}

	if (pipe(client_pipe) == -1)
		return false;
	if ((srv->socket = server_create_socket(name)) == -1)
		return false;

	switch ((pid = fork())) {
	case 0: /* child process */
		setsid();
		close(client_pipe[0]);
		switch ((pid = fork())) {
		case 0: /* child process */
			if (pipe(server_pipe) == -1) {
				snprintf(errormsg, sizeof(errormsg), "server-pipe: %s\n", strerror(errno));
				write_all(client_pipe[1], errormsg, strlen(errormsg));
				close(client_pipe[1]);
				_exit(EXIT_FAILURE);
			}
			sa.sa_flags = 0;
			sigemptyset(&sa.sa_mask);
			sa.sa_handler = server_pty_died_handler;
			sigaction(SIGCHLD, &sa, NULL);
			switch (srv->pid = forkpty(&srv->pty, NULL, srv->term, &srv->winsize)) {
			case 0: /* child = user application process */
				close(srv->socket);
				close(server_pipe[0]);
				if (fcntl(client_pipe[1], F_SETFD, FD_CLOEXEC) == 0 &&
				    fcntl(server_pipe[1], F_SETFD, FD_CLOEXEC) == 0)
					execvp(argv[0], argv);
				snprintf(errormsg, sizeof(errormsg), "server-execvp: %s: %s\n",
						 argv[0], strerror(errno));
				write_all(client_pipe[1], errormsg, strlen(errormsg));
				write_all(server_pipe[1], errormsg, strlen(errormsg));
				close(client_pipe[1]);
				close(server_pipe[1]);
				_exit(EXIT_FAILURE);
				break;
			case -1: /* forkpty failed */
				snprintf(errormsg, sizeof(errormsg), "server-forkpty: %s\n", strerror(errno));
				write_all(client_pipe[1], errormsg, strlen(errormsg));
				close(client_pipe[1]);
				close(server_pipe[0]);
				close(server_pipe[1]);
				_exit(EXIT_FAILURE);
				break;
			default: /* parent = server process */
				sa.sa_handler = server_sigterm_handler;
				sigaction(SIGTERM, &sa, NULL);
				sigaction(SIGINT, &sa, NULL);
				sa.sa_handler = server_sigusr1_handler;
				sigaction(SIGUSR1, &sa, NULL);
				sa.sa_handler = SIG_IGN;
				sigaction(SIGPIPE, &sa, NULL);
				sigaction(SIGHUP, &sa, NULL);
				if (chdir("/") == -1)
					_exit(EXIT_FAILURE);
			#ifdef NDEBUG
				int fd = open("/dev/null", O_RDWR);
				if (fd != -1) {
					dup2(fd, STDIN_FILENO);
					dup2(fd, STDOUT_FILENO);
					dup2(fd, STDERR_FILENO);
					close(fd);
				}
			#endif /* NDEBUG */
				close(client_pipe[1]);
				close(server_pipe[1]);
				if (read_all(server_pipe[0], errormsg, sizeof(errormsg)) > 0)
					_exit(EXIT_FAILURE);
				close(server_pipe[0]);
				server_mainloop(srv);
				break;
			}
			break;
		case -1: /* fork failed */
			snprintf(errormsg, sizeof(errormsg), "server-fork: %s\n", strerror(errno));
			write_all(client_pipe[1], errormsg, strlen(errormsg));
			close(client_pipe[1]);
			_exit(EXIT_FAILURE);
			break;
		default: /* parent = intermediate process */
			close(client_pipe[1]);
			_exit(EXIT_SUCCESS);
			break;
		}
		break;
	case -1: /* fork failed */
		close(client_pipe[0]);
		close(client_pipe[1]);
		return false;
	default: /* parent = client process */
		close(client_pipe[1]);
		while (waitpid(pid, NULL, 0) == -1 && errno == EINTR);
		ssize_t len = read_all(client_pipe[0], errormsg, sizeof(errormsg));
		if (len > 0) {
			write_all(STDERR_FILENO, errormsg, (size_t)len);
			session_unlink_socket();
			exit(EXIT_FAILURE);
		}
		close(client_pipe[0]);
	}
	return true;
}

static bool attach_session(Server *srv, const char *name, const bool terminate) {
	if (srv->socket > 0)
		close(srv->socket);
	if ((srv->socket = session_connect(srv, name)) == -1)
		return false;
	if (server_set_socket_non_blocking(srv->socket) == -1)
		return false;

	struct sigaction sa;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = client_sigwinch_handler;
	sigaction(SIGWINCH, &sa, NULL);
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);

	client_setup_terminal();
	int status = client_mainloop(srv);
	client_restore_terminal();
	if (status == -1) {
		info(srv, "detached");
	} else if (status == -EIO) {
		info(srv, "exited due to I/O errors");
	} else {
		info(srv, "session terminated with exit status %d", status);
		if (terminate)
			exit(status);
	}

	return terminate;
}

static int session_comparator(const struct dirent **a, const struct dirent **b) {
	struct stat sa, sb;
	if (stat((*a)->d_name, &sa) != 0)
		return -1;
	if (stat((*b)->d_name, &sb) != 0)
		return 1;
	return sa.st_atime < sb.st_atime ? -1 : 1;
}

static int list_session(Server *srv) {
	if (!session_set_socket_dir(srv))
		return 1;
	if (chdir(session_socket_path()) == -1)
		die("list-session");
	struct dirent **namelist;
	int n = scandir(session_socket_path(), &namelist, NULL, session_comparator);
	if (n < 0)
		return 1;
	printf("Active sessions (on host %s)\n", srv->host+1);
	while (n--) {
		struct stat sb; char buf[255];
		if (stat(namelist[n]->d_name, &sb) == 0 && S_ISSOCK(sb.st_mode)) {
			pid_t pid = 0;
			strftime(buf, sizeof(buf), "%a%t %F %T", localtime(&sb.st_mtime));
			char status = ' ';
			char *local = strstr(namelist[n]->d_name, srv->host);
			if (!local)
				continue;
			*local = '\0'; /* truncate hostname if we are local */
			if (!(pid = session_exists(srv, namelist[n]->d_name)))
				continue;
			if (sb.st_mode & S_IXUSR)
				status = '*';
			else if (sb.st_mode & S_IXGRP)
				status = '+';
			printf("%c %s\t%jd\t%s\n", status, buf, (intmax_t)pid, namelist[n]->d_name);
		}
		free(namelist[n]);
	}
	free(namelist);
	return 0;
}

int main(int argc, char *argv[]) {
	int opt;
	bool force = false;
	bool passthrough = false;
	Server server = {
		.running = true,
		.exit_status = -1,
		.host = "@localhost",
		.screen_max_rows = 120,
	};
	Server *srv = &server;
	char **cmd = NULL, action = '\0';

	char *default_cmd[4] = { "/bin/sh", "-c", getenv("ABDUCO_CMD"), NULL };
	if (!default_cmd[2]) {
		default_cmd[0] = ABDUCO_CMD;
		default_cmd[1] = NULL;
	}

	srv->name = basename(argv[0]);
	gethostname(srv->host+1, sizeof(srv->host) - 1);
	server_set_active(srv);

	while ((opt = getopt(argc, argv, "aAcdlne:fhpqrvL:")) != -1) {
		switch (opt) {
		case 'a':
		case 'A':
		case 'c':
		case 'd':
		case 'n':
			action = (char)opt;
			break;
		case 'e':
			if (!optarg)
				usage();
			if (optarg[0] == '^' && optarg[1])
				optarg[0] = CTRL(optarg[1]);
			KEY_DETACH = optarg[0];
			break;
		case 'f':
			force = true;
			break;
		case 'h':
			help();
			break;
		case 'p':
			passthrough = true;
			break;
		case 'q':
			quiet = true;
			break;
		case 'r':
			client_add_flags(CLIENT_READONLY);
			break;
		case 'l':
			client_add_flags(CLIENT_LOWPRIORITY);
			break;
		case 'L':
			if (!optarg)
				 usage();
			{
				char *endptr;
				errno = 0;
				long val = strtol(optarg, &endptr, 10);
				if (errno == ERANGE || endptr == optarg || *endptr != '\0' || val < 0 || val > INT_MAX) {
					fputs("ERROR: invalid value for -L (must be a non-negative integer).\n", stderr);
					usage();
				}
				srv->screen_max_rows = (int)val;
			}
			break;
		case 'v':
			puts("abduco-"VERSION" © 2013-2018 Marc André Tanner");
			exit(EXIT_SUCCESS);
		default:
			usage();
		}
	}

	/* collect the session name if trailing args */
	if (optind < argc)
		srv->session_name = argv[optind];

	/* if yet more trailing arguments, they must be the command */
	if (optind + 1 < argc)
		cmd = &argv[optind + 1];
	else
		cmd = default_cmd;

	if (srv->session_name && !isatty(STDIN_FILENO))
		passthrough = true;

	if (passthrough) {
		if (!action)
			action = 'a';
		quiet = true;
		client_add_flags(CLIENT_LOWPRIORITY);
	}
	client_set_passthrough(passthrough);
	client_set_keys(KEY_DETACH, KEY_REDRAW);

	if (!action && !srv->session_name)
		exit(list_session(srv));
	if (!action || !srv->session_name)
		usage();

	if (!passthrough)
		srv->term = client_capture_terminal();

	if (ioctl(STDIN_FILENO, TIOCGWINSZ, &srv->winsize) == -1) {
		srv->winsize.ws_col = 80;
		srv->winsize.ws_row = 25;
	}

	srv->read_pty = (action == 'n');

	redo:
	switch (action) {
	case 'n':
	case 'c':
		if (force) {
			if (session_alive(srv, srv->session_name)) {
				info(srv, "session exists and has not yet terminated");
				return 1;
			}
			if (session_exists(srv, srv->session_name))
				attach_session(srv, srv->session_name, false);
		}
		if (!create_session(srv, srv->session_name, cmd))
			die("create-session");
		if (action == 'n')
			break;
		/* fall through */
	case 'a':
		if (!attach_session(srv, srv->session_name, true))
			die("attach-session");
		break;
	case 'A':
		if (session_alive(srv, srv->session_name)) {
			if (!attach_session(srv, srv->session_name, true))
				die("attach-session");
		} else if (!attach_session(srv, srv->session_name, !force)) {
			force = false;
			action = 'c';
			goto redo;
		}
		break;
	case 'd':
		if (session_exists(srv, srv->session_name)) {
			return EXIT_SUCCESS;
		} else {
			return EXIT_FAILURE;
		}
		break;
	}

	return 0;
}
