// SPDX-License-Identifier: ISC
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "debug.h"
#include "io.h"
#include "session.h"
#include "server.h"

static Server *active_server;

#define FD_SET_MAX(fd, set, maxfd) do { \
		FD_SET(fd, set);        \
		if (fd > maxfd)         \
			maxfd = fd;     \
	} while (0)

static const char *client_state_name(int state) {
	switch (state) {
	case STATE_CONNECTED:
		return "connected";
	case STATE_ATTACHED:
		return "attached";
	case STATE_DETACHED:
		return "detached";
	case STATE_DISCONNECTED:
		return "disconnected";
	default:
		return "unknown";
	}
}

static Client *client_malloc(int socket) {
	Client *c = calloc(1, sizeof(Client));
	if (!c)
		return NULL;
	c->socket = socket;
	return c;
}

static void client_free(Client *c) {
	if (c && c->socket > 0)
		close(c->socket);
	free(c);
}

static void server_sink_client(Server *srv) {
	if (!srv->clients || !srv->clients->next)
		return;
	Client *target = srv->clients;
	srv->clients = target->next;
	Client *dst = srv->clients;
	while (dst->next)
		dst = dst->next;
	target->next = NULL;
	dst->next = target;
}

static void server_mark_socket_exec(bool exec, bool usr) {
	struct stat sb;
	if (stat(session_socket_path(), &sb) == -1) {
		debug_errno("server-socket-mode: stat failed path=%s",
		            session_socket_path());
		return;
	}
	mode_t mode = sb.st_mode;
	mode_t flag = usr ? S_IXUSR : S_IXGRP;
	if (exec)
		mode |= flag;
	else
		mode &= ~flag;
	if (chmod(session_socket_path(), mode) == -1) {
		debug_errno("server-socket-mode: chmod failed path=%s mode=%o",
		            session_socket_path(), mode);
	}
}

int server_create_socket(const char *name) {
	if (!session_set_socket_name(active_server, name)) {
		debug("server-create-socket: invalid session name=%s\n", name);
		return -1;
	}
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		debug_errno("server-create-socket: socket failed");
		return -1;
	}
	mode_t mask = umask(S_IXUSR|S_IRWXG|S_IRWXO);
	int r = session_socket_bind(fd);
	umask(mask);

	if (r == -1) {
		debug_errno("server-create-socket: bind failed fd=%d path=%s",
		            fd, session_socket_path());
		close(fd);
		return -1;
	}

	if (listen(fd, 5) == -1) {
		debug_errno("server-create-socket: listen failed fd=%d", fd);
		session_unlink_socket();
		close(fd);
		return -1;
	}

	return fd;
}

int server_set_socket_non_blocking(int sock) {
	int flags;
	if ((flags = fcntl(sock, F_GETFL, 0)) == -1) {
		debug_errno("server-nonblock: F_GETFL failed fd=%d", sock);
		flags = 0;
	}
	return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

void server_set_active(Server *srv) {
	active_server = srv;
}

static bool server_read_pty(Server *srv, Packet *pkt) {
	pkt->type = MSG_CONTENT;
	ssize_t len = read(srv->pty, pkt->u.msg, sizeof(pkt->u.msg));
	if (len > 0) {
		pkt->len = (uint32_t)len;
		print_packet("server-read-pty:", pkt);
	} else if (len == 0) {
		debug("server-read-pty: EOF pty=%d\n", srv->pty);
		srv->running = false;
	} else if (len == -1 && errno != EAGAIN && errno != EINTR && errno != EWOULDBLOCK) {
		debug_errno("server-read-pty: failed pty=%d", srv->pty);
		srv->running = false;
	}
	return len > 0;
}

static bool server_write_pty(Server *srv, Packet *pkt) {
	print_packet("server-write-pty:", pkt);
	size_t size = pkt->len;
	ssize_t written = write_all(srv->pty, pkt->u.msg, size);
	if (written >= 0 && (size_t)written == size)
		return true;
	debug_errno("server-write-pty: failed pty=%d type=%"PRIu32" len=%"PRIu32" written=%zd",
	            srv->pty, pkt->type, pkt->len, written);
	srv->running = false;
	return false;
}

static bool server_recv_packet(Client *c, Packet *pkt) {
	if (recv_packet(c->socket, pkt)) {
		print_packet("server-recv:", pkt);
		return true;
	}
	debug_errno("server-recv: failed client-fd=%d state=%s",
	            c->socket, client_state_name(c->state));
	c->state = STATE_DISCONNECTED;
	return false;
}

static bool server_send_packet(Client *c, Packet *pkt) {
	print_packet("server-send:", pkt);
	if (send_packet(c->socket, pkt))
		return true;
	debug_errno("server-send: failed client-fd=%d state=%s type=%"PRIu32" len=%"PRIu32,
	            c->socket, client_state_name(c->state), pkt->type, pkt->len);
	c->state = STATE_DISCONNECTED;
	return false;
}

void server_pty_died_handler(int sig) {
	(void)sig;
	Server *srv = active_server;
	int errsv = errno;
	pid_t pid;
	pid_t child = -1;

	if (!srv)
		return;

	while ((pid = waitpid(-1, &srv->exit_status, WNOHANG)) != 0) {
		if (pid == -1)
			break;
		child = pid;
		srv->exit_status = WEXITSTATUS(srv->exit_status);
		server_mark_socket_exec(true, false);
	}

	debug("server-pty-died: pid=%d exit-status=%d\n", child, srv->exit_status);
	errno = errsv;
}

void server_sigterm_handler(int sig) {
	(void)sig;
	exit(EXIT_FAILURE); /* invoke atexit handler */
}

static Client *server_accept_client(Server *srv) {
	int newfd = accept(srv->socket, NULL, NULL);
	if (newfd == -1) {
		debug_errno("server-accept: failed socket=%d", srv->socket);
		goto error;
	}
	if (server_set_socket_non_blocking(newfd) == -1) {
		debug_errno("server-accept: nonblock failed client-fd=%d", newfd);
		goto error;
	}
	Client *c = client_malloc(newfd);
	if (!c) {
		debug_errno("server-accept: client allocation failed client-fd=%d",
		            newfd);
		goto error;
	}
	if (!srv->clients)
		server_mark_socket_exec(true, true);
	c->socket = newfd;
	c->state = STATE_CONNECTED;
	c->next = srv->clients;
	srv->clients = c;
	srv->read_pty = true;
	debug("server-accept: client-fd=%d state=%s\n",
	      c->socket, client_state_name(c->state));

	Packet pkt = {
		.type = MSG_PID,
		.len = sizeof pkt.u.l,
		.u.l = (uint64_t)getpid(),
	};
	server_send_packet(c, &pkt);

	return c;
error:
	if (newfd != -1)
		close(newfd);
	return NULL;
}

void server_sigusr1_handler(int sig) {
	(void)sig;
	Server *srv = active_server;
	if (!srv)
		return;
	int socket = server_create_socket(srv->session_name);
	if (socket != -1) {
		debug("server-sigusr1: recreated socket old-fd=%d new-fd=%d\n",
		      srv->socket, socket);
		if (srv->socket)
			close(srv->socket);
		srv->socket = socket;
	} else {
		debug("server-sigusr1: socket recreation failed session=%s\n",
		      srv->session_name);
	}
}

static void server_send_screen_buffer(Server *srv, Client *c) {
	struct entry *np;

	TAILQ_FOREACH_REVERSE(np, &srv->screen, screenhead, entries) {
		size_t offset = 0;
		while (offset < np->len) {
			Packet pkt = { .type = MSG_CONTENT };
			size_t chunk = np->len - offset;
			if (chunk > sizeof(pkt.u.msg))
				chunk = sizeof(pkt.u.msg);
			pkt.len = (uint32_t)chunk;
			memcpy(pkt.u.msg, np->data + offset, chunk);
			server_send_packet(c, &pkt);
			offset += chunk;
		}
	}
}

static void server_preserve_screen_data(Server *srv, Packet *pkt) {
	char *str, *end;
	uint32_t len;
	struct entry *scrline = NULL;

	if (srv->screen_max_rows == 0 || pkt->len <= 0 || pkt->type != MSG_CONTENT)
		return;

	str = pkt->u.msg;
	len = pkt->len;
	end = str + len;

	while (str != end) {
		char *data;
		uint32_t dlen;

		bool newline = false;
		char *token = end;

		char *nl = memchr(str, '\n', len);
		if (nl) {
			token = nl + 1;
			newline = true;
		}

		ptrdiff_t diff = token - str;
		if (diff == 0)
			break;
		dlen = (uint32_t)diff;

		scrline = TAILQ_FIRST(&srv->screen);

		if (scrline && !scrline->complete) {
			/* Extend existing incomplete line */
			char *old_data = scrline->data;
			data = realloc(old_data, scrline->len + dlen);
			if (!data) {
				/* realloc failed: old_data still valid, don't leak it */
				die("unable to extend string in the screen buffer");
			}

			memcpy(data + scrline->len, str, dlen);

			scrline->complete = newline;
			scrline->data = data;
			scrline->len += dlen;
		} else {
			data = malloc(dlen);
			if (!data)
				die("unable to allocate memory for new line in the screen buffer");

			memcpy(data, str, dlen);

			scrline = malloc(sizeof(*scrline));
			if (!scrline) {
				free(data);
				die("unable to allocate memory for screen buffer element");
			}

			scrline->complete = newline;
			scrline->data = data;
			scrline->len = dlen;

			TAILQ_INSERT_HEAD(&srv->screen, scrline, entries);
			srv->screen_rows++;

			if (srv->screen_rows > srv->screen_max_rows) {
				scrline = TAILQ_LAST(&srv->screen, screenhead);
				TAILQ_REMOVE(&srv->screen, scrline, entries);
				free(scrline->data);
				free(scrline);
				srv->screen_rows--;
			}
		}

		str = token;
		len -= dlen;
	}
}

void server_mainloop(Server *srv) {
	server_set_active(srv);
	atexit(session_unlink_socket);
	fd_set new_readfds, new_writefds;
	FD_ZERO(&new_readfds);
	FD_ZERO(&new_writefds);
	FD_SET(srv->socket, &new_readfds);
	int new_fdmax = srv->socket;
	bool exit_packet_delivered = false;

	TAILQ_INIT(&srv->screen);

	if (srv->read_pty)
		FD_SET_MAX(srv->pty, &new_readfds, new_fdmax);

	while (srv->clients || !exit_packet_delivered) {
		int fdmax = new_fdmax;
		fd_set readfds = new_readfds;
		fd_set writefds = new_writefds;
		FD_SET_MAX(srv->socket, &readfds, fdmax);

		if (select(fdmax+1, &readfds, &writefds, NULL, NULL) == -1) {
			if (errno == EINTR)
				continue;
			die("server-mainloop");
		}

		FD_ZERO(&new_readfds);
		FD_ZERO(&new_writefds);
		new_fdmax = srv->socket;

		bool pty_data = false;

		Packet server_packet, client_packet;

		if (FD_ISSET(srv->socket, &readfds))
			server_accept_client(srv);

		if (FD_ISSET(srv->pty, &readfds)) {
			pty_data = server_read_pty(srv, &server_packet);
			if (pty_data)
				server_preserve_screen_data(srv, &server_packet);
		}

		for (Client **prev_next = &srv->clients, *c = srv->clients; c;) {
			if (FD_ISSET(c->socket, &readfds) && server_recv_packet(c, &client_packet)) {
				switch (client_packet.type) {
				case MSG_CONTENT:
					server_write_pty(srv, &client_packet);
					break;
				case MSG_ATTACH:
					c->flags = client_packet.u.i;
					debug("server-attach: client-fd=%d flags=0x%"PRIx32" readonly=%d low-priority=%d\n",
					      c->socket, (uint32_t)c->flags,
					      !!(c->flags & CLIENT_READONLY),
					      !!(c->flags & CLIENT_LOWPRIORITY));
					if (c->flags & CLIENT_LOWPRIORITY)
						server_sink_client(srv);
					server_send_screen_buffer(srv, c);
					break;
				case MSG_RESIZE: {
						pid_t group_id;

						c->state = STATE_ATTACHED;
						if (!(c->flags & CLIENT_READONLY) && c == srv->clients) {
							struct winsize ws = { 0 };
							ws.ws_row = client_packet.u.ws.rows;
							ws.ws_col = client_packet.u.ws.cols;
							if (ioctl(srv->pty, TIOCSWINSZ, &ws) == -1) {
								debug_errno("server-resize: ioctl failed pty=%d cols=%"PRIu16" rows=%"PRIu16,
								            srv->pty, (uint16_t)ws.ws_col,
								            (uint16_t)ws.ws_row);
							} else {
								debug("server-resize: pty=%d cols=%"PRIu16" rows=%"PRIu16"\n",
								      srv->pty, (uint16_t)ws.ws_col,
								      (uint16_t)ws.ws_row);
							}
						}

						group_id = tcgetpgrp(srv->pty);
						if (group_id == -1) {
							debug_errno("server-resize: tcgetpgrp failed pty=%d",
							            srv->pty);
						} else if (kill(-group_id, SIGWINCH) == -1) {
							debug_errno("server-resize: SIGWINCH failed pty=%d pgrp=%d",
							            srv->pty, group_id);
						}
						break;
					}
				case MSG_STDIN_EOF: {
					/* Forward EOF to pty - application sees EOF on stdin */
					struct termios t;
					if (tcgetattr(srv->pty, &t) == 0) {
						char eof_char = t.c_cc[VEOF];
						if (write(srv->pty, &eof_char, 1) < 0) {
							debug_errno("server-stdin-eof: write failed pty=%d",
							            srv->pty);
						}
					} else {
						debug_errno("server-stdin-eof: tcgetattr failed pty=%d",
						            srv->pty);
					}
					break;
				}
				case MSG_EXIT:
					exit_packet_delivered = true;
					/* fall through */
				case MSG_DETACH:
					debug("server-disconnect: client-fd=%d reason=%s\n",
					      c->socket,
					      client_packet.type == MSG_EXIT ? "exit" : "detach");
					c->state = STATE_DISCONNECTED;
					break;
				default: /* ignore package */
					break;
				}
			}

			if (c->state == STATE_DISCONNECTED) {
				bool first = (c == srv->clients);
				int socket = c->socket;
				Client *t = c->next;
				if (c->msg_exit_sent)
					exit_packet_delivered = true;
				client_free(c);
				debug("server-client-free: client-fd=%d first=%d remaining=%d\n",
				      socket, first, t != NULL);
				*prev_next = c = t;
				if (first && srv->clients) {
					Packet pkt = {
						.type = MSG_RESIZE,
						.len = 0,
					};
					server_send_packet(srv->clients, &pkt);
				} else if (!srv->clients) {
					server_mark_socket_exec(false, true);
				}
				continue;
			}

			FD_SET_MAX(c->socket, &new_readfds, new_fdmax);

			if (pty_data)
				server_send_packet(c, &server_packet);
			if (!srv->running) {
				if (srv->exit_status != -1) {
					Packet pkt = {
						.type = MSG_EXIT,
						.u.i = (uint32_t)srv->exit_status,
						.len = sizeof(pkt.u.i),
					};
					if (server_send_packet(c, &pkt))
						c->msg_exit_sent = true;
					else
						FD_SET_MAX(c->socket, &new_writefds, new_fdmax);
				} else {
					FD_SET_MAX(c->socket, &new_writefds, new_fdmax);
				}
			}
			prev_next = &c->next;
			c = c->next;
		}

		if (srv->running && srv->read_pty)
			FD_SET_MAX(srv->pty, &new_readfds, new_fdmax);
	}

	struct entry *n1, *n2;

	n1 = TAILQ_FIRST(&srv->screen);
	while (n1 != NULL) {
		n2 = TAILQ_NEXT(n1, entries);
		free(n1->data);
		free(n1);
		n1 = n2;
	}

	exit(EXIT_SUCCESS);
}
