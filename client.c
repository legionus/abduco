// SPDX-License-Identifier: ISC
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>

#include "client.h"
#include "debug.h"
#include "io.h"

static Client client;
static struct termios orig_term, cur_term;
static bool has_term, alternate_buffer, passthrough;
static char detach_key, redraw_key;

void client_sigwinch_handler(int sig) {
	(void)sig;
	client.need_resize = true;
}

static bool client_send_packet(Server *srv, Packet *pkt) {
	print_packet("client-send:", pkt);
	if (send_packet(srv->socket, pkt))
		return true;
	debug_errno("client-send: failed socket=%d type=%"PRIu32" len=%"PRIu32,
	            srv->socket, pkt->type, pkt->len);
	srv->running = false;
	return false;
}

bool client_recv_packet(Server *srv, Packet *pkt) {
	if (recv_packet(srv->socket, pkt)) {
		print_packet("client-recv:", pkt);
		return true;
	}
	debug_errno("client-recv: failed socket=%d", srv->socket);
	srv->running = false;
	return false;
}

void client_add_flags(int flags) {
	client.flags |= (unsigned int)flags;
}

void client_set_keys(char detach, char redraw) {
	detach_key = detach;
	redraw_key = redraw;
}

void client_set_passthrough(bool enabled) {
	passthrough = enabled;
}

struct termios *client_capture_terminal(void) {
	if (tcgetattr(STDIN_FILENO, &orig_term) == -1) {
		debug_errno("client-terminal: tcgetattr failed fd=%d", STDIN_FILENO);
		return NULL;
	}
	has_term = true;
	return &orig_term;
}

void client_restore_terminal(void) {
	if (!has_term)
		return;
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_term) == -1) {
		debug_errno("client-terminal: restore failed fd=%d", STDIN_FILENO);
	}
	if (alternate_buffer) {
		printf("\033[?25h\033[?1049l");
		fflush(stdout);
		alternate_buffer = false;
	}
}

void client_setup_terminal(void) {
	if (!has_term)
		return;
	atexit(client_restore_terminal);

	cur_term = orig_term;
	cur_term.c_iflag &= ~(tcflag_t)(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON|IXOFF);
	cur_term.c_oflag &= ~(tcflag_t)(OPOST);
	cur_term.c_lflag &= ~(tcflag_t)(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
	cur_term.c_cflag &= ~(tcflag_t)(CSIZE|PARENB);
	cur_term.c_cflag |= CS8;
	cur_term.c_cc[VLNEXT] = _POSIX_VDISABLE;
	cur_term.c_cc[VMIN] = 1;
	cur_term.c_cc[VTIME] = 0;
	if (tcsetattr(STDIN_FILENO, TCSANOW, &cur_term) == -1) {
		debug_errno("client-terminal: setup failed fd=%d", STDIN_FILENO);
	}

	if (!alternate_buffer) {
		printf("\033[?1049h\033[H");
		fflush(stdout);
		alternate_buffer = true;
	}
}

int client_mainloop(Server *srv) {
	sigset_t emptyset, blockset;
	sigemptyset(&emptyset);
	sigemptyset(&blockset);
	sigaddset(&blockset, SIGWINCH);
	sigprocmask(SIG_BLOCK, &blockset, NULL);

	bool stdin_eof = false;
	client.need_resize = true;
	Packet pkt = {
		.type = MSG_ATTACH,
		.u.i = client.flags,
		.len = sizeof(pkt.u.i),
	};
	client_send_packet(srv, &pkt);

	while (srv->running) {
		fd_set fds;
		FD_ZERO(&fds);
		if (!stdin_eof)
			FD_SET(STDIN_FILENO, &fds);
		FD_SET(srv->socket, &fds);

		if (client.need_resize) {
			struct winsize ws;
			if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) != -1) {
				Packet resize_pkt = {
					.type = MSG_RESIZE,
					.u = { .ws = { .rows = ws.ws_row, .cols = ws.ws_col } },
					.len = sizeof(resize_pkt.u.ws),
				};
				if (client_send_packet(srv, &resize_pkt))
					client.need_resize = false;
			} else {
				debug_errno("client-resize: TIOCGWINSZ failed fd=%d",
				            STDIN_FILENO);
			}
		}

		if (pselect(srv->socket+1, &fds, NULL, NULL, NULL, &emptyset) == -1) {
			if (errno == EINTR)
				continue;
			die("client-mainloop");
		}

		if (FD_ISSET(srv->socket, &fds)) {
			Packet recv_pkt;
			if (client_recv_packet(srv, &recv_pkt)) {
				switch (recv_pkt.type) {
				case MSG_CONTENT:
					if (!passthrough)
						write_all(STDOUT_FILENO, recv_pkt.u.msg, recv_pkt.len);
					break;
				case MSG_RESIZE:
					client.need_resize = true;
					break;
				case MSG_EXIT:
					client_send_packet(srv, &recv_pkt);
					close(srv->socket);
					return (int)recv_pkt.u.i;
				}
			}
		}

		if (FD_ISSET(STDIN_FILENO, &fds)) {
			Packet stdin_pkt = { .type = MSG_CONTENT };
			ssize_t len = read(STDIN_FILENO, stdin_pkt.u.msg, sizeof(stdin_pkt.u.msg));
			if (len == -1 && errno != EAGAIN && errno != EINTR)
				die("client-stdin");
			if (len > 0) {
				stdin_pkt.len = (uint32_t)len;
				if (redraw_key && stdin_pkt.u.msg[0] == redraw_key) {
					debug("client-stdin: redraw key received\n");
					client.need_resize = true;
				} else if (stdin_pkt.u.msg[0] == detach_key) {
					debug("client-stdin: detach key received\n");
					stdin_pkt.type = MSG_DETACH;
					stdin_pkt.len = 0;
					client_send_packet(srv, &stdin_pkt);
					close(srv->socket);
					return -1;
				} else if (!(client.flags & CLIENT_READONLY)) {
					client_send_packet(srv, &stdin_pkt);
				}
			} else if (len == 0) {
				debug("client-stdin: EOF, forwarding MSG_STDIN_EOF\n");
				Packet eof_pkt = { .type = MSG_STDIN_EOF, .len = 0 };
				client_send_packet(srv, &eof_pkt);
				stdin_eof = true;
			}
		}
	}

	return -EIO;
}
