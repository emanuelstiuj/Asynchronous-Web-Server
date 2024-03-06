// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/sendfile.h>
#include <sys/eventfd.h>
#include <libaio.h>
#include <errno.h>
#include <time.h>

#include "aws.h"
#include "utils/util.h"
#include "utils/debug.h"
#include "utils/sock_util.h"
#include "utils/w_epoll.h"

/* server socket file descriptor */
static int listenfd;

/* epoll file descriptor */
static int epollfd;

static io_context_t ctx;

static int aws_on_path_cb(http_parser *p, const char *buf, size_t len)
{
	struct connection *conn = (struct connection *)p->data;

	memcpy(conn->request_path, buf, len);
	conn->request_path[len] = '\0';
	conn->have_path = 1;

	return 0;
}

static void connection_prepare_send_reply_header(struct connection *conn)
{
	/* TODO: Prepare the connection buffer to send the reply header. */
	memset(conn->send_buffer, 0, sizeof(conn->send_buffer));
	sprintf(conn->send_buffer, "HTTP/1.1 200 OK Contet-Length: %ld\r\n\r\n", conn->file_size);
	conn->send_len = strlen(conn->send_buffer);
}

static void connection_prepare_send_404(struct connection *conn)
{
	/* TODO: Prepare the connection buffer to send the 404 header. */
	memset(conn->send_buffer, 0, sizeof(conn->send_buffer));
	sprintf(conn->send_buffer, "HTTP/1.1 404 Not Found Content-Length: 0\r\n\r\n");
	conn->send_len = strlen(conn->send_buffer);
	conn->file_size = 0;
}

struct connection *connection_create(int sockfd)
{
	/* TODO: Initialize connection structure on given socket. */
	struct connection *conn_handler;

	conn_handler = (struct connection *) calloc(1, sizeof(struct connection));
	DIE(conn_handler == NULL, "malloc");

	conn_handler->sockfd = sockfd;
	memset(conn_handler->recv_buffer, 0, sizeof(conn_handler->recv_buffer));
	memset(conn_handler->send_buffer, 0, sizeof(conn_handler->send_buffer));
	memset(conn_handler->request_path, 0, sizeof(conn_handler->request_path));
	memset(conn_handler->filename, 0, sizeof(conn_handler->filename));
	conn_handler->fd = -1;

	return conn_handler;
}

void connection_remove(struct connection *conn)
{
	/* TODO: Remove connection handler. */
	int rc;

	rc = close(conn->sockfd);
	DIE(rc < 0, "close");

	if (conn->fd >= 0) {
		rc = close(conn->fd);
		DIE(rc < 0, "close");
	}

	free(conn);
}

struct connection *handle_new_connection(void)
{
	/* TODO: Handle a new connection request on the server socket. */
	int rc, connection_fd;
	struct sockaddr_in client_addr;
	struct connection *conn_handler;
	socklen_t addrlen = sizeof(struct sockaddr_in);

	/* TODO: Accept new connection. */
	connection_fd = accept(listenfd, (struct sockaddr *) &client_addr, &addrlen);
	DIE(connection_fd < 0, "accept");
	dlog(LOG_INFO, "Accepted connection from %s:%d\n",
			inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

	/* TODO: Set socket to be non-blocking. */
	int fcntl_flags;

	fcntl_flags = fcntl(connection_fd, F_GETFL, 0);
	DIE(fcntl_flags < 0, "fcntl");
	rc = fcntl(connection_fd, F_SETFL, fcntl_flags | O_NONBLOCK);
	DIE(rc < 0, "fcntl");

	/* TODO: Instantiate new connection handler. */
	conn_handler = connection_create(connection_fd);

	/* TODO: Add socket to epoll. */
	rc = w_epoll_add_ptr_in(epollfd, connection_fd, (void *) conn_handler);
	DIE(rc < 0, "w_epoll_add_ptr_inout");

	/* TODO: Initialize HTTP_REQUEST parser. */
	http_parser_init(&(conn_handler->request_parser), HTTP_REQUEST);

	return conn_handler;
}

int connection_open_file(struct connection *conn)
{
	/* TODO: Open file and update connection fields. */

	char path[BUFSIZ];

	memset(path, 0, BUFSIZ);
	path[0] = '.';
	strcat(path, conn->request_path);

	conn->fd = open(path, O_RDWR);

	if (conn->fd > 0) {
		//200
		conn->state = STATE_SENDING_HEADER;
		if (strstr(conn->request_path, "static/"))
			conn->res_type = RESOURCE_TYPE_STATIC;
		else
			conn->res_type = RESOURCE_TYPE_DYNAMIC;
	} else {
		//404
		conn->state = STATE_SENDING_404;
		conn->res_type = RESOURCE_TYPE_NONE;
	}

	return conn->fd;
}

int parse_header(struct connection *conn)
{
	/* TODO: Parse the HTTP header and extract the file path. */
	/* Use mostly null settings except for on_path callback. */
	int rc;

	http_parser_settings settings_on_path = {
		.on_message_begin = 0,
		.on_header_field = 0,
		.on_header_value = 0,
		.on_path = aws_on_path_cb,
		.on_url = 0,
		.on_fragment = 0,
		.on_query_string = 0,
		.on_body = 0,
		.on_headers_complete = 0,
		.on_message_complete = 0
	};

	conn->request_parser.data = conn;
	rc = http_parser_execute(&(conn->request_parser), &settings_on_path, conn->recv_buffer, conn->recv_len);
	return rc;
}

enum connection_state connection_send_static(struct connection *conn)
{
	/* TODO: Send static data using sendfile(2). */

	long remaining_bytes = conn->file_size;
	long bytes_written;
	long total_bytes_written = 0;
	long offset = 0;

	while (1) {
		//offset = total_bytes_written;
		bytes_written = sendfile(conn->sockfd, conn->fd, &offset, remaining_bytes);

		if (bytes_written == 0)
			break;
		if (bytes_written < 0)
			bytes_written = 0;

		remaining_bytes = remaining_bytes - bytes_written;
		total_bytes_written = total_bytes_written + bytes_written;
	}

	return STATE_NO_STATE;
}

void connection_start_async_io(struct connection *conn)
{
	/* TODO: Start asynchronous operation (read from file).
	 * Use io_submit(2) & friends for reading data asynchronously.
	 */

	long send_buff_offset = 0;
	long current_file_size = conn->file_size;
	long bytes_remaining;
	int count_buffers, rc;
	char **buffer;
	struct iocb **piocb;
	struct iocb *iocb;

	conn->eventfd = eventfd(0, 0);

	if (current_file_size % BUFSIZ)
		count_buffers = current_file_size / BUFSIZ + 1;
	else
		count_buffers = current_file_size / BUFSIZ;

	rc = io_setup(count_buffers, &(conn->ctx));

	iocb = malloc(count_buffers * sizeof(struct iocb));
	piocb = malloc(count_buffers * sizeof(struct iocb *));

	buffer = malloc(count_buffers * sizeof(char *));
	for (int i = 0; i < count_buffers - 1; i++)
		buffer[i] = calloc(1, BUFSIZ);

	if (current_file_size % BUFSIZ)
		buffer[count_buffers - 1] = calloc(1, current_file_size % BUFSIZ);
	else
		buffer[count_buffers - 1] = calloc(1, BUFSIZ);

	for (int i = 0; i < count_buffers; i++) {
		piocb[i] = &iocb[i];
		io_set_eventfd(piocb[i], conn->eventfd);
		if (i == count_buffers - 1 && current_file_size % BUFSIZ)
			io_prep_pread(piocb[i], conn->fd, buffer[i], current_file_size % BUFSIZ, BUFSIZ * i);
		else
			io_prep_pread(piocb[i], conn->fd, buffer[i], BUFSIZ, BUFSIZ * i);
	}

	io_submit(conn->ctx, count_buffers, piocb);

	struct io_event events[count_buffers];

	rc = io_getevents(conn->ctx, 1, count_buffers, events, NULL);

	for (int i = 0; i < count_buffers; i++) {
		while (events[i].res < 0)
			;

		send_buff_offset = 0;
		bytes_remaining = BUFSIZ;

		if (i == count_buffers - 1 && current_file_size % BUFSIZ)
			bytes_remaining = current_file_size % BUFSIZ;

		while (bytes_remaining) {
			rc = send(conn->sockfd, buffer[i] + send_buff_offset, bytes_remaining, 0);
			if (rc > 0) {
				bytes_remaining = bytes_remaining - rc;
				send_buff_offset = send_buff_offset + rc;
			}
		}
	}

	free(iocb);
	free(piocb);
	for (int i = 0; i < count_buffers; i++)
		free(buffer[i]);
	free(buffer);

	io_destroy(conn->ctx);
}

int connection_send_data(struct connection *conn)
{
	/* May be used as a helper function. */
	/* TODO: Send as much data as possible from the connection send buffer.
	 * Returns the number of bytes sent or -1 if an error occurred
	 */

	if (conn->state == STATE_SENDING_404 || conn->state == STATE_SENDING_HEADER) {
		ssize_t total_sent = 0;

		while (total_sent < conn->send_len) {
			ssize_t bytes_sent = send(conn->sockfd, conn->send_buffer + total_sent, conn->send_len - total_sent, 0);

			if (bytes_sent > 0)
				total_sent += bytes_sent;
			else
				break;
		}

		if (total_sent == conn->send_len) {
			if (conn->state == STATE_SENDING_404)
				conn->state = STATE_404_SENT;
			else if (conn->state == STATE_SENDING_HEADER)
				conn->state = STATE_HEADER_SENT;
		}
	} else {
		if (conn->res_type == RESOURCE_TYPE_DYNAMIC) {
			connection_start_async_io(conn);
			w_epoll_remove_ptr(epollfd, conn->sockfd, conn);
			connection_remove(conn);
		} else if (conn->res_type == RESOURCE_TYPE_STATIC) {
			connection_send_static(conn);
			w_epoll_remove_ptr(epollfd, conn->sockfd, conn);
			connection_remove(conn);
		}
	}

	return -1;
}

void receive_data(struct connection *conn)
{
	/* TODO: Receive message on socket.
	 * Store message in recv_buffer in struct connection.
	 */
	off_t total_bytes = 0;

	while (1) {
		ssize_t bytes_read = recv(conn->sockfd, conn->recv_buffer + total_bytes, sizeof(conn->recv_buffer) - total_bytes, 0);

		if (bytes_read > 0)
			total_bytes += bytes_read;
		else
			break;
	}
	conn->recv_len = total_bytes;
}

void handle_input(struct connection *conn)
{
	/* TODO: Handle input information: may be a new message or notification of
	 * completion of an asynchronous I/O operation.
	 */
	receive_data(conn);
	parse_header(conn);
	connection_open_file(conn);
	w_epoll_update_ptr_out(epollfd, conn->sockfd, conn);
}

void handle_output(struct connection *conn)
{
	/* TODO: Handle output information: may be a new valid requests or notification of
	 * completion of an asynchronous I/O operation or invalid requests.
	 */

	if (conn->state == STATE_SENDING_404) {
		connection_prepare_send_404(conn);
		connection_send_data(conn);
		w_epoll_remove_ptr(epollfd, conn->sockfd, conn);
		connection_remove(conn);

		return;
	}

	if (conn->state == STATE_SENDING_HEADER) {
		struct stat buffer;

		fstat(conn->fd, &buffer);
		conn->file_size = buffer.st_size;
		connection_prepare_send_reply_header(conn);
		connection_send_data(conn);
	}

	if (conn->state == STATE_HEADER_SENT)
		connection_send_data(conn);
}

void handle_client(uint32_t event, struct connection *conn)
{
	/* TODO: Handle new client. There can be input and output connections.
	 * Take care of what happened at the end of a connection.
	 */
	if (event & EPOLLIN) {
		handle_input(conn);
		return;
	}

	if (event & EPOLLOUT) {
		handle_output(conn);
		return;
	}
}

int main(void)
{
	int rc;

	/* TODO: Initialize asynchronous operations. */
	ctx = 0;
	rc = io_setup(1, &ctx);
	DIE(rc < 0, "io_setup");

	/* TODO: Initialize multiplexing. */
	epollfd = w_epoll_create();
	DIE(epollfd < 0, "w_epoll_create");

	/* TODO: Create server socket. */
	listenfd = tcp_create_listener(AWS_LISTEN_PORT, DEFAULT_LISTEN_BACKLOG);
	DIE(listenfd < 0, "tcp_create_listener");

	/* TODO: Add server socket to epoll object*/
	rc = w_epoll_add_fd_in(epollfd, listenfd);
	DIE(rc < 0, "w_epoll_add_fd_in");

	/* Uncomment the following line for debugging. */
	// dlog(LOG_INFO, "Server waiting for connections on port %d\n", AWS_LISTEN_PORT);

	/* server main loop */
	while (1) {
		struct epoll_event rev;

		/* TODO: Wait for events. */
		rc = w_epoll_wait_infinite(epollfd, &rev);
		DIE(rc < 0, "w_epoll_wait_infinite");

		/* TODO: Switch event types; consider
		 *   - new connection requests (on server socket)
		 *   - socket communication (on connection sockets)
		 */
		if (rev.data.fd == listenfd) {
			dlog(LOG_DEBUG, "NEW CLIENT\n");
			if (rev.events & EPOLLIN)
				rev.data.ptr = handle_new_connection();
		} else {
			dlog(LOG_DEBUG, "HANDLE CLIENT\n");
			handle_client(rev.events, (struct connection *) rev.data.ptr);
		}
	}

	return 0;
}
