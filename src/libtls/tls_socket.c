/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "tls_socket.h"

#include <unistd.h>
#include <errno.h>

#include <utils/debug.h>
#include <threading/thread.h>

/**
 * Buffer size for plain side I/O
 */
#define PLAIN_BUF_SIZE 4096

/**
 * Buffer size for encrypted side I/O
 */
#define CRYPTO_BUF_SIZE 4096

typedef struct private_tls_socket_t private_tls_socket_t;
typedef struct private_tls_application_t private_tls_application_t;

struct private_tls_application_t {

	/**
	 * Implements tls_application layer.
	 */
	tls_application_t application;

	/**
	 * Output buffer to write to
	 */
	chunk_t out;

	/**
	 * Number of bytes written to out
	 */
	size_t out_done;

	/**
	 * Input buffer to read to
	 */
	chunk_t in;

	/**
	 * Number of bytes read to in
	 */
	size_t in_done;

	/**
	 * Cached input data
	 */
	chunk_t cache;

	/**
	 * Bytes cosnumed in cache
	 */
	size_t cache_done;

	/**
	 * Close TLS connection?
	 */
	bool close;
};

/**
 * Private data of an tls_socket_t object.
 */
struct private_tls_socket_t {

	/**
	 * Public tls_socket_t interface.
	 */
	tls_socket_t public;

	/**
	 * TLS application implementation
	 */
	private_tls_application_t app;

	/**
	 * TLS stack
	 */
	tls_t *tls;

	/**
	 * Underlying OS socket
	 */
	int fd;
};

METHOD(tls_application_t, process, status_t,
	private_tls_application_t *this, bio_reader_t *reader)
{
	chunk_t data;
	size_t len;

	if (this->close)
	{
		return SUCCESS;
	}
	len = min(reader->remaining(reader), this->in.len - this->in_done);
	if (len)
	{	/* copy to read buffer as much as fits in */
		if (!reader->read_data(reader, len, &data))
		{
			return FAILED;
		}
		memcpy(this->in.ptr + this->in_done, data.ptr, data.len);
		this->in_done += data.len;
	}
	else
	{	/* read buffer is full, cache for next read */
		if (!reader->read_data(reader, reader->remaining(reader), &data))
		{
			return FAILED;
		}
		this->cache = chunk_cat("mc", this->cache, data);
	}
	return NEED_MORE;
}

METHOD(tls_application_t, build, status_t,
	private_tls_application_t *this, bio_writer_t *writer)
{
	if (this->close)
	{
		return SUCCESS;
	}
	if (this->out.len > this->out_done)
	{
		writer->write_data(writer, this->out);
		this->out_done = this->out.len;
		return NEED_MORE;
	}
	return INVALID_STATE;
}

/**
 * TLS data exchange loop
 */
static bool exchange(private_tls_socket_t *this, bool wr, bool block)
{
	char buf[CRYPTO_BUF_SIZE], *pos;
	ssize_t len, out;
	int round = 0, flags;

	for (round = 0; TRUE; round++)
	{
		while (TRUE)
		{
			len = sizeof(buf);
			switch (this->tls->build(this->tls, buf, &len, NULL))
			{
				case NEED_MORE:
				case ALREADY_DONE:
					pos = buf;
					while (len)
					{
						out = write(this->fd, pos, len);
						if (out == -1)
						{
							DBG1(DBG_TLS, "TLS crypto write error: %s",
								 strerror(errno));
							return FALSE;
						}
						len -= out;
						pos += out;
					}
					continue;
				case INVALID_STATE:
					break;
				case SUCCESS:
					return TRUE;
				default:
					return FALSE;
			}
			break;
		}
		if (wr)
		{
			if (this->app.out_done == this->app.out.len)
			{	/* all data written */
				return TRUE;
			}
		}
		else
		{
			if (this->app.in_done == this->app.in.len)
			{	/* buffer fully received */
				return TRUE;
			}
		}

		flags = 0;
		if (this->app.out_done == this->app.out.len)
		{
			if (!block || this->app.in_done)
			{
				flags |= MSG_DONTWAIT;
			}
		}
		len = recv(this->fd, buf, sizeof(buf), flags);
		if (len < 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
			{
				if (this->app.in_done == 0)
				{
					/* reading, nothing got yet, and call would block */
					errno = EWOULDBLOCK;
					this->app.in_done = -1;
				}
				return TRUE;
			}
			return FALSE;
		}
		if (len == 0)
		{	/* EOF */
			return TRUE;
		}
		switch (this->tls->process(this->tls, buf, len))
		{
			case NEED_MORE:
				break;
			case SUCCESS:
				return TRUE;
			default:
				return FALSE;
		}
	}
}

METHOD(tls_socket_t, read_, ssize_t,
	private_tls_socket_t *this, void *buf, size_t len, bool block)
{
	if (this->app.cache.len)
	{
		size_t cache;

		cache = min(len, this->app.cache.len - this->app.cache_done);
		memcpy(buf, this->app.cache.ptr + this->app.cache_done, cache);

		this->app.cache_done += cache;
		if (this->app.cache_done == this->app.cache.len)
		{
			chunk_free(&this->app.cache);
			this->app.cache_done = 0;
		}
		return cache;
	}
	this->app.in.ptr = buf;
	this->app.in.len = len;
	this->app.in_done = 0;
	if (exchange(this, FALSE, block))
	{
		return this->app.in_done;
	}
	return -1;
}

METHOD(tls_socket_t, write_, ssize_t,
	private_tls_socket_t *this, void *buf, size_t len)
{
	this->app.out.ptr = buf;
	this->app.out.len = len;
	this->app.out_done = 0;
	if (exchange(this, TRUE, FALSE))
	{
		return this->app.out_done;
	}
	return -1;
}

METHOD(tls_socket_t, splice, bool,
	private_tls_socket_t *this, int rfd, int wfd)
{
	char buf[PLAIN_BUF_SIZE], *pos;
	fd_set set;
	ssize_t in, out;
	bool old, plain_eof = FALSE, crypto_eof = FALSE;

	while (!plain_eof && !crypto_eof)
	{
		FD_ZERO(&set);
		FD_SET(rfd, &set);
		FD_SET(this->fd, &set);

		old = thread_cancelability(TRUE);
		in = select(max(rfd, this->fd) + 1, &set, NULL, NULL, NULL);
		thread_cancelability(old);
		if (in == -1)
		{
			DBG1(DBG_TLS, "TLS select error: %s", strerror(errno));
			return FALSE;
		}
		while (!plain_eof && FD_ISSET(this->fd, &set))
		{
			in = read_(this, buf, sizeof(buf), FALSE);
			switch (in)
			{
				case 0:
					plain_eof = TRUE;
					break;
				case -1:
					if (errno != EWOULDBLOCK)
					{
						DBG1(DBG_TLS, "TLS read error: %s", strerror(errno));
						return FALSE;
					}
					break;
				default:
					pos = buf;
					while (in)
					{
						out = write(wfd, pos, in);
						if (out == -1)
						{
							DBG1(DBG_TLS, "TLS plain write error: %s",
								 strerror(errno));
							return FALSE;
						}
						in -= out;
						pos += out;
					}
					continue;
			}
			break;
		}
		if (!crypto_eof && FD_ISSET(rfd, &set))
		{
			in = read(rfd, buf, sizeof(buf));
			switch (in)
			{
				case 0:
					crypto_eof = TRUE;
					break;
				case -1:
					DBG1(DBG_TLS, "TLS plain read error: %s", strerror(errno));
					return FALSE;
				default:
					pos = buf;
					while (in)
					{
						out = write_(this, pos, in);
						if (out == -1)
						{
							DBG1(DBG_TLS, "TLS write error");
							return FALSE;
						}
						in -= out;
						pos += out;
					}
					break;
			}
		}
	}
	return TRUE;
}

METHOD(tls_socket_t, get_fd, int,
	private_tls_socket_t *this)
{
	return this->fd;
}

METHOD(tls_socket_t, destroy, void,
	private_tls_socket_t *this)
{
	/* send a TLS close notify if not done yet */
	this->app.close = TRUE;
	write_(this, NULL, 0);
	free(this->app.cache.ptr);
	this->tls->destroy(this->tls);
	free(this);
}

/**
 * See header
 */
tls_socket_t *tls_socket_create(bool is_server, identification_t *server,
							identification_t *peer, int fd, tls_cache_t *cache)
{
	private_tls_socket_t *this;

	INIT(this,
		.public = {
			.read = _read_,
			.write = _write_,
			.splice = _splice,
			.get_fd = _get_fd,
			.destroy = _destroy,
		},
		.app = {
			.application = {
				.build = _build,
				.process = _process,
				.destroy = (void*)nop,
			},
		},
		.fd = fd,
	);

	this->tls = tls_create(is_server, server, peer, TLS_PURPOSE_GENERIC,
						   &this->app.application, cache);
	if (!this->tls)
	{
		free(this);
		return NULL;
	}

	return &this->public;
}
