/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2009 Martin Willi
 * Hochschule fuer Technik Rapperswil
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

#include "resolve_handler.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <hydra.h>
#include <debug.h>
#include <threading/mutex.h>

/* path to resolvconf executable */
#define RESOLVCONF_EXEC "/sbin/resolvconf"

/* prefix used for resolvconf interfaces */
#define RESOLVCONF_PREFIX "lo.inet.ipsec."

typedef struct private_resolve_handler_t private_resolve_handler_t;

/**
 * Private data of an resolve_handler_t object.
 */
struct private_resolve_handler_t {

	/**
	 * Public resolve_handler_t interface.
	 */
	resolve_handler_t public;

	/**
	 * resolv.conf file to use
	 */
	char *file;

	/**
	 * use resolvconf instead of writing directly to resolv.conf
	 */
	bool use_resolvconf;

	/**
	 * Mutex to access file exclusively
	 */
	mutex_t *mutex;
};

/**
 * Writes the given nameserver to resolv.conf
 */
static bool write_nameserver(private_resolve_handler_t *this,
							 identification_t *server, host_t *addr)
{
	FILE *in, *out;
	char buf[1024];
	size_t len;
	bool handled = FALSE;

	in = fopen(this->file, "r");
	/* allows us to stream from in to out */
	unlink(this->file);
	out = fopen(this->file, "w");
	if (out)
	{
		fprintf(out, "nameserver %H   # by strongSwan, from %Y\n", addr,
				server);
		DBG1(DBG_IKE, "installing DNS server %H to %s", addr, this->file);
		handled = TRUE;

		/* copy rest of the file */
		if (in)
		{
			while ((len = fread(buf, 1, sizeof(buf), in)))
			{
				ignore_result(fwrite(buf, 1, len, out));
			}
		}
		fclose(out);
	}
	if (in)
	{
		fclose(in);
	}
	return handled;
}

/**
 * Removes the given nameserver from resolv.conf
 */
static void remove_nameserver(private_resolve_handler_t *this,
							  identification_t *server, host_t *addr)
{
	FILE *in, *out;
	char line[1024], matcher[512];

	in = fopen(this->file, "r");
	if (in)
	{
		/* allows us to stream from in to out */
		unlink(this->file);
		out = fopen(this->file, "w");
		if (out)
		{
			snprintf(matcher, sizeof(matcher),
					 "nameserver %H   # by strongSwan, from %Y\n",
					 addr, server);

			/* copy all, but matching line */
			while (fgets(line, sizeof(line), in))
			{
				if (strneq(line, matcher, strlen(matcher)))
				{
					DBG1(DBG_IKE, "removing DNS server %H from %s",
						 addr, this->file);
				}
				else
				{
					fputs(line, out);
				}
			}
			fclose(out);
		}
		fclose(in);
	}
}

/**
 * Add or remove the given nameserver by invoking resolvconf.
 */
static bool invoke_resolvconf(private_resolve_handler_t *this,
							  identification_t *server, host_t *addr,
							  bool install)
{
	char cmd[128];

	/* we use the nameserver's IP address as part of the interface name to
	 * make them unique */
	if (snprintf(cmd, sizeof(cmd), "%s %s %s%H", RESOLVCONF_EXEC,
				 install ? "-a" : "-d", RESOLVCONF_PREFIX, addr) >= sizeof(cmd))
	{
		return FALSE;
	}

	if (install)
	{
		FILE *out;

		out = popen(cmd, "w");
		if (!out)
		{
			return FALSE;
		}
		DBG1(DBG_IKE, "installing DNS server %H via resolvconf", addr);
		fprintf(out, "nameserver %H   # by strongSwan, from %Y\n", addr,
				server);
		if (ferror(out) || pclose(out))
		{
			return FALSE;
		}
	}
	else
	{
		ignore_result(system(cmd));
	}
	return TRUE;
}

METHOD(attribute_handler_t, handle, bool,
	private_resolve_handler_t *this, identification_t *server,
	configuration_attribute_type_t type, chunk_t data)
{
	host_t *addr;
	bool handled;

	switch (type)
	{
		case INTERNAL_IP4_DNS:
			addr = host_create_from_chunk(AF_INET, data, 0);
			break;
		case INTERNAL_IP6_DNS:
			addr = host_create_from_chunk(AF_INET6, data, 0);
			break;
		default:
			return FALSE;
	}

	if (!addr || addr->is_anyaddr(addr))
	{
		DESTROY_IF(addr);
		return FALSE;
	}

	this->mutex->lock(this->mutex);
	if (this->use_resolvconf)
	{
		handled = invoke_resolvconf(this, server, addr, TRUE);
	}
	else
	{
		handled = write_nameserver(this, server, addr);
	}
	this->mutex->unlock(this->mutex);
	addr->destroy(addr);

	if (!handled)
	{
		DBG1(DBG_IKE, "adding DNS server failed");
	}
	return handled;
}

METHOD(attribute_handler_t, release, void,
	private_resolve_handler_t *this, identification_t *server,
	configuration_attribute_type_t type, chunk_t data)
{
	host_t *addr;
	int family;

	switch (type)
	{
		case INTERNAL_IP4_DNS:
			family = AF_INET;
			break;
		case INTERNAL_IP6_DNS:
			family = AF_INET6;
			break;
		default:
			return;
	}
	addr = host_create_from_chunk(family, data, 0);

	this->mutex->lock(this->mutex);
	if (this->use_resolvconf)
	{
		invoke_resolvconf(this, server, addr, FALSE);
	}
	else
	{
		remove_nameserver(this, server, addr);
	}
	this->mutex->unlock(this->mutex);

	addr->destroy(addr);
}

/**
 * Attribute enumerator implementation
 */
typedef struct {
	/** implements enumerator_t interface */
	enumerator_t public;
	/** virtual IP we are requesting */
	host_t *vip;
} attribute_enumerator_t;

static bool attribute_enumerate(attribute_enumerator_t *this,
								configuration_attribute_type_t *type,
								chunk_t *data)
{
	switch (this->vip->get_family(this->vip))
	{
		case AF_INET:
			*type = INTERNAL_IP4_DNS;
			break;
		case AF_INET6:
			*type = INTERNAL_IP6_DNS;
			break;
		default:
			return FALSE;
	}
	*data = chunk_empty;
	/* enumerate only once */
	this->public.enumerate = (void*)return_false;
	return TRUE;
}

METHOD(attribute_handler_t, create_attribute_enumerator, enumerator_t*,
	private_resolve_handler_t *this, identification_t *server, host_t *vip)
{
	if (vip)
	{
		attribute_enumerator_t *enumerator;

		enumerator = malloc_thing(attribute_enumerator_t);
		enumerator->public.enumerate = (void*)attribute_enumerate;
		enumerator->public.destroy = (void*)free;
		enumerator->vip = vip;

		return &enumerator->public;
	}
	return enumerator_create_empty();
}

METHOD(resolve_handler_t, destroy, void,
	private_resolve_handler_t *this)
{
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * See header
 */
resolve_handler_t *resolve_handler_create()
{
	private_resolve_handler_t *this;
	struct stat st;

	INIT(this,
		.public = {
			.handler = {
				.handle = _handle,
				.release = _release,
				.create_attribute_enumerator = _create_attribute_enumerator,
			},
			.destroy = _destroy,
		},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.file = lib->settings->get_str(lib->settings, "%s.plugins.resolve.file",
									   RESOLV_CONF, hydra->daemon),
	);

	if (stat(RESOLVCONF_EXEC, &st) == 0)
	{
		this->use_resolvconf = TRUE;
	}

	return &this->public;
}

