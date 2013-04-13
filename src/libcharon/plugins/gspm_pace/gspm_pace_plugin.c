/*
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

#include "gspm_pace_plugin.h"
#include "gspm_pace_listener.h"

#include <daemon.h>

typedef struct private_gspm_pace_plugin_t private_gspm_pace_plugin_t;

/**
 * private data of gspm_pace plugin
 */
struct private_gspm_pace_plugin_t {

	/**
	 * implements plugin interface
	 */
	gspm_pace_plugin_t public;

	/**
	 * Listener getting DH object
	 */
	gspm_pace_listener_t *listener;
};

METHOD(plugin_t, get_name, char*,
		private_gspm_pace_plugin_t *this)
{
	return "gspm-pace";
}

METHOD(plugin_t, destroy, void,
		private_gspm_pace_plugin_t *this)
{
	charon->bus->remove_listener(charon->bus, &this->listener->listener);
	this->listener->destroy(this->listener);
	free(this);
}

/*
 * see header file
 */
plugin_t *gspm_pace_plugin_create()
{
	private_gspm_pace_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
		.listener = gspm_pace_listener_create(),
	);


	charon->bus->add_listener(charon->bus, &this->listener->listener);

	return &this->public.plugin;
}

