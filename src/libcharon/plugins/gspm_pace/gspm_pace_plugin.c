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
#include "gspm_pace.h"

#include <daemon.h>
#include <sa/ikev2/gspm/gspm_manager.h>

typedef struct private_gspm_pace_plugin_t private_gspm_pace_plugin_t;

/**
 * private data of gspm_pace plugin
 */
struct private_gspm_pace_plugin_t {

	/**
	 * implements plugin interface
	 */
	gspm_pace_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
		private_gspm_pace_plugin_t *this)
{
	return "gspm-pace";
}

METHOD(plugin_t, destroy, void,
		private_gspm_pace_plugin_t *this)
{
	charon->bus->remove_listener(charon->bus, &gspm_pace_listener->listener);
	charon->gspm->remove_method(charon->gspm, (gspm_method_constructor_t) gspm_method_pace_create);
	gspm_pace_listener->destroy(gspm_pace_listener);
	free(this);
}

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
	);

	gspm_pace_listener = gspm_pace_listener_create(),
	charon->bus->add_listener(charon->bus, &gspm_pace_listener->listener);
	charon->gspm->add_method(charon->gspm, GSPM_PACE, FALSE,
			(gspm_method_constructor_t) gspm_method_pace_create);
	charon->gspm->add_method(charon->gspm, GSPM_PACE, TRUE,
			(gspm_method_constructor_t) gspm_method_pace_create);

	return &this->public.plugin;
}
