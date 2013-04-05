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

#include "gspm_pace_listener.h"

#include <errno.h>

#include <daemon.h>
#include <threading/mutex.h>
#include <processing/jobs/callback_job.h>

typedef struct private_gspm_pace_listener_t private_gspm_pace_listener_t;

/**
 * Private data of an gspm_pace_listener_t object.
 */
struct private_gspm_pace_listener_t {

	/**
	 * Public gspm_pace_listener_t interface.
	 */
	gspm_pace_listener_t public;

	/**
	 * Mutex
	 */
	mutex_t *mutex;

};

METHOD(listener_t, ike_state_change, bool,
	private_gspm_pace_listener_t *this, ike_sa_t *ike_sa, ike_sa_state_t state)
{
	return TRUE;
}

METHOD(listener_t, message_hook, bool,
	private_gspm_pace_listener_t *this, ike_sa_t *ike_sa,
	message_t *message, bool incoming, bool plain)
{
	return TRUE;
}

METHOD(gspm_pace_listener_t, destroy, void,
	private_gspm_pace_listener_t *this)
{
	free(this);
}

/**
 * See header
 */
gspm_pace_listener_t *gspm_pace_listener_create()
{
	private_gspm_pace_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.ike_state_change = _ike_state_change,
				.message = _message_hook,
			},
			.destroy = _destroy,
		},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	return &this->public;
}
