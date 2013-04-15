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

#include "gspm_pace_listener.h"
#include "src/libcharon/sa/ikev2/gspm/gspm_manager.h"

#include <errno.h>
#include <daemon.h>
#include <threading/mutex.h>
#include <processing/jobs/callback_job.h>
#include <collections/hashtable.h>

typedef struct private_gspm_pace_listener_t private_gspm_pace_listener_t;

/**
 * Private data of an gspm_pace_listener_t object.
 */
struct private_gspm_pace_listener_t {

	/**
	 * Public gspm_pace_listener_t interface.
	 */
	gspm_pace_listener_t public;

	ike_sa_id_t *ike_sa_id;

	/**
	 * hashtable with dh objects relevant for gspm_pace connections
	 * @key		SPI
	 * @value	dh object
	 */
	hashtable_t *dh_objects;
};

/**
 * Hashtable hash function
 */
static u_int64_t hash(uintptr_t key)
{
	return key;
}

/**
 * Hashtable equals function
 */
static bool equals(uintptr_t a, uintptr_t b)
{
	return a == b;
}

METHOD(listener_t, message, bool,
	private_gspm_pace_listener_t *this,
	ike_sa_t *ike_sa,
	message_t *message,
	bool incoming,
	bool plain)
{
	u_int16_t method;
	u_int64_t id;
	notify_payload_t *notify_payload;
	bool placeholder;

	placeholder = true;

	if (message->get_exchange_type(message) == IKE_SA_INIT)
	{
		notify_payload = message->get_notify(message, SECURE_PASSWORD_METHOD);
		if(notify_payload)
		{
			method = ntohs(*(u_int16_t*) notify_payload->get_notification_data(notify_payload).ptr);

			if((method == GSPM_PACE)
					&&
				(message->get_ike_sa_id(message)->get_responder_spi(message->get_ike_sa_id(message))))
			{
				id = message->get_ike_sa_id(message)->get_responder_spi(message->get_ike_sa_id(message));
				DBG1(DBG_IKE, "GSPM LISTENER sa_id_r is: %016llX", id);
				this->dh_objects->put(this->dh_objects,
						(void*)(uintptr_t) id,
						(void*) placeholder);
			}
		}
	}
	return TRUE;
}

METHOD(listener_t, ike_keys, bool,
	private_gspm_pace_listener_t *this,
	ike_sa_t *ike_sa,
	diffie_hellman_t *dh,
	chunk_t dh_other,
	chunk_t nonce_i,
	chunk_t nonce_r,
	ike_sa_t *rekey,
	shared_key_t *shared)
{
	uint64_t id;

	id = ike_sa->get_id(ike_sa)->get_responder_spi(ike_sa->get_id(ike_sa));
	if(this->dh_objects->get(this->dh_objects,
			(void*)(uintptr_t) id))
	{
		DBG1(DBG_IKE, "GSPM LISTENER found SPI in hashtable, put dh");
		this->dh_objects->put(this->dh_objects, (void*)(uintptr_t) id, dh);
	}
	return TRUE;
}

METHOD(gspm_pace_listener_t, get_dh, diffie_hellman_t*,
		private_gspm_pace_listener_t *this,
		uint64_t spi)
{
	diffie_hellman_t *dh;

	dh = this->dh_objects->get(this->dh_objects, (void*)(uintptr_t) spi);
	return dh;
}

METHOD(gspm_pace_listener_t, destroy, void,
	private_gspm_pace_listener_t *this)
{
	this->dh_objects->destroy(this->dh_objects);
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
				.ike_keys = _ike_keys,
				.message = _message,
			},
			.destroy = _destroy,
		},
		.dh_objects = hashtable_create((hashtable_hash_t)hash,
				   	   	   	   	   	   (hashtable_equals_t)equals, 32),
	);
	return &this->public;
}
