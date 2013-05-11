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

#include <errno.h>
#include <daemon.h>
#include <threading/mutex.h>
#include <processing/jobs/callback_job.h>
#include <collections/hashtable.h>

typedef struct private_gspm_pace_listener_t private_gspm_pace_listener_t;
typedef struct dh_entry_t dh_entry_t;

/**
 * dh object entry
 */
struct dh_entry_t {

	/**
	 * ike_sa_id
	 */
	ike_sa_id_t *ike_sa_id;

	/**
	 * shared secret from DH round
	 */
	chunk_t shared_secret;
};

/**
 * Private data of an gspm_pace_listener_t object.
 */
struct private_gspm_pace_listener_t {

	/**
	 * Public gspm_pace_listener_t interface.
	 */
	gspm_pace_listener_t public;

	/**
	 * ID of assigned IKE_SA.
	 */
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
static u_int32_t hash(u_int32_t key)
{
	return key;
}

/**
 * Hashtable equals function
 */
static bool equals(u_int32_t a, u_int32_t b)
{
	return a == b;
}


/**
 * creates a hash value from 2 SPI's for uniqueness
 */
static u_int32_t create_spi_hash(ike_sa_id_t *id)
{
	u_int64_t idi, idr;
	chunk_t chunk_spi, chunk_spr;

	idi = id->get_initiator_spi(id);
	idr = id->get_responder_spi(id);
	chunk_spi = chunk_from_thing(idi);
	chunk_spr = chunk_from_thing(idr);

	return chunk_hash_inc(chunk_spi, chunk_hash(chunk_spr));
}

METHOD(listener_t, message, bool, private_gspm_pace_listener_t *this,
	ike_sa_t *ike_sa, message_t *message, bool incoming, bool plain)
{
	ike_sa_id_t *id;
	u_int16_t method;
	uintptr_t hash;
	dh_entry_t *dh_entry;
	notify_payload_t *notify_payload;

	id = ike_sa->get_id(ike_sa);

	if(id->is_initiator(id))
	{
		/** Initiator gets selected method from responders notify */
		if (incoming && message->get_exchange_type(message) == IKE_SA_INIT)
		{
			notify_payload = message->get_notify(message,
				SECURE_PASSWORD_METHOD);
			if(notify_payload)
			{
				method = ntohs(*(u_int16_t*) notify_payload->
						get_notification_data(notify_payload).ptr);
				if(method == GSPM_PACE)
				{
					hash = create_spi_hash(id);
					dh_entry = malloc_thing(dh_entry_t);
					dh_entry->ike_sa_id = id->clone(id);
					this->dh_objects->put(this->dh_objects, (void*)hash,
						dh_entry);
				}
			}
		}
	}
	else
	{	/** Reponder has selected method and send his notify */
		if (incoming && message->get_exchange_type(message) == IKE_SA_INIT)
		{
			notify_payload = message->get_notify(message,
				SECURE_PASSWORD_METHOD);
			if(notify_payload)
			{
				hash = create_spi_hash(id);
				dh_entry = malloc_thing(dh_entry_t);
				dh_entry->ike_sa_id = id->clone(id);
				this->dh_objects->put(this->dh_objects, (void*)hash,
					dh_entry);
			}
		}
		if (!incoming && message->get_exchange_type(message) == IKE_SA_INIT)
		{
			notify_payload = message->get_notify(message,
				SECURE_PASSWORD_METHOD);
			if(notify_payload)
			{
				method = ntohs(*(u_int16_t*) notify_payload->
						get_notification_data(notify_payload).ptr);
				if(method != GSPM_PACE)
				{
					hash = create_spi_hash(id);
					DBG1(DBG_IKE, "GSPM Listener was not GSPM PACE with hash: %d", hash);
					this->dh_objects->remove(this->dh_objects, (void*)hash);
				}
			}
		}
	}

	return TRUE;
}

METHOD(listener_t, ike_keys, bool,	private_gspm_pace_listener_t *this,
	ike_sa_t *ike_sa, diffie_hellman_t *dh,	chunk_t dh_other, chunk_t nonce_i,
	chunk_t nonce_r, ike_sa_t *rekey, shared_key_t *shared)
{
	uintptr_t hash;
	dh_entry_t *dh_entry;
	ike_sa_id_t *id;

	id = ike_sa->get_id(ike_sa);
	hash = create_spi_hash(id);

	if(this->dh_objects->get(this->dh_objects, (void*)hash))
	{
		dh_entry = this->dh_objects->get(this->dh_objects, (void*)hash);
		if(dh_entry)
		{
			if(dh_entry->ike_sa_id->equals(dh_entry->ike_sa_id,
				ike_sa->get_id(ike_sa)))
			{
				if(dh->get_shared_secret(dh, &dh_entry->shared_secret) == SUCCESS)
				{
					DBG1(DBG_IKE, "GSPM Listener copied shared secret");
					this->dh_objects->put(this->dh_objects, (void*)hash,
						dh_entry);
				}
			}
		}
	}
	return TRUE;
}

METHOD(listener_t, ike_updown, bool, private_gspm_pace_listener_t *this,
	ike_sa_t *ike_sa, bool up)
{
	uintptr_t hash;
	ike_sa_id_t *id;
	dh_entry_t *dh_entry;

	id = ike_sa->get_id(ike_sa);
	hash = create_spi_hash(id);

	if(!up)
	{
		dh_entry = this->dh_objects->get(this->dh_objects, (void*)hash);
		if(dh_entry)
		{
			dh_entry->ike_sa_id->destroy(dh_entry->ike_sa_id);
			free(dh_entry);
			this->dh_objects->remove(this->dh_objects, (void*)hash);
		}
	}
	return TRUE;
}

METHOD(gspm_pace_listener_t, get_shared_secret, chunk_t,
	private_gspm_pace_listener_t *this, ike_sa_t *ike_sa)
{
	dh_entry_t *dh_entry;
	uintptr_t hash;
	ike_sa_id_t *id;

	id = ike_sa->get_id(ike_sa);
	hash = create_spi_hash(id);
	dh_entry = this->dh_objects->get(this->dh_objects, (void*)hash);
	if(dh_entry)
	{
		if(dh_entry->ike_sa_id->equals(dh_entry->ike_sa_id, ike_sa->get_id(ike_sa)))
		{
			return dh_entry->shared_secret;
		}
	}
	return chunk_empty;
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
				.message = _message,
				.ike_keys = _ike_keys,
				.ike_updown = _ike_updown,
			},
			.get_shared_secret = _get_shared_secret,
			.destroy = _destroy,
		},
		.dh_objects = hashtable_create((hashtable_hash_t)hash,
				   	   	   	   	   	   (hashtable_equals_t)equals, 32),
	);
	return &this->public;
}
