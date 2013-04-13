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

};

METHOD(listener_t, message, bool,
	private_gspm_pace_listener_t *this,
	ike_sa_t *ike_sa,
	message_t *message,
	bool incoming,
	bool plain)
{
	//this->ike_sa_id = message->get_ike_sa_id(message);
	this->ike_sa_id = ike_sa->get_id(ike_sa);
	if (
			(message->get_exchange_type(message) == IKE_SA_INIT)
			&&
			(message->get_notify(message, SECURE_PASSWORD_METHOD))
			&&
			(this->ike_sa_id->get_initiator_spi(this->ike_sa_id))
			&&
			(this->ike_sa_id->get_responder_spi(this->ike_sa_id))
		)
	{
		DBG1(DBG_IKE, "GSPM LISTENER sa_id_i is: %016llX", this->ike_sa_id->get_initiator_spi(this->ike_sa_id));
		DBG1(DBG_IKE, "GSPM LISTENER sa_id_r is: %016llX", this->ike_sa_id->get_responder_spi(this->ike_sa_id));
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
	if(ike_sa->get_id(ike_sa) == this->ike_sa_id){
		DBG1(DBG_IKE, "GSPM LISTENER called ike_keys and same ID!");
	}
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
				.ike_keys = _ike_keys,
				.message = _message,
			},
			.destroy = _destroy,
		},
	);

	return &this->public;
}
