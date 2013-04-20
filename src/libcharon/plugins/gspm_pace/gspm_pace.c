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

#include "gspm_pace.h"

#include <daemon.h>
#include <sa/ikev2/keymat_v2.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/gspm_payload.h>
#include <sa/ikev2/gspm/gspm_manager.h>
#include <sa/ikev2/gspm/gspm_method.h>

typedef struct private_gspm_method_pace_t private_gspm_method_pace_t;

struct private_gspm_method_pace_t {

	/**
	 * implements gspm_method interface
	 */
	gspm_method_pace_t public;

	/**
	 * Assigned IKE_SA
	 */
	ike_sa_t *ike_sa;

	/**
	 * others nonce to include in AUTH calculation
	 */
	chunk_t received_nonce;

	/**
	 * our nonce to include in AUTH calculation
	 */
	chunk_t sent_nonce;

	/**
	 * others IKE_SA_INIT message data to include in AUTH calculation
	 */
	chunk_t received_init;

	/**
	 * our IKE_SA_INIT message data to include in AUTH calculation
	 */
	chunk_t sent_init;

	/**
	 * Reserved bytes of ID payload
	 */
	char reserved[3];


	/**
	 * random nonce s to include in GSPM ENONCE calculation
	 */
	chunk_t nonce;

	/**
	 * KE2 ephemeral public key from DH
	 */
	ke_payload_t *ke_payload;

	/**
	 * round#2 of method_pace
	 */
	bool round2;
};

/*
 * gspm_method implementation
 */

METHOD(gspm_method_t, build_initiator, status_t,
		private_gspm_method_pace_t *this, message_t *message)
{
	auth_payload_t *auth_payload;
	gspm_payload_t *gspm_payload;
	chunk_t auth_data;
	chunk_t gspm_data;

	/**TODO needs manager -> plugin -> to reach DH Object from bus via Listener

	diffie_hellman_t dh;
	dh = lib->crypto->create_dh(lib->crypto, MODP_CUSTOM);

	*/
	if(this->round2)
	{
		auth_payload = auth_payload_create();
		auth_payload->set_auth_method(auth_payload, AUTH_GSPM);
		auth_payload->set_data(auth_payload, auth_data);
		chunk_free(&auth_data);
		message->add_payload(message, (payload_t*)auth_payload);

		return SUCCESS;
	}

	gspm_data = chunk_empty;
	gspm_payload = gspm_payload_create();
	gspm_payload->set_data(gspm_payload, gspm_data);
	chunk_free(&gspm_data);
	message->add_payload(message, (payload_t*)gspm_payload);

	return SUCCESS;
}
METHOD(gspm_method_t, process_responder, status_t,
		private_gspm_method_pace_t *this, message_t *message)
{
	return SUCCESS;
}
METHOD(gspm_method_t, build_responder, status_t,
		private_gspm_method_pace_t *this, message_t *message)
{
	auth_payload_t *auth_payload;
	gspm_payload_t *gspm_payload;
	chunk_t auth_data;
	chunk_t gspm_data;

	if(this->round2)
	{
		auth_payload = auth_payload_create();
		auth_payload->set_auth_method(auth_payload, AUTH_GSPM);
		auth_payload->set_data(auth_payload, auth_data);
		chunk_free(&auth_data);
		message->add_payload(message, (payload_t*)auth_payload);
		return SUCCESS;
	}

	gspm_payload = gspm_payload_create();
	gspm_payload->set_data(gspm_payload, gspm_data);
	chunk_free(&gspm_data);
	message->add_payload(message, (payload_t*)gspm_payload);

	return SUCCESS;
}
METHOD(gspm_method_t, process_initiator, status_t,
		private_gspm_method_pace_t *this, message_t *message)
{
	return SUCCESS;
}

METHOD(gspm_method_t, destroy, void,
		private_gspm_method_pace_t *this)
{
	free(this);
}

/*
 * gspm_method implementation
 * see header file
 */
gspm_method_t *gspm_method_pace_create_builder(ike_sa_t *ike_sa,
		chunk_t received_nonce, chunk_t sent_nonce, chunk_t received_init,
		chunk_t sent_init, char reserved[3])
{
	private_gspm_method_pace_t *this;

	INIT(this,
		.public = {
			.gspm_method = {
				.build = _build_initiator,
				.process = _process_initiator,
				.destroy = _destroy,
			},
		},
		.ike_sa = ike_sa,
		.received_init = received_init,
		.sent_init = sent_init,
		.received_nonce = received_nonce,
		.sent_nonce = sent_nonce,
	);
	memcpy(this->reserved, reserved, sizeof(this->reserved));

	return &this->public.gspm_method;
}

gspm_method_t *gspm_method_pace_create_verifier(ike_sa_t *ike_sa,
		chunk_t received_nonce, chunk_t sent_nonce, chunk_t received_init,
		chunk_t sent_init, char reserved[3])
{
	private_gspm_method_pace_t *this;

	INIT(this,
		.public = {
			.gspm_method = {
				.build = _build_responder,
				.process = _process_responder,
				.destroy = _destroy,
			},
		},
		.ike_sa = ike_sa,
		.received_init = received_init,
		.sent_init = sent_init,
		.received_nonce = received_nonce,
		.sent_nonce = sent_nonce,
	);
	memcpy(this->reserved, reserved, sizeof(this->reserved));

	return &this->public.gspm_method;
}
