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
#include "gspm_pace_plugin.h"

#include <daemon.h>
#include <sa/ikev2/keymat_v2.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/gspm_payload.h>
#include <sa/ikev2/gspm/gspm_method.h>

typedef struct private_gspm_method_pace_t private_gspm_method_pace_t;

/**
 * Private data of an gspm_method_pace_t object.
 */
struct private_gspm_method_pace_t {

	/**
	 * Public gspm_method interface
	 */
	gspm_method_pace_t public;

	/**
	 * if its a verifier or not
	 */
	bool pace_verifier;

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

};

METHOD(gspm_method_t, build_initiator, status_t,
		private_gspm_method_pace_t *this, message_t *message)
{
	return NEED_MORE;
}

METHOD(gspm_method_t, process_responder, status_t,
		private_gspm_method_pace_t *this, message_t *message)
{
	return NEED_MORE;
}

METHOD(gspm_method_t, build_responder, status_t,
		private_gspm_method_pace_t *this, message_t *message)
{
	return NEED_MORE;
}

METHOD(gspm_method_t, process_initiator, status_t,
		private_gspm_method_pace_t *this, message_t *message)
{
	return NEED_MORE;
}

METHOD(gspm_method_t, destroy, void,
		private_gspm_method_pace_t *this)
{
	free(this);
}

/*
 * See header
 */
gspm_method_pace_t *gspm_method_pace_create(
		bool verifier, ike_sa_t *ike_sa,
		chunk_t received_nonce, chunk_t sent_nonce,
		chunk_t received_init, chunk_t sent_init,
		char reserved[3])
{
	private_gspm_method_pace_t *this;

	if(verifier)
	{
		INIT(this,
			.public = {
				.gspm_method = {
					.build = _build_responder,
					.process = _process_responder,
					.destroy = _destroy,
				},
			},
			.pace_verifier = verifier,
			.ike_sa = ike_sa,
			.received_nonce = received_nonce,
			.sent_nonce = sent_nonce,
			.received_init = received_init,
			.sent_init = sent_init,
		);
	}
	else
	{
		INIT(this,
			.public = {
				.gspm_method = {
					.build = _build_initiator,
					.process = _process_initiator,
					.destroy = _destroy,
				},
			},
			.pace_verifier = verifier,
			.ike_sa = ike_sa,
			.received_nonce = received_nonce,
			.sent_nonce = sent_nonce,
			.received_init = received_init,
			.sent_init = sent_init,
		);
	}
	memcpy(this->reserved, reserved, sizeof(this->reserved));

	return &this->public;
}
