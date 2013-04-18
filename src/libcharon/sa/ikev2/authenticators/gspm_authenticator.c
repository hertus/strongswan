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

#include "gspm_authenticator.h"

#include <daemon.h>
#include <sa/ikev2/keymat_v2.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <sa/ikev2/gspm/gspm_manager.h>
#include <sa/ikev2/gspm/gspm_member.h>

typedef struct private_gspm_authenticator_t private_gspm_authenticator_t;

/**
 * Private data of an gspm_authenticator_t object.
 */
struct private_gspm_authenticator_t
{
	/**
	 * Public authenticator_t interface.
	 */
	gspm_authenticator_t public;

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
	 * selected GSPM method from IKE_SA_INIT via auth_cfg
	 */
	u_int16_t member_id;
};

METHOD(authenticator_t, build_initiator, status_t,
		private_gspm_authenticator_t *this, message_t *message)
{
	DBG1(DBG_IKE, "GSPM authenticator build_initiator");
	auth_cfg_t *auth;

	auth = this->ike_sa->get_auth_cfg(this->ike_sa, TRUE);
	this->member_id = (u_int16_t)(intptr_t) auth->get(auth, AUTH_RULE_GSPM_MEMBER);

	gspm_member_t *member_authenticator;

	member_authenticator = gspm_member_create_builder(this->ike_sa, this->received_nonce,
			this->sent_nonce, this->received_init, this->sent_init,
			this->reserved, this->member_id);

	if (this->member_id == GSPM_PACE)
	{
		DBG1(DBG_IKE, "GSPM authenticator FOUND PACE IN AUTH_RULE");
	}
	return SUCCESS;
}

METHOD(authenticator_t, process_responder, status_t,
		private_gspm_authenticator_t *this, message_t *message)
{
	DBG1(DBG_IKE, "GSPM authenticator process_responder");
	auth_cfg_t *auth;

	auth = this->ike_sa->get_auth_cfg(this->ike_sa, TRUE);
	this->member_id = (u_int16_t)(intptr_t) auth->get(auth, AUTH_RULE_GSPM_MEMBER);
	if (this->member_id == GSPM_PACE)
	{
		DBG1(DBG_IKE, "GSPM authenticator FOUND PACE IN AUTH_RULE");
	}
	return SUCCESS;
}

METHOD(authenticator_t, build_responder, status_t,
		private_gspm_authenticator_t *this, message_t *message)
{
	DBG1(DBG_IKE, "GSPM authenticator build_responder");

	return SUCCESS;
}

METHOD(authenticator_t, process_initiator, status_t,
		private_gspm_authenticator_t *this, message_t *message)
{
	DBG1(DBG_IKE, "GSPM authenticator process_initiator");
	return SUCCESS;
}

METHOD(authenticator_t, destroy, void,
		private_gspm_authenticator_t *this)
{
	free(this);
}

gspm_authenticator_t *gspm_authenticator_create_builder(ike_sa_t *ike_sa,
		chunk_t received_nonce, chunk_t sent_nonce, chunk_t received_init,
		chunk_t sent_init, char reserved[3])
{
	private_gspm_authenticator_t *this;

	INIT(this,
		.public = {
			.authenticator = {
				.build = _build_initiator,
				.process = _process_initiator,
				.is_mutual = (void*)return_true,
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

	return &this->public;
}

gspm_authenticator_t *gspm_authenticator_create_verifier(ike_sa_t *ike_sa,
		chunk_t received_nonce, chunk_t sent_nonce, chunk_t received_init,
		chunk_t sent_init, char reserved[3])
{
	private_gspm_authenticator_t *this;

	INIT(this,
		.public = {
			.authenticator = {
				.build = _build_responder,
				.process = _process_responder,
				.is_mutual = (void*)return_true,
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

	return &this->public;
}
