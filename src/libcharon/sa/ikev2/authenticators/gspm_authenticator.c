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
#include <encoding/payloads/gspm_payload.h>

typedef struct private_gspm_authenticator_t private_gspm_authenticator_t;

ENUM(gspm_member_names, GSPM_RESERVED, GSPM_SPSKA,
	"GSPM_RESERVED",
	"GSPM_PACE",
	"GSPM_AUGPAKE",
	"GSPM_SPSKA",
);

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
	 * random nonce s to include in GSPM ENONCE calculation
	 */
	chunk_t nonce;

	/**
	 * generated GSPM Payload
	 */
	gspm_payload_t *gspm_payload;

	/**
	 * KE2 ephemeral public key from DH
	 */
	ke_payload_t *ke_payload;

};

/*
 * PACE round#1 create a random nonce s, calculate ENONCE with DH Key, map it and choose keypair
 * fill GSPM chunk with IV and ENONCE
 */
METHOD(authenticator_t, build_initiator, status_t,
		private_gspm_authenticator_t *this, message_t *message)
{
	DBG1(DBG_IKE, "GSPM build_initiator");

	/**TODO needs manager -> plugin -> to reach DH Object from bus via Listener

	diffie_hellman_t dh;
	dh = lib->crypto->create_dh(lib->crypto, MODP_CUSTOM);

	*/

	return FAILED;
}

METHOD(authenticator_t, process_initiator, status_t,
		private_gspm_authenticator_t *this, message_t *message)
{
	DBG1(DBG_IKE, "GSPM process_initiator");
	return FAILED;
}

METHOD(authenticator_t, build_responder, status_t,
		private_gspm_authenticator_t *this, message_t *message)
{
	DBG1(DBG_IKE, "GSPM build_responder");
	return FAILED;
}

METHOD(authenticator_t, process_responder, status_t,
		private_gspm_authenticator_t *this, message_t *message)
{
	DBG1(DBG_IKE, "GSPM process_responder");
	return FAILED;
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
