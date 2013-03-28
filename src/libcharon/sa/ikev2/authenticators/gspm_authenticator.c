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
};

gspm_authenticator_t *gspm_authenticator_create_builder(ike_sa_t *ike_sa,
		chunk_t received_nonce, chunk_t sent_nonce, chunk_t received_init,
		chunk_t sent_init, char reserved[3])
{
	return &this->public;
}

gspm_authenticator_t *gspm_authenticator_create_verifier(ike_sa_t *ike_sa,
		chunk_t received_nonce, chunk_t sent_nonce, chunk_t received_init,
		chunk_t sent_init, char reserved[3])
{
	return &this->public;
}
