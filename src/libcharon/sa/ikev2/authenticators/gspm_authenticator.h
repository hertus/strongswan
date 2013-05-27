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

/**
 * @defgroup gspm_authenticator gspm_authenticator
 * @{ @ingroup authenticators_v2
 */

#ifndef GSPM_AUTHENTICATOR_H_
#define GSPM_AUTHENTICATOR_H_

typedef struct gspm_authenticator_t gspm_authenticator_t;

#include <sa/authenticator.h>

/**
 * Implementation of authenticator_t using generic secure password method
 *
Initiator                         									Responder
-----------------------------------------------------------------------------
HDR(SPIi=xxx, SPIr=yyy, IKE_AUTH,
   Flags: Initiator, Message ID=1),
   SK {IDi, [CERTREQ,] GSPM, [GSPM, ...,]
   [IDr,] SAi2, TSi, TSr}  -->
								 <--  HDR(SPIi=xxx, SPIr=yyy, IKE_AUTH, Flags:
										Response, Message ID=1),
										SK {IDr, [CERT,] GSPM, [GSPM, ...]}
HDR(SPIi=xxx, SPIr=yyy, IKE_AUTH,
   Flags: Initiator, Message ID=2),
   SK {GSPM, [GSPM, ...,]}  -->
								 <--  HDR(SPIi=xxx, SPIr=yyy, IKE_AUTH, Flags:
										Response, Message ID=2),
										SK {GSPM, [GSPM, ...]}
...
 */
struct gspm_authenticator_t
{

	/**
	 * Implementation of authenticator_t using secure passwords.
	 */
	authenticator_t authenticator;

};

/**
 * Creates an authenticator to authenticate against responder.
 *
 * @param ike_sa                        associated ike_sa
 * @param received_nonce				nonce received in IKE_SA_INIT
 * @param sent_nonce					nonce sent in IKE_SA_INIT
 * @param received_init         		received IKE_SA_INIT message data
 * @param sent_init                     sent IKE_SA_INIT message data
 * @param reserved                      reserved bytes of ID payload
 * @return                              GSPM authenticator
 */
gspm_authenticator_t *gspm_authenticator_create_builder(ike_sa_t *ike_sa,
		chunk_t received_nonce, chunk_t sent_nonce, chunk_t received_init,
		chunk_t sent_init, char reserved[3]);

/**
 * Creates an authenticator to verify secure passwords.
 *
 * @param ike_sa                        associated ike_sa
 * @param received_nonce				nonce received in IKE_SA_INIT
 * @param sent_nonce					nonce sent in IKE_SA_INIT
 * @param received_init         		received IKE_SA_INIT message data
 * @param sent_init                     sent IKE_SA_INIT message data
 * @param reserved                      reserved bytes of ID payload
 * @return                              GSPM authenticator
 */
gspm_authenticator_t *gspm_authenticator_create_verifier(ike_sa_t *ike_sa,
		chunk_t received_nonce, chunk_t sent_nonce, chunk_t received_init,
		chunk_t sent_init, char reserved[3]);

#endif /* GSPM_AUTHENTICATOR_H_ */
