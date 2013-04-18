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
 * @defgroup gspm gspm
 * @{ @ingroup sa
 */

#ifndef GSPM_MEMBER_H_
#define GSPM_MEMBER_H_

typedef struct gspm_member_t gspm_member_t;

#include <library.h>
#include <sa/ike_sa.h>
#include <credentials/auth_cfg.h>

#include "gspm_manager.h"

/**
 * GSPM Member interface implemented by the various authenticators.
 *
 * An member implementation handles AUTH and GSPM payloads,
 * depends on the gener secure password method. Received
 * messages from the authenticator are passed to the process() method,
 * to send authentication data back, the message  is passed to the build() method.
 */
struct gspm_member_t {

	/**
	 * Process an incoming message using the member method.
	 *
	 * @param message		message containing authentication payloads
	 * @return
	 *						- SUCCESS if authentication successful
	 *						- FAILED if authentication failed
	 *						- NEED_MORE if another exchange required
	 */
	status_t (*process)(gspm_member_t *this, message_t *message);

	/**
	 * Attach authentication data to an outgoing message.
	 *
	 * @param message		message to add authentication data to
	 * @return
	 *						- SUCCESS if authentication successful
	 *						- FAILED if authentication failed
	 *						- NEED_MORE if another exchange required
	 */
	status_t (*build)(gspm_member_t *this, message_t *message);

	/**
	 * Destroy authenticator instance.
	 */
	void (*destroy) (gspm_member_t *this);
};

/**
 * Create an GSPM member to build signatures.
 *
 * @param ike_sa			associated ike_sa
 * @param cfg				authentication configuration
 * @param received_nonce	nonce received in IKE_SA_INIT
 * @param sent_nonce		nonce sent in IKE_SA_INIT
 * @param received_init		received IKE_SA_INIT message data
 * @param sent_init			sent IKE_SA_INIT message data
 * @param reserved			reserved bytes of the ID payload
 * @param member_id			ID of the selected GSPM member
 * @return					authenticator, NULL if not supported
 */
gspm_member_t *gspm_member_create_builder(ike_sa_t *ike_sa,
									chunk_t received_nonce, chunk_t sent_nonce,
									chunk_t received_init, chunk_t sent_init,
									char reserved[3], uint16_t member_id);

/**
 * Create an GSPM member to verify signatures.
 *
 * @param ike_sa			associated ike_sa
 * @param message			message containing authentication data
 * @param received_nonce	nonce received in IKE_SA_INIT
 * @param sent_nonce		nonce sent in IKE_SA_INIT
 * @param received_init		received IKE_SA_INIT message data
 * @param sent_init			sent IKE_SA_INIT message data
 * @param reserved			reserved bytes of the ID payload
 * @param member_id			ID of the selected GSPM member
 * @return					authenticator, NULL if not supported
 */
gspm_member_t *gspm_member_create_verifier(ike_sa_t *ike_sa,
									chunk_t received_nonce, chunk_t sent_nonce,
									chunk_t received_init, chunk_t sent_init,
									char reserved[3], uint16_t member_id);

#endif /** GSPM_MEMBER_H_ @}*/
