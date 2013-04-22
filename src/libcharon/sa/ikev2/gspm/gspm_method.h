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

#ifndef GSPM_METHOD_H_
#define GSPM_METHOD_H_

typedef struct gspm_method_t gspm_method_t;

#include <sa/ike_sa.h>


/**
 * PACE GSPM method interface implemented by the various authenticators.
 *
 * An method implementation handles AUTH and GSPM payloads,
 * depends on the generic secure password method. Received
 * messages from the authenticator are passed to the process() method,
 * to send authentication data back, the message  is passed to the build() method.
 */
struct gspm_method_t {

	/**
	 * Process an incoming message using the GSPM method.
	 *
	 * @param message		message containing authentication payloads
	 * @return				status_t
	 *						- SUCCESS if authentication method successful
	 *						- FAILED if authentication method failed
	 *						- NEED_MORE if another exchange required
	 */
	status_t (*process)(gspm_method_t *this, message_t *message);

	/**
	 * Attach authentication data to an outgoing message.
	 *
	 * @param message		message to add authentication data to
	 * @return				status_t
	 *						- SUCCESS if authentication method successful
	 *						- FAILED if authentication method failed
	 *						- NEED_MORE if another exchange required
	 */
	status_t (*build)(gspm_method_t *this, message_t *message);

	/**
	 * Destroy gspm_method instance.
	 */
	void (*destroy) (gspm_method_t *this);
};

/**
 * Constructor definition for a pluggable GSPM method.
 *
 * Each GSPM method must define a constructor function which will return
 * an initialized object with the methods defined in gspm_method_t.
 * Builder and verifier are separated later in gspm_manager by a boolean.
 *
 * @param verifier			authenticator is a verifier = true or a builder = false
 * @param ike_sa            associated ike_sa
 * @param received_nonce	nonce received in IKE_SA_INIT
 * @param sent_nonce		nonce sent in IKE_SA_INIT
 * @param received_init     received IKE_SA_INIT message data
 * @param sent_init         sent IKE_SA_INIT message data
 * @param reserved          reserved bytes of ID payload
 * @return					implementation of gspm_method_t interface
 */
typedef gspm_method_t *(*gspm_method_constructor_t)(
		bool verifier, ike_sa_t *ike_sa,
		chunk_t received_nonce, chunk_t sent_nonce,
		chunk_t received_init, chunk_t sent_init,
		char reserved[3]);

#endif /** GSPM_METHOD_H_ @}*/
