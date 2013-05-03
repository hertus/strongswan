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
 * @defgroup gspm_payload gspm_payload
 * @{ @ingroup payloads
 */

/** PACE authenticator implementation header */

#ifndef GSPM_PAYLOAD_H_
#define GSPM_PAYLOAD_H_

typedef struct gspm_payload_t gspm_payload_t;

#include <library.h>
#include <encoding/payloads/payload.h>
#include <sa/authenticator.h>

/**
 * Class representing an IKEv2 GSPM payload
 * The GSPM payload is described in RFC 6467 Section 3
 *
 */
struct gspm_payload_t {

	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * set the contained GSPM data (Data specific to GSPM Method)
	 *
	 * @param message	GSPM data
	 */
	void (*set_data) (gspm_payload_t *this, chunk_t data);

	/**
	 * get the contained GSPM data
	 *
	 */
	chunk_t (*get_data) (gspm_payload_t *this);

	/**
	 * destroys a GSPM payload object
	 *
	 */
	void (*destroy) (gspm_payload_t *this);
};

/**
 * Creates an empty gspm_payload_t object.
 *
 * @return gspm_payload_t object
 */
gspm_payload_t *gspm_payload_create(void);

#endif /* GSPM_PAYLOAD_H_ */
