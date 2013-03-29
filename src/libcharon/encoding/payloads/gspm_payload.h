/*
 * gspm_payload.h
 *
 *  Created on: Mar 29, 2013
 *      Author: hert
 */

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
	 * checks if payload contains subtype
	 */
	bool (*has_subtype) (gspm_payload_t *this);

	/**
	 * set the method-specific subtype (if required by GSPM method)
	 *
	 * @param message	subtype specific to GSPM method
	 */
	void (*set_subtype) (gspm_payload_t *this, chunk_t data);

	/**
	 * get the method-specific subtype
	 */
	chunk_t (*get_subtype) (gspm_payload_t *this);

	/**
	 * destroys a GSPM payload object
	 *
	 */
	void (*destroy) (gspm_payload_t *this)
};

#endif /* GSPM_PAYLOAD_H_ */
