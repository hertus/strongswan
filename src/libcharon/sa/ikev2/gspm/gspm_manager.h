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
 * @defgroup gspm_manager gspm_manager
 * @{ @ingroup gspm
 */

/**PACE gspm manager for registered gspm_method constructors from plugins */

#ifndef GSPM_MANAGER_H_
#define GSPM_MANAGER_H_

#include <utils/chunk.h>
#include <src/libcharon/encoding/message.h>
#include <sa/ikev2/gspm/gspm_method.h>

typedef enum  gspm_methodlist_t gspm_methodlist_t;
typedef struct gspm_manager_t gspm_manager_t;

/** IANA secure password methods
 *
 * 1	P A C E
 * 2	AugPAKE
 * 3	Secure PSK Authentication
 * ...
 */
enum gspm_methodlist_t {
	GSPM_PACE = 1,
	GSPM_AUGPAKE = 2,
	GSPM_SPSKA = 3,
};

/**
 * enum names for gspm_methodlist_names.
 */
extern enum_name_t *gspm_methodlist_names;

struct gspm_manager_t {
	/**
	 * Register a GSPM method implementation.
	 *
	 * @param method_id		IANA number of the GSPM method
	 * @param constructor	constructor function, returns an gspm_method_t
	 */
	void (*add_method)(gspm_manager_t *this, u_int16_t method_id,
			bool verifier, gspm_method_constructor_t constructor);

	/**
	 * Unregister a GSPM method implementation using it's constructor.
	 *
	 * @param constructor	constructor function to remove
	 */
	void (*remove_method)(gspm_manager_t *this,
			gspm_method_constructor_t constructor);

	/**
	 * Create a new GSPM method instance.
	 *
	 * @param method_id		type of the GSPM method, IANA number of the method
	 * @return				GSPM method instance, NULL if no constructor found
	 */
	gspm_method_t* (*create_instance)(gspm_manager_t *this, u_int16_t method_id,
			bool verifier, ike_sa_t *ike_sa, chunk_t received_nonce,
			chunk_t sent_nonce, chunk_t received_init, chunk_t sent_init,
			char reserved[3]);
	/**
	 * Gets notify chunk with GSPM methods.
	 *
	 * @return				chunk_t with all methods as u_int16_t
	 */
	chunk_t (*get_notify_chunk)(gspm_manager_t *this);

	/**
	 * Gets notify chunk with GSPM methods.
	 *
	 * @param				method id as u_int16_t
	 * @return				chunk_t with all methods as u_int16_t
	 */
	chunk_t (*get_notify_chunk_from_method)(gspm_manager_t *this,
		u_int16_t method_id);

	/**
	 * Gets the selected GSPM method from a list of methods in a message with
	 * GSPM notify data
	 *
	 * @param message		the received message with GSPM notify data
	 * @param initiator		if it's the initiator or responder
	 * @return				the selected method as u_int16_t
	 *
	 */
	u_int16_t (*get_selected_method)(gspm_manager_t *this,
		message_t *message, bool initiator);

	/**
	 * Destroys a gspm_manager_t object.
	 */
	void (*destroy)(gspm_manager_t *this);
};

/**
 * Create a new notify chunk for all supported GSPM method.
 *
 * @return				chunk_t with all supported GSPM methods
 */
chunk_t gspm_generate_chunk();

/**
 * Create a new notify chunk with given method number.
 *
 * @param method_id		IANA number of the GSPM method
 * @return				chunk_t with selected GSPM method
 */
chunk_t gspm_generate_chunk_from_method(u_int16_t method_id);

/**
 * Selects a method from given message chunk in notify,
 * returns the selected method number
 *
 * @param message		message_t from a received message with notify GSPM
 * @param initiator		if called from a initiator = true or a responder = false
 * @return				u_int16_t from selected GSPM method number
 */
u_int16_t gspm_select_method(message_t *message, bool initiator);

/**
 * Create a gspm_manager instance.
 */
gspm_manager_t *gspm_manager_create();

#endif /** GSPM_MANAGER_H_ @}*/
