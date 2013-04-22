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
 * @defgroup gspm_pace gspm_pace
 * @{ @ingroup gspm_pace
 *
 * @defgroup gspm_pace_plugin gspm_pace_plugin
 * @{ @ingroup gspm_pace
 */

#ifndef GSPM_PACE_LISTENER_H_
#define GSPM_PACE_LISTENER_H_

#include <bus/listeners/listener.h>

typedef struct gspm_pace_listener_t gspm_pace_listener_t;

/**
 * PACE GSPM Listener
 */
struct gspm_pace_listener_t {

	/**
	 * Implements listener_t interface.
	 */
	listener_t listener;

	/**
	 * Destroy a gspm_pace_listener_t.
	 */
	void (*destroy)(gspm_pace_listener_t *this);

	/**
	 * gets a dh_object which has been captured from bus
	 * @param spi	SPI from responder
	 * @return		diffie_hellman_t object
	 */
	diffie_hellman_t* (*get_dh)(gspm_pace_listener_t *this, uint64_t spi);
};

/**
 * Create a gspm_pace_listener instance.
 */
gspm_pace_listener_t *gspm_pace_listener_create();

#endif /** GSPM_PACE_LISTENER_H_ @}*/
