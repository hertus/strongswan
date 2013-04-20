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

#include "gspm_method.h"
#include "gspm_manager.h"

#include <plugins/gspm_pace/gspm_pace.h>

/**
 * Described in header.
 */
gspm_method_t *gspm_method_create_builder(ike_sa_t *ike_sa,
									chunk_t received_nonce, chunk_t sent_nonce,
									chunk_t received_init, chunk_t sent_init,
									char reserved[3], uint16_t method_id)
{
	switch ((uintptr_t) method_id)
	{
		case GSPM_RESERVED:
			/* reserved value */
		case GSPM_PACE:
//			return (gspm_method_t*)gspm_method_pace_create_builder(ike_sa,
//									received_nonce, sent_nonce,
//									received_init, sent_init,
//									reserved);
		case GSPM_AUGPAKE:
		case GSPM_SPSKA:
		default:
			return NULL;
	}
}

/**
 * Described in header.
 */
gspm_method_t *gspm_method_create_verifier(ike_sa_t *ike_sa,
									chunk_t received_nonce, chunk_t sent_nonce,
									chunk_t received_init, chunk_t sent_init,
									char reserved[3], uint16_t method_id)
{
	switch ((uintptr_t) method_id)
	{
		case GSPM_RESERVED:
			/* reserved value */
		case GSPM_PACE:
//			return (gspm_method_t*)gspm_method_pace_create_verifier(ike_sa,
//									received_nonce, sent_nonce,
//									received_init, sent_init,
//									reserved);
		case GSPM_AUGPAKE:
		case GSPM_SPSKA:
		default:
			return NULL;
	}
}
