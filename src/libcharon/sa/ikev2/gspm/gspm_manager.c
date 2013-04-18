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

#include "gspm_manager.h"

#include <collections/linked_list.h>
#include <src/libcharon/encoding/payloads/notify_payload.h>

typedef struct private_gspm_manager_t private_gspm_manager_t;
typedef struct gspm_entry_t gspm_entry_t;

ENUM(gspm_memberlist_names, GSPM_RESERVED, GSPM_SPSKA,
	"GSPM_RESERVED",
	"GSPM_PACE",
	"GSPM_AUGPAKE",
	"GSPM_SPSKA",
);

/**
 * GSPM constructor entry
 */
struct gspm_entry_t {

};

/**
 * private data of gspm_manager
 */
struct private_gspm_manager_t {
	/**
	 * public functions
	 */
	gspm_manager_t public;
};

METHOD(gspm_manager_t, destroy, void,
	private_gspm_manager_t *this)
{
	free(this);
}

chunk_t gspm_generate_chunk()
{
	chunk_t chunk;
	u_int16_t method;

	method = GSPM_PACE;
	method = htons(method);
	chunk = chunk_from_thing(method);

	/** need to clone on heap, cause on stack byteorder changes after return (compiler, kernel...)*/
	return chunk_clone(chunk);
}

chunk_t gspm_generate_chunk_from_member(u_int16_t member)
{
	chunk_t chunk;
	u_int16_t method;

	method = member;
	method = htons(method);
	chunk = chunk_from_thing(method);

	/** need to clone on heap, cause on stack byteorder changes after return (compiler, kernel...)*/
	return chunk_clone(chunk);
}

u_int16_t gspm_select_member(message_t *message, bool initiator){
	notify_payload_t *notify_payload;
	linked_list_t *gspm_method_list;
	chunk_t data;
	u_int16_t method;

	if(initiator)
	{
		notify_payload = message->get_notify(message, SECURE_PASSWORD_METHOD);
		data = notify_payload->get_notification_data(notify_payload);
		method = ntohs(*(u_int16_t*) data.ptr);
		return method;
	}
	else
	{
		gspm_method_list = linked_list_create();
		notify_payload = message->get_notify(message, SECURE_PASSWORD_METHOD);
		if(notify_payload)
		{
			notify_payload = message->get_notify(message, SECURE_PASSWORD_METHOD);
			data = notify_payload->get_notification_data(notify_payload);
			method = ntohs(*(u_int16_t*) data.ptr);
			//TODO enumerate data + memberlist

			if (method == GSPM_PACE)
			{
				gspm_method_list->insert_last(gspm_method_list, (u_int16_t*) GSPM_PACE);
			}

			/** enumerate list, add and choose methods -> MANAGER
			 *

			enumerator = gspm_method_list->create_enumerator(gspm_method_list);
			while (enumerator->enumerate(enumerator, &gm))
			{
				if(gm == GSPM_PACE)
				{
				this->gspm_member = (u_int16_t) GSPM_PACE;
				}
			}
			enumerator->destroy(enumerator);
			 */
		}
	}
	return 1;
}

gspm_manager_t *gspm_manager_create()
{
	private_gspm_manager_t *this;

	INIT(this,
			.public = {
				.destroy = _destroy,
			},
	);

	return &this->public;
}
