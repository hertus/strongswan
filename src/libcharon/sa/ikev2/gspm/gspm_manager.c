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

#include <daemon.h>
#include <threading/rwlock.h>
#include <collections/linked_list.h>
#include <src/libcharon/encoding/payloads/notify_payload.h>

typedef struct private_gspm_manager_t private_gspm_manager_t;
typedef struct gspm_entry_t gspm_entry_t;

ENUM(gspm_methodlist_names, GSPM_PACE, GSPM_SPSKA,
	"PACE",
	"AugPAKE",
	"Secure PSK Authentication",
);

/**
 * GSPM constructor entry
 */
struct gspm_entry_t {

	/**
	 * GSPM method number
	 */
	u_int16_t method_id;

	/**
	 * method is verifier or builder
	 */
	bool verifier;

	/**
	 * constructor function to create instance
	 */
	gspm_method_constructor_t constructor;
};

/**
 * private data of gspm_manager
 */
struct private_gspm_manager_t {
	/**
	 * public functions
	 */
	gspm_manager_t public;

	/**
	 * list of gspm_entry_t's
	 */
	linked_list_t *methods;

	/**
	 * list of unique registered methods;
	 */
	linked_list_t *reg_methods;

	/**
	 * rwlock to lock methods
	 */
	rwlock_t *lock;
};

chunk_t chunk_from_method(u_int16_t method_id)
{
	chunk_t chunk;
	u_int16_t method;

	method = htons(method_id);
	chunk = chunk_from_thing(method);

	/** need to clone on heap, cause on stack byteorder changes after
	 * return (compiler, kernel...)
	 */
	return chunk_clone(chunk);
}

METHOD(gspm_manager_t, get_notify_chunk, chunk_t,
	private_gspm_manager_t *this)
{
	chunk_t chunk;

	chunk = chunk_from_method(GSPM_PACE);
	chunk = chunk_cat("cc", chunk, chunk_from_method(GSPM_AUGPAKE));

	return chunk_clone(chunk);
}

METHOD(gspm_manager_t, get_notify_chunk_from_method, chunk_t,
	private_gspm_manager_t *this, u_int16_t method_id)
{
	chunk_t chunk;

	chunk = chunk_from_method(method_id);

	return chunk_clone(chunk);
}

METHOD(gspm_manager_t, get_selected_method, u_int16_t,
	private_gspm_manager_t *this, message_t *message, bool initiator)
{
	notify_payload_t *notify_payload;
	u_int16_t method;
	chunk_t data;
	int len;

	notify_payload = message->get_notify(message, SECURE_PASSWORD_METHOD);
	data = notify_payload->get_notification_data(notify_payload);

	if(!initiator && data.len > 2)
	{
		for(len = 0; len < data.len; len += 2)
		{
			data.ptr += len;
			method = ntohs(*(u_int16_t*) data.ptr);
			DBG1(DBG_IKE, "GSPM method in chunk: %d", method);
			switch (method) {
				case GSPM_PACE:
					return GSPM_PACE;
				case GSPM_AUGPAKE:
					return GSPM_AUGPAKE;
				case GSPM_SPSKA:
					return GSPM_SPSKA;
				default:
					break;
			}
		}
	}
	else
	{
		if(data.len == 2)
		{
			method = ntohs(*(u_int16_t*) data.ptr);
			return method;
		}
	}
	return 0;
}


METHOD(gspm_manager_t, add_method, void,
	private_gspm_manager_t *this, u_int16_t method_id,
	bool verifier, gspm_method_constructor_t constructor)
{
	gspm_entry_t *entry = malloc_thing(gspm_entry_t);

	entry->method_id = method_id;
	entry->verifier = verifier;
	entry->constructor = constructor;

	this->lock->write_lock(this->lock);
	this->methods->insert_last(this->methods, entry);
	this->lock->unlock(this->lock);
}

METHOD(gspm_manager_t, remove_method, void,
	private_gspm_manager_t *this, gspm_method_constructor_t constructor)
{
	enumerator_t *enumerator;
	gspm_entry_t *entry;

	this->lock->write_lock(this->lock);
	enumerator = this->methods->create_enumerator(this->methods);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (constructor == entry->constructor)
		{
			this->methods->remove_at(this->methods, enumerator);
			free(entry);
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
}

METHOD(gspm_manager_t, create_instance, gspm_method_t*,
	private_gspm_manager_t *this, u_int16_t method_id, bool verifier,
	ike_sa_t *ike_sa, chunk_t received_nonce, chunk_t sent_nonce,
	chunk_t received_init, chunk_t sent_init, char reserved[3])
{
	enumerator_t *enumerator;
	gspm_entry_t *entry;
	gspm_method_t *method = NULL;

	this->lock->read_lock(this->lock);
	enumerator = this->methods->create_enumerator(this->methods);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (method_id == entry->method_id && verifier == entry->verifier)
		{
			method = entry->constructor(
					verifier, ike_sa,
					received_nonce, sent_nonce,
					received_init, sent_init,
					reserved);
			if (method)
			{
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
	return method;
}

METHOD(gspm_manager_t, destroy, void,
	private_gspm_manager_t *this)
{
	free(this);
}

gspm_manager_t *gspm_manager_create()
{
	private_gspm_manager_t *this;

	INIT(this,
			.public = {
				.add_method = _add_method,
				.remove_method = _remove_method,
				.create_instance = _create_instance,
				.get_notify_chunk = _get_notify_chunk,
				.get_selected_method = _get_selected_method,
				.get_notify_chunk_from_method = _get_notify_chunk_from_method,
				.destroy = _destroy,
			},
			.methods = linked_list_create(),
			.reg_methods = 	linked_list_create(),
			.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	return &this->public;
}
