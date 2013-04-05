/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
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
#include <threading/rwlock.h>

typedef struct private_gspm_manager_t private_gspm_manager_t;
typedef struct gspm_entry_t gspm_entry_t;

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

gspm_manager_t *gspm_manager_create()
{
	private_gspm_manager_t *this;

	INIT(this,
			.public = {
				.destroy = _destroy,
			},
			.methods = linked_list_create(),
			.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	return &this->public;
}
