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

/**PACE gspm manager for method injection authenticator - plugin */

#ifndef GSPM_MANAGER_H_
#define GSPM_MANAGER_H_

typedef struct gspm_manager_t gspm_manager_t;

struct gspm_manager_t {

	void (*destroy)(gspm_manager_t *this);
};

gspm_manager_t *gspm_manager_create();

#endif /** GSPM_MANAGER_H_ @}*/
