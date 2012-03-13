/*
 * Copyright (C) 2012 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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
 * @defgroup libradius libradius
 *
 * @addtogroup libradius
 * RADIUS protocol support library.
 *
 * @defgroup radius_msse radius_msse
 * @{ @ingroup libradius
 */

#ifndef RADIUS_MSSE_H_
#define RADIUS_MSSE_H_

/**
 * Microsoft specific vendor attributes
 */
#define MS_MPPE_SEND_KEY 16
#define MS_MPPE_RECV_KEY 17

typedef struct mppe_key_t mppe_key_t;

struct mppe_key_t {
	u_int32_t id;
	u_int8_t type;
	u_int8_t length;
	u_int16_t salt;
	u_int8_t key[];
} __attribute__((packed));

#endif /** RADIUS_MSSE_H_ @}*/