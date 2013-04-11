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

#include "gspm_payload.h"

#include <bio/bio_writer.h>

typedef struct private_gspm_payload_t private_gspm_payload_t;

/**
 * Private part of a gspm_payload_t object.
 *
 */
struct private_gspm_payload_t {
	/**
	 * public gspm_payload_t interface
	 */
	gspm_payload_t public;

	/**
	 * next payload type
	 */
	u_int8_t next_payload;

	/**
	 * critical flag
	 */
	bool critical;

	/**
	 * reserved bits
	 */
	bool reserved[7];

	/**
	 * payload length
	 */
	uint16_t payload_length;

	/**
	 * GSPM-specific Data
	 */
	chunk_t gspm_data;

};
/**
 * Encoding rules to parse or generate a GSPM payload.
 *
 * The defined offsets are the positions in a object of type
 * private_gspm_payload_t.
 *
 */
static encoding_rule_t encodings[] = {
	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_gspm_payload_t, next_payload) 	},
	/* the critical bit */
	{ FLAG,				offsetof(private_gspm_payload_t, critical) 		},
	/* 7 Bit reserved bits, nowhere stored */
	{ RESERVED_BIT,		offsetof(private_gspm_payload_t, reserved[0])	},
	{ RESERVED_BIT,		offsetof(private_gspm_payload_t, reserved[1])	},
	{ RESERVED_BIT,		offsetof(private_gspm_payload_t, reserved[2])	},
	{ RESERVED_BIT,		offsetof(private_gspm_payload_t, reserved[3])	},
	{ RESERVED_BIT,		offsetof(private_gspm_payload_t, reserved[4])	},
	{ RESERVED_BIT,		offsetof(private_gspm_payload_t, reserved[5])	},
	{ RESERVED_BIT,		offsetof(private_gspm_payload_t, reserved[6])	},
	/* Length of the whole payload*/
	{ PAYLOAD_LENGTH,	offsetof(private_gspm_payload_t, payload_length)},
	/* chunt to data, starting at "code" */
	{ CHUNK_DATA,		offsetof(private_gspm_payload_t, gspm_data)		},
};


/* Generic Secure Password Method (GSPM) payload:
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~         Data Specific to the Secure Password Method           ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/* If the method uses payload subtypes (which are specific to the secure
   password method) inside the GSPM payload:
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Subtype*    |                                               |
   +-+-+-+-+-+-+-+-+                                               +
   |                                                               |
   ~         Data Specific to the Secure Password Method           ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * method-specific subtype field
 */

METHOD(payload_t, has_subtype, bool, private_gspm_payload_t *this)
{
	return true;
}

METHOD(payload_t, verify, status_t,
	private_gspm_payload_t *this)
{
	return SUCCESS;
}

METHOD(payload_t, get_encoding_rules, int,
	private_gspm_payload_t *this, encoding_rule_t **rules)
{
	*rules = encodings;
	return countof(encodings);
}

METHOD(payload_t, get_header_length, int,
	private_gspm_payload_t *this)
{
	return 8;
}

METHOD(payload_t, get_type, payload_type_t,
	private_gspm_payload_t *this)
{
	return AUTHENTICATION;
}

METHOD(payload_t, get_next_type, payload_type_t,
	private_gspm_payload_t *this)
{
	return this->next_payload;
}

METHOD(payload_t, set_next_type, void,
	private_gspm_payload_t *this, payload_type_t type)
{
	this->next_payload = type;
}

METHOD(payload_t, get_length, size_t,
	private_gspm_payload_t *this)
{
	return this->payload_length;
}

METHOD(gspm_payload_t, set_data, void,
	private_gspm_payload_t *this, chunk_t data)
{
	free(this->gspm_data.ptr);
	this->gspm_data = chunk_clone(data);
	this->payload_length = get_header_length(this) + this->gspm_data.len;
}

METHOD(gspm_payload_t, get_data, chunk_t,
	private_gspm_payload_t *this)
{
	return this->gspm_data;
}

METHOD2(payload_t, gspm_payload_t, destroy, void,
	private_gspm_payload_t *this)
{
	chunk_free(&this->gspm_data);
	free(this);
}

/*
 * Described in header
 */
gspm_payload_t *gspm_payload_create()
{
	private_gspm_payload_t *this;

	INIT(this,
		.public = {
			.payload_interface = {
				.verify = _verify,
				.get_encoding_rules = _get_encoding_rules,
				.get_header_length = _get_header_length,
				.get_length = _get_length,
				.get_next_type = _get_next_type,
				.set_next_type = _set_next_type,
				.get_type = _get_type,
				.destroy = _destroy,
			},
			.set_data = _set_data,
			.get_data = _get_data,
			.destroy = _destroy,
		},
		.next_payload = NO_PAYLOAD,
		.payload_length = get_header_length(this),
	);
	return &this->public;
}

