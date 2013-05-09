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

#include "gspm_pace.h"
#include "gspm_pace_plugin.h"

#include <gmp.h>
#include <daemon.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/gspm_payload.h>
#include <sa/ikev2/gspm/gspm_method.h>
#include <sa/ikev2/keymat_v2.h>

#ifdef HAVE_MPZ_POWM_SEC
# undef mpz_powm
# define mpz_powm mpz_powm_sec
#endif

typedef struct private_gspm_method_pace_t private_gspm_method_pace_t;

/**
 * Private data of an gspm_method_pace_t object.
 */
struct private_gspm_method_pace_t {

	/**
	 * Public gspm_method interface
	 */
	gspm_method_pace_t public;

	/**
	 * if its a verifier or not
	 */
	bool pace_verifier;

	/**
	 * Assigned IKE_SA
	 */
	ike_sa_t *ike_sa;

	/**
	 * others nonce to include in AUTH calculation
	 */
	chunk_t received_nonce;

	/**
	 * our nonce to include in AUTH calculation
	 */
	chunk_t sent_nonce;

	/**
	 * others IKE_SA_INIT message data to include in AUTH calculation
	 */
	chunk_t received_init;

	/**
	 * our IKE_SA_INIT message data to include in AUTH calculation
	 */
	chunk_t sent_init;

	/**
	 * Reserved bytes of ID payload
	 */
	char reserved[3];

	/**
	 * Signalize if it's round 1 or 2
	 */
	bool round2;

	/**
	 * Encrpytion settings
	 */
	u_int16_t prf_algorithm, enc_algorithm, enc_keysize, dh_group;

	/**
	 * prf with prf_algorithm
	 */
	prf_t *prf;

	/**
	 * random nonce s
	 */
	chunk_t s;

	/**
	 * new DH with GE
	 */
	diffie_hellman_t *dh_ge;

	/**
	 * shared secret from IKE_INIT
	 */
	chunk_t shared_secret;
};

/**
 * Convert a MP integer into a chunk_t
 */
chunk_t mpz_to_chunk(const mpz_t value)
{
	chunk_t n;

	n.len = 1 + mpz_sizeinbase(value, 2) / BITS_PER_BYTE;
	n.ptr = mpz_export(NULL, NULL, 1, n.len, 1, 0, value);
	if (n.ptr == NULL)
	{	/* if we have zero in "value", gmp returns NULL */
		n.len = 0;
	}
	return n;
}

/**
 * Map counter-mode encryption algorithm if necessary
 */
void map_cm_encr(private_gspm_method_pace_t *this)
{
	switch(this->enc_algorithm)
	{
		case ENCR_AES_CCM_ICV8:
		case ENCR_AES_CCM_ICV12:
		case ENCR_AES_CCM_ICV16:
		case ENCR_AES_GCM_ICV8:
		case ENCR_AES_GCM_ICV12:
		case ENCR_AES_GCM_ICV16:
			this->enc_algorithm = ENCR_AES_CTR;
			break;
		case ENCR_CAMELLIA_CCM_ICV8:
		case ENCR_CAMELLIA_CCM_ICV12:
		case ENCR_CAMELLIA_CCM_ICV16:
			this->enc_algorithm = ENCR_CAMELLIA_CTR;
			break;
		default:
			break;
	}
}

/**
 * prf function to create KPwd from key (password)
 */
bool prf_kpwd(private_gspm_method_pace_t *this, chunk_t key, chunk_t *kpwd)
{
	prf_plus_t *prfp;
	chunk_t pace_seed, spwd, nonce_seed;

	this->prf = lib->crypto->create_prf(lib->crypto, this->prf_algorithm);

	pace_seed = chunk_from_str("IKE with PACE");
	nonce_seed = chunk_cat("cc", this->sent_nonce, this->received_nonce);

	/* SPwd = prf("IKE with PACE", Pwd) */
	if (this->prf->set_key(this->prf, key) &&
		this->prf->allocate_bytes(this->prf, pace_seed, &spwd) &&
		this->prf->set_key(this->prf, spwd))
	{
		DBG1(DBG_IKE, "GSPM PACE initiated PRF with: %N",
			pseudo_random_function_names, this->prf_algorithm);

		/**
		 * KPwd = prf+(Ni | Nr, SPwd)
		 * KPwd length determined by encryption key length
		 */
		prfp = prf_plus_create(this->prf, TRUE, nonce_seed);
		if(!prfp->allocate_bytes(prfp, this->enc_keysize / 8, kpwd))
		{
			DBG1(DBG_IKE, "GSPM PACE failed creating prf+");
			return FALSE;
		}
	}
	else
	{
		DBG1(DBG_IKE, "GSPM PACE failed creating prf");
		return FALSE;
	}
	return TRUE;
}

/**
 * Create new DH with new generator GE for PACE
 */
bool create_new_dh_ge(private_gspm_method_pace_t *this)
{
	mpz_t g, ge, p, nonce_s, sa_secret;
	diffie_hellman_params_t *dh_param;
	chunk_t new_ge;

	/**
	 * New DH round
	 */
	this->shared_secret = gspm_pace_listener->get_shared_secret(
		gspm_pace_listener, this->ike_sa);
	if(!(this->shared_secret.len > 0))
	{
		DBG1(DBG_IKE, "GSPM PACE failed to get IKE_INIT shared secret");
		return FALSE;
	}
	DBG1(DBG_IKE, "GSPM PACE IKE_INIT shared secret found");
	dh_param = diffie_hellman_get_params(this->dh_group);

	/**
	 * Initialize MPZ values
	 */
	mpz_init(g);
	mpz_init(ge);
	mpz_init(p);
	mpz_init(nonce_s);
	mpz_init(sa_secret);

	mpz_import(g, dh_param->generator.len, 1, 1, 1, 0, dh_param->generator.ptr);
	mpz_import(p, dh_param->prime.len, 1, 1, 1, 0, dh_param->prime.ptr);
	mpz_import(nonce_s, this->s.len, 1, 1, 1, 0, this->s.ptr);
	mpz_import(sa_secret, this->shared_secret.len, 1, 1, 1, 0, this->shared_secret.ptr);

	/**
	 * Mapping the NONCE if DH is Elliptic
	 * GE = s*G + SASharedSecret
	 */
	if(diffie_hellman_group_is_ec(this->dh_group))
	{
		/** TODO implementation with OpenSSL*/
		return FALSE;
	}
	/**
	 * Mapping the NONCE if DH is Modular
	 * GE = G^s * SASharedSecret
	 * since prime is part of G^s -> G^s mod(p)
	 * SharedSecret is part of g^ir
	 * -> G^(s+ir) mod(p)
	 */
	else
	{
		DBG1(DBG_IKE, "GSPM PACE mapping nonce DH Modular");
		mpz_powm_sec(ge, g, nonce_s, p);
		mpz_mul(ge, ge, sa_secret);
		mpz_mod(ge, ge, p);
	}

	new_ge =  mpz_to_chunk(ge);

	mpz_clear(g);
	mpz_clear(ge);
	mpz_clear(p);
	mpz_clear(nonce_s);
	mpz_clear(sa_secret);

	/**
	 * Create new DH with MODP_CUSTOM and chunk g, p
	 */
	this->dh_ge = lib->crypto->create_dh(lib->crypto, MODP_CUSTOM,
		new_ge, dh_param->prime);

	return TRUE;
}

METHOD(gspm_method_t, build_initiator, status_t,
		private_gspm_method_pace_t *this, message_t *message)
{
	gspm_payload_t *gspm_payload;
	chunk_t gspm_data;
	identification_t *my_id, *other_id;
	shared_key_t *shared_key;
	nonce_gen_t *nonceg;
	chunk_t enonce, iv;
	rng_t *rng;
	crypter_t *crypter;
	chunk_t kpwd;
	chunk_t subtype;
	u_int8_t subtype_pace;
	ke_payload_t *ke_payload;
	auth_payload_t *auth_payload;
	keymat_v2_t *keymat;

	if(!this->round2)
	{
		DBG1(DBG_IKE, "GSPM PACE build i round #1");

		/**
		 * PSK use instead of a PACE Password
		 */
		my_id = this->ike_sa->get_my_id(this->ike_sa);
		other_id = this->ike_sa->get_other_id(this->ike_sa);

		DBG1(DBG_IKE, "authentication of '%Y' (myself) with %N",
			 my_id, gspm_methodlist_names, GSPM_PACE);

		shared_key = lib->credmgr->get_shared(lib->credmgr, SHARED_IKE, my_id, other_id);

		if(!prf_kpwd(this, shared_key->get_key(shared_key), &kpwd))
		{
			DBG1(DBG_IKE, "GSPM PACE failed creating KPwd");
			return FAILED;
		}

		/**
		 * creating NONCE s - size 32 octets
		 * nonce not weak -> mb rng with STRONG
		 *
		nonceg = lib->crypto->create_nonce_gen(lib->crypto);
		if(!nonceg->allocate_nonce(nonceg, NONCE_SIZE, &this->s))
		{
			DBG1(DBG_IKE, "GSPM PACE nonce allocation failed");
			nonceg->destroy(nonceg);
			return FAILED;
		}
		nonceg->destroy(nonceg);
		 */
		rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
		if (!rng)
		{
			DBG1(DBG_IKE, "GSPM PACE no RNG found");
			return FAILED;
		}
		if(!rng->allocate_bytes(rng, NONCE_SIZE, &this->s))
		{
			DBG1(DBG_IKE, "GSPM PACE no random nonce s");
			rng->destroy(rng);
			return FAILED;
		}
		rng->destroy(rng);

		/**
		 * Encrypting the NONCE
		 * ENONCE = E(KPwd, s)
		 */
		if(!(kpwd.len == this->enc_keysize / 8))
		{
			DBG1(DBG_IKE, "GSPM PACE KPwd is not in keysize, kpwd: %d, keysize: %d bytes",
				kpwd.len, this->enc_keysize / 8);
			return FAILED;
		}
		DBG1(DBG_IKE, "GSPM PACE KPwd is in keysize, kpwd: %d, keysize: %d bytes",
			kpwd.len, this->enc_keysize / 8);

		map_cm_encr(this);

		crypter = lib->crypto->create_crypter(lib->crypto, this->enc_algorithm,
			this->enc_keysize / 8);

		if(!crypter)
		{
			DBG1(DBG_IKE, "GSPM PACE failed creating crypter");
			return FAILED;
		}

		iv.len = crypter->get_iv_size(crypter);

		rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
		if (!rng)
		{
			DBG1(DBG_IKE, "GSPM PACE no RNG found");
			return FAILED;
		}
		if(!rng->allocate_bytes(rng, iv.len, &iv))
		{
			DBG1(DBG_IKE, "GSPM PACE no IV");
			rng->destroy(rng);
			return FAILED;
		}
		rng->destroy(rng);

		if(!crypter->set_key(crypter, kpwd) ||
			!crypter->encrypt(crypter, this->s, iv, &enonce))
		{
			DBG1(DBG_IKE, "GSPM PACE failed encrypting the nonce");
			crypter->destroy(crypter);
			return FAILED;
		}
		crypter->destroy(crypter);

		DBG1(DBG_IKE, "GSPM PACE ENONCE created with len: %d",
			enonce.len);

		/**
		 * GSPM Payload
		 */
		subtype_pace = 0;
		subtype = chunk_from_thing(subtype_pace);
		gspm_data = chunk_cat("mmm", subtype, iv, enonce);

		gspm_payload = gspm_payload_create();
		gspm_payload->set_data(gspm_payload, gspm_data);
		chunk_free(&gspm_data);
		message->add_payload(message, (payload_t*)gspm_payload);

		/**
		 * New DH round
		 */
		if(!create_new_dh_ge(this))
		{
			return FAILED;
		}

		DBG1(DBG_IKE, "GSPM PACE new DH created");

		ke_payload = ke_payload_create_from_diffie_hellman(KEY_EXCHANGE,
			this->dh_ge);
		message->add_payload(message, (payload_t*)ke_payload);

		return NEED_MORE;
	}
	else
	{
		DBG1(DBG_IKE, "GSPM PACE build i round#2");

		/**
		 * Create AUTHi
		 * 	AUTHi = prf(prf+(Ni | Nr, PACESharedSecret),
      	 * 	<InitiatorSignedOctets> | PKEr)
		 */

		keymat = (keymat_v2_t*)this->ike_sa->get_keymat(this->ike_sa);

		auth_payload = auth_payload_create();
		auth_payload->set_auth_method(auth_payload, AUTH_GSPM);

		message->add_payload(message, (payload_t*)auth_payload);
		message->add_notify(message, FALSE, PSK_PERSIST, chunk_empty);

		return NEED_MORE;
	}

}

METHOD(gspm_method_t, process_responder, status_t,
		private_gspm_method_pace_t *this, message_t *message)
{
	gspm_payload_t *gspm_payload;
	ke_payload_t *ke_payload;
	chunk_t recv_gspm_data, state, iv, enonce;
	identification_t *my_id, *other_id;
	shared_key_t *shared_key;
	chunk_t kpwd;
	crypter_t *crypter;

	if(!message->get_payload(message, AUTHENTICATION))
	{
		DBG1(DBG_IKE, "GSPM PACE process r round #1");

		gspm_payload = (gspm_payload_t*)message->get_payload(message,
			SECURE_PASSWORD_METHOD);
		ke_payload = (ke_payload_t*)message->get_payload(message, KEY_EXCHANGE);

		if(!gspm_payload || !ke_payload)
		{
			DBG1(DBG_IKE, "GSPM PACE failed to get payload data");
			return FAILED;
		}

		/**
		 * PSK use instead of a PACE Password
		 */
		my_id = this->ike_sa->get_my_id(this->ike_sa);
		other_id = this->ike_sa->get_other_id(this->ike_sa);

		DBG1(DBG_IKE, "authentication of '%Y' (myself) with %N",
			 my_id, gspm_methodlist_names, GSPM_PACE);

		shared_key = lib->credmgr->get_shared(lib->credmgr, SHARED_IKE, my_id, other_id);

		if(!prf_kpwd(this, shared_key->get_key(shared_key), &kpwd))
		{
			DBG1(DBG_IKE, "GSPM PACE failed creating KPwd");
			return FAILED;
		}

		map_cm_encr(this);

		/**
		 * Decrypt ENONCE
		 */
		crypter = lib->crypto->create_crypter(lib->crypto, this->enc_algorithm,
			this->enc_keysize / 8);

		if(!crypter)
		{
			DBG1(DBG_IKE, "GSPM PACE failed creating crypter");
			return FAILED;
		}

		iv.len = crypter->get_iv_size(crypter);
		recv_gspm_data = gspm_payload->get_data(gspm_payload);

		/**
		 * TODO read with bioreader
		 */
		if(iv.len > 0)
		{
			state = chunk_create(recv_gspm_data.ptr, recv_gspm_data.ptr[1]);
			iv = chunk_create(recv_gspm_data.ptr + 8, recv_gspm_data.ptr[iv.len]);
			enonce = chunk_create(recv_gspm_data.ptr + 8 + iv.len, recv_gspm_data.ptr[32]);
		}
		else
		{
			state = chunk_create(recv_gspm_data.ptr, recv_gspm_data.ptr[1]);
			enonce = chunk_create(recv_gspm_data.ptr + 8, recv_gspm_data.ptr[32]);
		}

		if(!crypter->set_key(crypter, kpwd) ||
			!crypter->decrypt(crypter, enonce, iv, &this->s))
		{
			DBG1(DBG_IKE, "GSPM PACE failed decrypting the enonce");
			crypter->destroy(crypter);
			return FAILED;
		}
		crypter->destroy(crypter);

		if(!create_new_dh_ge(this))
		{
			return FAILED;
		}

		this->dh_ge->set_other_public_value(this->dh_ge,
			ke_payload->get_key_exchange_data(ke_payload));

		return NEED_MORE;
	}
	else
	{
		DBG1(DBG_IKE, "GSPM PACE process r round #2");
		this->round2 = TRUE;

		/**
		 * verify AUTHi
		 */

		return NEED_MORE;
	}
}

METHOD(gspm_method_t, build_responder, status_t,
		private_gspm_method_pace_t *this, message_t *message)
{
	ke_payload_t *ke_payload;
	auth_payload_t *auth_payload;
	keymat_v2_t *keymat;

	if(!this->round2)
	{
		DBG1(DBG_IKE, "GSPM PACE build r round #1");
		ke_payload = ke_payload_create_from_diffie_hellman(KEY_EXCHANGE, this->dh_ge);
		message->add_payload(message, (payload_t*)ke_payload);
		return NEED_MORE;
	}
	else
	{
		DBG1(DBG_IKE, "GSPM PACE build r round #2");
		/**
		 * Create AUTHr
		 * 	AUTHr = prf(prf+(Ni | Nr, PACESharedSecret),
      	 * 	<InitiatorSignedOctets> | PKEi)
		 */

		keymat = (keymat_v2_t*)this->ike_sa->get_keymat(this->ike_sa);

		auth_payload = auth_payload_create();
		auth_payload->set_auth_method(auth_payload, AUTH_GSPM);

		message->add_payload(message, (payload_t*)auth_payload);
		message->add_notify(message, FALSE, PSK_PERSIST, chunk_empty);

		return NEED_MORE;
	}

}

METHOD(gspm_method_t, process_initiator, status_t,
		private_gspm_method_pace_t *this, message_t *message)
{
	ke_payload_t *ke_payload;

	if(!message->get_payload(message, AUTHENTICATION))
	{
		DBG1(DBG_IKE, "GSPM PACE process i round #1");
		ke_payload = (ke_payload_t*)message->get_payload(message, KEY_EXCHANGE);

		this->dh_ge->set_other_public_value(this->dh_ge,
			ke_payload->get_key_exchange_data(ke_payload));

		this->round2 = TRUE;

		return NEED_MORE;
	}
	else
	{
		DBG1(DBG_IKE, "GSPM PACE process i round #2");
		/**
		 * verify AUTHr
		 */

		return NEED_MORE;
	}

}

METHOD(gspm_method_t, destroy, void,
		private_gspm_method_pace_t *this)
{
	free(this);
}

/*
 * See header
 */
gspm_method_pace_t *gspm_method_pace_create(
		bool verifier, ike_sa_t *ike_sa,
		chunk_t received_nonce, chunk_t sent_nonce,
		chunk_t received_init, chunk_t sent_init,
		char reserved[3])
{
	private_gspm_method_pace_t *this;

	if(verifier)
	{
		INIT(this,
			.public = {
				.gspm_method = {
					.build = _build_responder,
					.process = _process_responder,
					.destroy = _destroy,
				},
			},
			.pace_verifier = verifier,
			.ike_sa = ike_sa,
			.received_nonce = received_nonce,
			.sent_nonce = sent_nonce,
			.received_init = received_init,
			.sent_init = sent_init,
		);
	}
	else
	{
		INIT(this,
			.public = {
				.gspm_method = {
					.build = _build_initiator,
					.process = _process_initiator,
					.destroy = _destroy,
				},
			},
			.pace_verifier = verifier,
			.ike_sa = ike_sa,
			.received_nonce = received_nonce,
			.sent_nonce = sent_nonce,
			.received_init = received_init,
			.sent_init = sent_init,
		);
	}
	this->ike_sa->get_proposal(this->ike_sa)->
		get_algorithm(this->ike_sa->get_proposal(this->ike_sa), ENCRYPTION_ALGORITHM,
		&this->enc_algorithm, &this->enc_keysize);
	DBG1(DBG_IKE, "GSPM PACE encryption algorithm is: %N",
		encryption_algorithm_names, this->enc_algorithm);

	this->ike_sa->get_proposal(this->ike_sa)->get_algorithm(
		this->ike_sa->get_proposal(this->ike_sa), PSEUDO_RANDOM_FUNCTION,
		&this->prf_algorithm, NULL);
	DBG1(DBG_IKE, "GSPM PACE pseudo random function is: %N",
		pseudo_random_function_names, this->prf_algorithm);

	this->ike_sa->get_proposal(this->ike_sa)->get_algorithm(
		this->ike_sa->get_proposal(this->ike_sa), DIFFIE_HELLMAN_GROUP,
		&this->dh_group, NULL);
	DBG1(DBG_IKE, "GSPM PACE DH group is: %N",
		diffie_hellman_group_names, this->dh_group);

	memcpy(this->reserved, reserved, sizeof(this->reserved));

	return &this->public;
}
