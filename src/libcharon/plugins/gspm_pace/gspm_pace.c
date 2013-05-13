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
#include <bio/bio_reader.h>
#include <bio/bio_writer.h>
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
	 * new DH with GE
	 */
	diffie_hellman_t *dh_ge;

	/**
	 * other public key from DH
	 */
	chunk_t my_pke;

	/**
	 * other public key from DH
	 */
	chunk_t other_pke;

	/**
	 * random nonce s
	 */
	chunk_t s;

	/**
	 * Signalize if it's round 1 or 2
	 */
	bool round_two;

	/**
	 * PRF algorithm
	 */
	u_int16_t prf_algorithm;

	/**
	 * Encrpytion algorithm
	 */
	u_int16_t enc_algorithm;

	/**
	 * Encryption keysize
	 */
	u_int16_t enc_keysize;

	/**
	 * DH group from IKE_SA_INIT
	 */
	u_int16_t dh_group;

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
bool prf_kpwd(private_gspm_method_pace_t *this, chunk_t key, chunk_t nonce_i,
	chunk_t nonce_r,chunk_t *kpwd)
{
	prf_t *prf;
	prf_plus_t *prfp;
	chunk_t pace_seed, nonce_seed, spwd;

	prf = lib->crypto->create_prf(lib->crypto, this->prf_algorithm);

	pace_seed = chunk_from_str("IKE with PACE");
	nonce_seed = chunk_cat("cc", nonce_i, nonce_r);

	/* SPwd = prf("IKE with PACE", Pwd) */
	if (!prf->set_key(prf, key) ||
		!prf->allocate_bytes(prf, pace_seed, &spwd) ||
		!prf->set_key(prf, spwd))
	{
		DBG1(DBG_IKE, "GSPM PACE failed creating prf");
		prf->destroy(prf);
		return FALSE;
	}

	/**
	 * KPwd = prf+(Ni | Nr, SPwd)
	 * KPwd length determined by encryption key length
	 */
	prfp = prf_plus_create(prf, TRUE, nonce_seed);
	if(!prfp->allocate_bytes(prfp, this->enc_keysize / 8, kpwd))
	{
		DBG1(DBG_IKE, "GSPM PACE failed creating prf+");
		chunk_free(&spwd);
		prf->destroy(prf);
		prfp->destroy(prfp);
		return FALSE;
	}
	chunk_free(&spwd);
	prf->destroy(prf);
	prfp->destroy(prfp);
	return TRUE;
}

/**
 * Create new DH with new generator GE for PACE
 */
bool create_new_dh_ge(private_gspm_method_pace_t *this)
{
	mpz_t g, ge, p, nonce_s, sa_secret, check1, check2, one;
	diffie_hellman_params_t *dh_param;
	chunk_t new_ge, shared_secret;

	shared_secret = gspm_pace_listener->get_shared_secret(
		gspm_pace_listener, this->ike_sa);

	if(!(shared_secret.len > 0))
	{
		DBG1(DBG_IKE, "GSPM PACE failed to get IKE_INIT shared secret");
		return FALSE;
	}

	dh_param = diffie_hellman_get_params(this->dh_group);

	DBG1(DBG_IKE, "GSPM PACE secret from init: %B", &shared_secret);
	DBG1(DBG_IKE, "GSPM PACE p from init: %B", &dh_param->prime);

	mpz_init(g);
	mpz_init(ge);
	mpz_init(p);
	mpz_init(nonce_s);
	mpz_init(sa_secret);

	mpz_import(g, dh_param->generator.len, 1, 1, 1, 0, dh_param->generator.ptr);
	mpz_import(p, dh_param->prime.len, 1, 1, 1, 0, dh_param->prime.ptr);
	mpz_import(nonce_s, this->s.len, 1, 1, 1, 0, this->s.ptr);
	mpz_import(sa_secret, shared_secret.len, 1, 1, 1, 0, shared_secret.ptr);

	/**
	 * Mapping the NONCE if DH is Elliptic
	 * GE = s*G + SASharedSecret
	 */
	if(diffie_hellman_group_is_ec(this->dh_group))
	{
		/** TODO implementation with OpenSSL*/

		/**
		 * checking values and fail if
		 * GE = s*G + SASharedSecret
		 */
		return FALSE;
	}
	/**
	 * Mapping the NONCE if DH is Modular
	 * GE = G^s * SASharedSecret
	 * since prime is part of G^s -> G^s mod(p)
	 * SharedSecret is part of g^ir -> GE mod(p)
	 */
	else
	{
		DBG1(DBG_IKE, "GSPM PACE mapping nonce DH Modular");
		mpz_powm_sec(ge, g, nonce_s, p);
		mpz_mul(ge, ge, sa_secret);
		mpz_mod(ge, ge, p);

		/**
		 * checking values and fail if
		 * G^s = 1/SASharedSecret
		 */
		mpz_init(check1);
		mpz_init(check2);
		mpz_init_set_ui(one, 1);

		mpz_powm_sec(check1, g, nonce_s, p);
		mpz_div(check2, one, sa_secret);

		if(mpz_cmp(check1, check2) == 0)
		{
			DBG1(DBG_IKE, "GSPM PACE failed checking values, try again");
			mpz_clear(check1);
			mpz_clear(check2);
			mpz_clear(one);
			return FALSE;
		}
	}

	new_ge =  mpz_to_chunk(ge);

	DBG1(DBG_IKE, "GSPM PACE new GE: %B", &new_ge);

	mpz_clear(g);
	mpz_clear(ge);
	mpz_clear(p);
	mpz_clear(nonce_s);
	mpz_clear(sa_secret);
	mpz_clear(check1);
	mpz_clear(check2);
	mpz_clear(one);

	/**
	 * Create new DH with MODP_CUSTOM and chunk g, p
	 */
	this->dh_ge = lib->crypto->create_dh(lib->crypto, MODP_CUSTOM,
		new_ge, dh_param->prime);

	chunk_free(&new_ge);
	chunk_free(&shared_secret);

	return TRUE;
}

/**
 * prf function to create AUTH payload
 */
bool prf_auth_data(private_gspm_method_pace_t *this, chunk_t *auth_data,
	identification_t *id, chunk_t init, chunk_t nonce, chunk_t pke, bool verify)
{
	prf_t *prf;
	prf_plus_t *prfp;
	keymat_v2_t *keymat;
	chunk_t auth_octets, pace_shared_secret, prf_seed, prf_key, nonce_seed;

	keymat = (keymat_v2_t*)this->ike_sa->get_keymat(this->ike_sa);
	keymat->get_auth_octets(keymat, verify, init, nonce,
		id, this->reserved, &auth_octets);

	DBG1(DBG_IKE, "GSPM PACE auth_octet: %B", &auth_octets);

	/**
	 * Create AUTHir
	 * 	AUTHir = prf(prf+(Ni | Nr, PACESharedSecret),
  	 * 	<InitiatorSignedOctets> | PKEir)
	 */
	prf_key = chunk_cat("mc", auth_octets, pke);
	if(verify)
	{
		nonce_seed = chunk_cat("cc", this->received_nonce, this->sent_nonce);
	}
	else
	{
		nonce_seed = chunk_cat("cc", this->sent_nonce, this->received_nonce);
	}

	if (!this->dh_ge->get_shared_secret(this->dh_ge, &pace_shared_secret) == SUCCESS)
	{
		DBG1(DBG_IKE, "GSPM PACE could'nt get shared secret");
		return FAILED;
	}

	DBG1(DBG_IKE, "GSPM PACE pace_shared_secret: %B", &pace_shared_secret);

	/**
	 * prf+(Ni | Nr, PACESharedSecret)
	 */
	prf = lib->crypto->create_prf(lib->crypto, this->prf_algorithm);
	if (!prf)
	{
		DBG1(DBG_IKE, "GSPM PACE no prf created");
		chunk_free(&pace_shared_secret);
		return FAILED;
	}
	if(!prf->set_key(prf, pace_shared_secret))
	{
		DBG1(DBG_IKE, "GSPM PACE prf failed to set key");
		chunk_free(&pace_shared_secret);
		prf->destroy(prf);
		return FAILED;
	}

	prfp = prf_plus_create(prf, TRUE, nonce_seed);
	if(!prfp)
	{
		DBG1(DBG_IKE, "GSPM PACE no prf+ created");
		chunk_free(&pace_shared_secret);
		prf->destroy(prf);
		return FAILED;
	}
	if(!prfp->allocate_bytes(prfp, pace_shared_secret.len, &prf_seed))
	{
		DBG1(DBG_IKE, "GSPM PACE failed allocating prf+");
		chunk_free(&pace_shared_secret);
		prf->destroy(prf);
		prfp->destroy(prfp);
		return FAILED;
	}

	/**
	 * prf(prf+(Ni | Nr, PACESharedSecret),
	 *	<InitiatorSignedOctets> | PKEir)
	 */
	if(!prf->set_key(prf, prf_key) ||
		!prf->allocate_bytes(prf, prf_seed, auth_data))
	{
		DBG1(DBG_IKE, "GSPM PACE failed allocating prf for AUTH");
		chunk_free(&pace_shared_secret);
		chunk_free(&prf_seed);
		prfp->destroy(prfp);
		prf->destroy(prf);
		return FAILED;
	}

	chunk_free(&prf_seed);
	chunk_free(&pace_shared_secret);
	prfp->destroy(prfp);
	prf->destroy(prf);
	return TRUE;
}

bool verify_auth(private_gspm_method_pace_t *this, message_t *message)
{
	auth_payload_t *auth_payload;
	chunk_t auth_data, recv_auth_data;

	auth_payload = (auth_payload_t*)message->get_payload(message, AUTHENTICATION);
	if (!auth_payload)
	{
		DBG1(DBG_IKE, "GSPM PACE no auth_payload");
		return FALSE;
	}

	recv_auth_data = auth_payload->get_data(auth_payload);

	if(!prf_auth_data(this, &auth_data, this->ike_sa->get_other_id(this->ike_sa),
		this->received_init, this->received_nonce, this->my_pke, TRUE))
	{
		DBG1(DBG_IKE, "GSPM PACE couldn't create auth data");
		chunk_free(&recv_auth_data);
		return FALSE;
	}

	DBG1(DBG_IKE, "GSPM PACE recv_auth_data: %B", &recv_auth_data);
	DBG1(DBG_IKE, "GSPM PACE auth_data: %B", &auth_data);

	if(!auth_data.len || !chunk_equals(auth_data, recv_auth_data))
	{
		DBG1(DBG_IKE, "GSPM PACE auth_data invalid");
		chunk_free(&auth_data);
		chunk_free(&recv_auth_data);
		return FALSE;
	}

	chunk_free(&auth_data);
	chunk_free(&recv_auth_data);

	return TRUE;
}

METHOD(gspm_method_t, build_initiator, status_t,
		private_gspm_method_pace_t *this, message_t *message)
{
	ke_payload_t *ke_payload;
	auth_payload_t *auth_payload;
	gspm_payload_t *gspm_payload;
	chunk_t gspm_data, enonce, iv, kpwd, auth_data;
	identification_t *my_id, *other_id;
	shared_key_t *shared_key;
	rng_t *rng;
	u_int8_t st;
	crypter_t *crypter;

	if(!this->round_two)
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
		if(!shared_key)
		{
			DBG1(DBG_IKE, "GSPM PACE failed to get shared key");
			return FAILED;
		}

		if(!prf_kpwd(this, shared_key->get_key(shared_key), this->sent_nonce,
			this->received_nonce, &kpwd))
		{
			DBG1(DBG_IKE, "GSPM PACE failed creating KPwd");
			shared_key->destroy(shared_key);
			return FAILED;
		}
		shared_key->destroy(shared_key);

		/**
		 * creating NONCE s - size 32 octets
		 * nonce not weak -> don't use noncegen, use rng with STRONG
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
			chunk_free(&kpwd);
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

		DBG1(DBG_IKE, "GSPM PACE nonce s : %B", &this->s);

		if(!crypter->set_key(crypter, kpwd) ||
			!crypter->encrypt(crypter, this->s, iv, &enonce))
		{
			DBG1(DBG_IKE, "GSPM PACE failed encrypting the nonce");
			chunk_free(&kpwd);
			crypter->destroy(crypter);
			return FAILED;
		}
		chunk_free(&kpwd);
		crypter->destroy(crypter);

		/* gspm_data = subtype | IV | ENONCE */
		gspm_data = chunk_cat("mmm", chunk_from_thing(st), iv, enonce);
		gspm_payload = gspm_payload_create();
		gspm_payload->set_data(gspm_payload, gspm_data);
		chunk_free(&gspm_data);
		message->add_payload(message, (payload_t*)gspm_payload);

		/**
		 * New DH round
		 */
		if(!create_new_dh_ge(this))
		{
			DBG1(DBG_IKE, "GSPM PACE creating new DH failed");
			return FAILED;
		}

		this->dh_ge->get_my_public_value(this->dh_ge, &this->my_pke);

		DBG1(DBG_IKE,"GSPM my pke: %B", &this->my_pke);

		ke_payload = ke_payload_create_from_diffie_hellman(KEY_EXCHANGE,
			this->dh_ge);
		message->add_payload(message, (payload_t*)ke_payload);

		this->round_two = TRUE;

		return NEED_MORE;
	}
	else
	{
		DBG1(DBG_IKE, "GSPM PACE build i round#2");

		if(!prf_auth_data(this, &auth_data, this->ike_sa->get_my_id(this->ike_sa),
			this->sent_init, this->sent_nonce, this->other_pke, FALSE))
		{
			DBG1(DBG_IKE, "GSPM PACE couldn't create auth data");
			return FAILED;
		}

		auth_payload = auth_payload_create();
		auth_payload->set_auth_method(auth_payload, AUTH_GSPM);
		auth_payload->set_data(auth_payload, auth_data);
		message->add_payload(message, (payload_t*)auth_payload);

		/**
		 * TODO if Long Term Secret is used
		message->add_notify(message, FALSE, PSK_PERSIST, chunk_empty);
		 */

		chunk_free(&auth_data);
		return NEED_MORE;
	}
}

METHOD(gspm_method_t, process_responder, status_t,
		private_gspm_method_pace_t *this, message_t *message)
{
	gspm_payload_t *gspm_payload;
	ke_payload_t *ke_payload;
	chunk_t recv_gspm_data, iv, enonce, kpwd;
	identification_t *my_id, *other_id;
	shared_key_t *shared_key;
	u_int8_t st;
	crypter_t *crypter;
	bio_reader_t *reader;

	if(!message->get_payload(message, AUTHENTICATION))
	{
		DBG1(DBG_IKE, "GSPM PACE process r round #1");

		gspm_payload = (gspm_payload_t*)message->get_payload(message,
			GENERIC_SECURE_PASSWORD_METHOD);
		if(!gspm_payload )
		{
			DBG1(DBG_IKE, "GSPM PACE failed to get gspm payload data");
			return FAILED;
		}

		ke_payload = (ke_payload_t*)message->get_payload(message, KEY_EXCHANGE);
		if(!ke_payload)
		{
			DBG1(DBG_IKE, "GSPM PACE failed to get ke payload data");
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
		if(!shared_key)
		{
			DBG1(DBG_IKE, "GSPM PACE failed to get shared key");
			return FAILED;
		}
		if(!prf_kpwd(this, shared_key->get_key(shared_key), this->received_nonce,
			this->sent_nonce, &kpwd))
		{
			DBG1(DBG_IKE, "GSPM PACE failed creating KPwd");
			shared_key->destroy(shared_key);
			return FAILED;
		}
		shared_key->destroy(shared_key);

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

		reader = bio_reader_create(recv_gspm_data);
		if(!reader->read_uint8(reader, &st) ||
			!reader->read_data(reader, iv.len, &iv) ||
			!reader->read_data(reader, reader->remaining(reader), &enonce))
		{
			DBG1(DBG_IKE, "GSPM PACE reading gspm_data failed");
			reader->destroy(reader);
			return FAILED;
		}
		reader->destroy(reader);

		/**
		 * Fail if state value in GSPM payload is not pace_reserved = 0
		 */
		if(st != 0)
		{
			DBG1(DBG_IKE, "GSPM PACE subtype not PACE RESERVED");
			return FAILED;
		}

		if(!crypter->set_key(crypter, kpwd) ||
			!crypter->decrypt(crypter, enonce, iv, &this->s))
		{
			DBG1(DBG_IKE, "GSPM PACE failed decrypting the enonce");
			chunk_free(&iv);
			chunk_free(&enonce);
			chunk_free(&kpwd);
			crypter->destroy(crypter);
			return FAILED;
		}
		crypter->destroy(crypter);

		DBG1(DBG_IKE, "GSPM PACE nonce s : %B", &this->s);

		if(!create_new_dh_ge(this))
		{
			DBG1(DBG_IKE, "GSPM PACE creating new DH failed");
			return FAILED;
		}

		this->dh_ge->get_my_public_value(this->dh_ge, &this->my_pke);
		this->other_pke = ke_payload->get_key_exchange_data(ke_payload);
		this->dh_ge->set_other_public_value(this->dh_ge, this->other_pke);

		DBG1(DBG_IKE,"GSPM my pke: %B", &this->my_pke);
		DBG1(DBG_IKE,"GSPM other pke: %B", &this->other_pke);

		chunk_t ss;
		this->dh_ge->get_shared_secret(this->dh_ge, &ss);
		DBG1(DBG_IKE,"GSPM ss: %B", &ss);
		chunk_free(&ss);

		chunk_free(&iv);
		chunk_free(&enonce);
		chunk_free(&kpwd);
		return NEED_MORE;
	}
	else
	{
		DBG1(DBG_IKE, "GSPM PACE process r round #2");
		if(!verify_auth(this, message))
		{
			DBG1(DBG_IKE, "GSPM PACE couldn't verify auth");
			return FAILED;
		}
		return NEED_MORE;
	}
}

METHOD(gspm_method_t, build_responder, status_t,
		private_gspm_method_pace_t *this, message_t *message)
{
	ke_payload_t *ke_payload;
	auth_payload_t *auth_payload;
	chunk_t auth_data;

	if(!this->round_two)
	{
		DBG1(DBG_IKE, "GSPM PACE build r round #1");
		ke_payload = ke_payload_create_from_diffie_hellman(KEY_EXCHANGE, this->dh_ge);
		if(!ke_payload)
		{
			DBG1(DBG_IKE, "GSPM PACE failed to create KE payload");
			return FAILED;
		}
		message->add_payload(message, (payload_t*)ke_payload);
		this->round_two = TRUE;
		return NEED_MORE;
	}
	else
	{
		DBG1(DBG_IKE, "GSPM PACE build r round #2");

		if(!prf_auth_data(this, &auth_data, this->ike_sa->get_my_id(this->ike_sa),
			this->sent_init, this->sent_nonce, this->other_pke, FALSE))
		{
			DBG1(DBG_IKE, "GSPM PACE couldn't create auth data");
			return FAILED;
		}

		auth_payload = auth_payload_create();
		auth_payload->set_auth_method(auth_payload, AUTH_GSPM);
		auth_payload->set_data(auth_payload, auth_data);
		chunk_free(&auth_data);
		message->add_payload(message, (payload_t*)auth_payload);

		/**
		 * TODO if Long Term Secret is used
		message->add_notify(message, FALSE, PSK_PERSIST, chunk_empty);
		 */
		return SUCCESS;
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
		if(!ke_payload)
		{
			DBG1(DBG_IKE, "GSPM PACE failed to get ke payload data");
			return FAILED;
		}

		this->other_pke = ke_payload->get_key_exchange_data(ke_payload);
		this->dh_ge->set_other_public_value(this->dh_ge, this->other_pke);

		DBG1(DBG_IKE,"GSPM other pke: %B", &this->other_pke);

		chunk_t ss;
		this->dh_ge->get_shared_secret(this->dh_ge, &ss);
		DBG1(DBG_IKE,"GSPM ss: %B", &ss);
		chunk_free(&ss);

		return NEED_MORE;
	}
	else
	{
		DBG1(DBG_IKE, "GSPM PACE process i round #2");
		if(!verify_auth(this, message))
		{
			DBG1(DBG_IKE, "GSPM PACE couldn't verify auth");
			return FAILED;
		}
		return SUCCESS;
	}

}

METHOD(gspm_method_t, destroy, void,
		private_gspm_method_pace_t *this)
{
	DESTROY_IF(this->dh_ge);
	chunk_free(&this->my_pke);
	chunk_free(&this->other_pke);
	chunk_free(&this->s);
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

	this->round_two = FALSE;

	memcpy(this->reserved, reserved, sizeof(this->reserved));

	return &this->public;
}
