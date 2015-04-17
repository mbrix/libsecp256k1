/* Copyright, 2015 Matthew Branton
 * Distributed under the MIT license located in the LICENSE file.
 *
 * */

#include "erl_nif.h"

#include "libsecp256k1-config.h"
#include "secp256k1.c"
#include "testrand_impl.h"


// Prototypes


static ERL_NIF_TERM atom_from_result(ErlNifEnv* env, int res);
static ERL_NIF_TERM error_result(ErlNifEnv* env, char* error_msg);
static ERL_NIF_TERM ok_result(ErlNifEnv* env, ERL_NIF_TERM *r);
int get_compressed_flag(ErlNifEnv* env, ERL_NIF_TERM arg, int* compressed, int* pubkeylen);
int get_nonce_function(ErlNifEnv* env, ERL_NIF_TERM nonce_term, ERL_NIF_TERM nonce_data_term, secp256k1_nonce_function_t* noncefp, ErlNifBinary* noncedata);
int get_recid(ErlNifEnv* env, ERL_NIF_TERM argv, int* recid); 
// Global context
secp256k1_context_t *ctx;

static int
load(ErlNifEnv* env, void** priv, ERL_NIF_TERM load_info)
{
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    return 0;
}

static int
upgrade(ErlNifEnv* env, void** priv, void** old_priv, ERL_NIF_TERM load_info)
{
    return 0;
}

static void
unload(ErlNifEnv* env, void* priv)
{
	secp256k1_context_destroy(ctx);
    return;
}

static ERL_NIF_TERM
sha256(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	unsigned char* output;
	ErlNifBinary p;
	ERL_NIF_TERM r;

	if (!enif_inspect_binary(env, argv[0], &p)) {
       return enif_make_badarg(env);
    }

	// Create a NIF binary object with a 32 byte return
	output = enif_make_new_binary(env, 32, &r);
    secp256k1_sha256_t hasher;
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, (const unsigned char*)(p.data), p.size);
    secp256k1_sha256_finalize(&hasher, output);

    return r;
}

static ERL_NIF_TERM
hmac_sha256(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	unsigned char* output;
	ErlNifBinary key, input;
	ERL_NIF_TERM r;

	if (!enif_inspect_binary(env, argv[0], &key)) {
       return enif_make_badarg(env);
    }

	if (!enif_inspect_binary(env, argv[1], &input)) {
       return enif_make_badarg(env);
    }

	// Create a NIF binary object with a 32 byte return
	output = enif_make_new_binary(env, 32, &r);
    secp256k1_hmac_sha256_t hasher;
    secp256k1_hmac_sha256_initialize(&hasher, (const unsigned char*)(key.data), key.size);
    secp256k1_hmac_sha256_write(&hasher, (const unsigned char*)(input.data), input.size);
    secp256k1_hmac_sha256_finalize(&hasher, output);

    return r;
}

// Random Test Functions
//

static ERL_NIF_TERM
rand32(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM r;
	unsigned char* output = enif_make_new_binary(env, 4, &r);
	uint32_t v = secp256k1_rand32();
    memcpy(&v, output, 4);
	return r;
}

static ERL_NIF_TERM
rand256(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM r;
	unsigned char* output = enif_make_new_binary(env, 32, &r);
	secp256k1_rand256(output);
	return r;
}

// Number operations

// Scalar operations

// ECDSA key operations

static ERL_NIF_TERM
ec_seckey_verify(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary privkey;
	secp256k1_scalar_t key;
	unsigned char b32[32];
    int overflow = 0;
	int result;

	if (!enif_inspect_binary(env, argv[0], &privkey)) {
       return enif_make_badarg(env);
    }

    if (privkey.size != 32) {
    	return enif_make_badarg(env);
	}

	secp256k1_scalar_set_b32(&key, b32, &overflow);
	if (overflow || secp256k1_scalar_is_zero(&key)) {
		return enif_make_int(env, 0);
	}

	secp256k1_scalar_get_b32(privkey.data, &key);

    result = secp256k1_ec_seckey_verify(ctx, privkey.data);
    return atom_from_result(env, result);
}

static ERL_NIF_TERM
ec_pubkey_create(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	int result;
	ErlNifBinary privkey;
	ERL_NIF_TERM r;
	unsigned char* pubkey_buf;
	int pubkeylen, compressed;

	if (!enif_inspect_binary(env, argv[0], &privkey)) {
       return enif_make_badarg(env);
    }

	if (!get_compressed_flag(env, argv[1], &compressed, &pubkeylen)) {
		return error_result(env, "Compression flag invalid");
	}

	if (privkey.size != 32) {
		return error_result(env, "Private key size not 32 bytes");
	}

	pubkey_buf = enif_make_new_binary(env, pubkeylen, &r);
	result = secp256k1_ec_pubkey_create(ctx, pubkey_buf, &pubkeylen, privkey.data, compressed);
	if (result == 1) {
		return ok_result(env, &r);
	} else {
		return error(env, "Public key generation error");
	}

}


static ERL_NIF_TERM
ec_pubkey_decompress(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{

	ErlNifBinary pubkey;
	ERL_NIF_TERM r;
	unsigned char* decompressedkey;
	int pubkeylen;

	if (!enif_inspect_binary(env, argv[0], &pubkey)) {
       return enif_make_badarg(env);
    }

	if ((pubkey.size != 33) && (pubkey.size != 65)) {
		return error_result(env, "Public key size != 33 or 65 bytes");
	}


	pubkeylen = pubkey.size;
	decompressedkey = enif_make_new_binary(env, 65, &r);
	memcpy(decompressedkey, pubkey.data, pubkeylen);
	
	if (secp256k1_ec_pubkey_decompress(ctx, decompressedkey, &pubkeylen) == 0) {
		return enif_make_badarg(env);
	}
	return ok_result(env, &r);
	
}

static ERL_NIF_TERM
ec_pubkey_verify(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	int result;
	ErlNifBinary pubkey;
	
	if (!enif_inspect_binary(env, argv[0], &pubkey)) {
       return enif_make_badarg(env);
    }

    if ((pubkey.size != 33) && (pubkey.size != 65)) {
		return error_result(env, "Public key size != 33 or 65 bytes");
	}

	result = secp256k1_ec_pubkey_verify(ctx, pubkey.data, pubkey.size);
	return atom_from_result(env, result); 
}

static ERL_NIF_TERM
ec_privkey_export(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM r;
	ErlNifBinary privkey;
	unsigned char exported_seckey[300];
	unsigned char* seckey_buf;
	int seckey_len = 300;
	int compressed, pubkeylen, result;

	if (!enif_inspect_binary(env, argv[0], &privkey)) {
       return enif_make_badarg(env);
    }

    if (privkey.size != 32) {
    	return enif_make_badarg(env);
	}

	if (!get_compressed_flag(env, argv[1], &compressed, &pubkeylen)) {
		return error_result(env, "Compression flag invalid");
	}

	result = secp256k1_ec_privkey_export(ctx, privkey.data, exported_seckey, &seckey_len, compressed);
	if (result == 0) {
		return error_result(env, "privkey export returned 0");
	}

	seckey_buf = enif_make_new_binary(env, seckey_len, &r);
	memcpy(seckey_buf, exported_seckey, seckey_len);
	return ok_result(env, &r);
}

static ERL_NIF_TERM
ec_privkey_import(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM r;
	ErlNifBinary exportedkey;
	unsigned char* privkey_buf;
	int result;

	if (!enif_inspect_binary(env, argv[0], &exportedkey)) {
       return enif_make_badarg(env);
    }

	privkey_buf = enif_make_new_binary(env, 32, &r);
    result = secp256k1_ec_privkey_import(ctx, privkey_buf, exportedkey.data, exportedkey.size);
    if (result == 0) {
		return error_result(env, "privkey import returned 0");
	}

	return ok_result(env, &r);

}

static ERL_NIF_TERM
ec_privkey_tweak_add(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM r;
	ErlNifBinary privkey, tweak;
	unsigned char* privkey_buf;
	int result;

	if (!enif_inspect_binary(env, argv[0], &privkey)) {
       return enif_make_badarg(env);
    }

	if (!enif_inspect_binary(env, argv[1], &tweak)) {
       return enif_make_badarg(env);
    }

    privkey_buf = enif_make_new_binary(env, 32, &r); 
	memcpy(privkey_buf, privkey.data, privkey.size);

	result = secp256k1_ec_privkey_tweak_add(ctx, privkey_buf, tweak.data);

	if (result == 0) {
		return error_result(env, "ec_privkey_tweak_add returned 0");
	}

	return ok_result(env, &r);
}

static ERL_NIF_TERM
ec_pubkey_tweak_add(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM r;
	ErlNifBinary pubkey, tweak;
	unsigned char* pubkey_buf;
	int result;

	if (!enif_inspect_binary(env, argv[0], &pubkey)) {
       return enif_make_badarg(env);
    }

	if (!enif_inspect_binary(env, argv[1], &tweak)) {
       return enif_make_badarg(env);
    }

    pubkey_buf = enif_make_new_binary(env, pubkey.size, &r); 
	memcpy(pubkey_buf, pubkey.data, pubkey.size);

	result = secp256k1_ec_pubkey_tweak_add(ctx, pubkey_buf, pubkey.size, tweak.data);

	if (result == 0) {
		return error_result(env, "ec_pubkey_tweak_add returned 0");
	}

	return ok_result(env, &r);
}

static ERL_NIF_TERM
ec_privkey_tweak_mul(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM r;
	ErlNifBinary privkey, tweak;
	unsigned char* privkey_buf;
	int result;

	if (!enif_inspect_binary(env, argv[0], &privkey)) {
       return enif_make_badarg(env);
    }

	if (!enif_inspect_binary(env, argv[1], &tweak)) {
       return enif_make_badarg(env);
    }

    privkey_buf = enif_make_new_binary(env, 32, &r); 
	memcpy(privkey_buf, privkey.data, privkey.size);

	result = secp256k1_ec_privkey_tweak_mul(ctx, privkey_buf, tweak.data);

	if (result == 0) {
		return error_result(env, "ec_privkey_tweak_mul returned 0");
	}

	return ok_result(env, &r);

}

static ERL_NIF_TERM
ec_pubkey_tweak_mul(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM r;
	ErlNifBinary pubkey, tweak;
	unsigned char* pubkey_buf;
	int result;

	if (!enif_inspect_binary(env, argv[0], &pubkey)) {
       return enif_make_badarg(env);
    }

	if (!enif_inspect_binary(env, argv[1], &tweak)) {
       return enif_make_badarg(env);
    }

    pubkey_buf = enif_make_new_binary(env, pubkey.size, &r); 
	memcpy(pubkey_buf, pubkey.data, pubkey.size);

	result = secp256k1_ec_pubkey_tweak_mul(ctx, pubkey_buf, pubkey.size, tweak.data);

	if (result == 0) {
		return error_result(env, "ec_pubkey_tweak_mul returned 0");
	}

	return ok_result(env, &r);

}

// Ecdsa Signing

static ERL_NIF_TERM
ecdsa_sign(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM r;
	ErlNifBinary message, privkey, noncedata;
	int result;
	unsigned char signature_buf[72];
	int signaturelen = 72;
	unsigned char* finished_signature_buf;

	secp256k1_nonce_function_t noncefp;

	if (!enif_inspect_binary(env, argv[0], &message)) {
       return enif_make_badarg(env);
    }

	if (!enif_inspect_binary(env, argv[1], &privkey)) {
       return enif_make_badarg(env);
    }

    if (!get_nonce_function(env, argv[2], argv[3], &noncefp, &noncedata)) {
		return error_result(env, "Invalid nonce function name");
	}

	result = secp256k1_ecdsa_sign(ctx, message.data, signature_buf, &signaturelen, privkey.data, noncefp, noncedata.data);
	if (!result) {
		return error_result(env, "ecdsa_sign returned 0");
	}
    finished_signature_buf = enif_make_new_binary(env, signaturelen, &r); 
    memcpy(finished_signature_buf, signature_buf, signaturelen);
	return ok_result(env, &r);

}

static ERL_NIF_TERM
ecdsa_verify(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary message, signature, pubkey;
	int result;

	if (!enif_inspect_binary(env, argv[0], &message)) {
       return enif_make_badarg(env);
    }

	if (!enif_inspect_binary(env, argv[1], &signature)) {
       return enif_make_badarg(env);
    }

	if (!enif_inspect_binary(env, argv[2], &pubkey)) {
       return enif_make_badarg(env);
    }

	result = secp256k1_ecdsa_verify(ctx, message.data, signature.data, signature.size, pubkey.data, pubkey.size);

	return atom_from_result(env, result);
}

static ERL_NIF_TERM
ecdsa_sign_compact(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM r;
	ErlNifBinary message, privkey, noncedata;
	secp256k1_nonce_function_t noncefp;
	unsigned char csignature[64];
	unsigned char* finished_signature_buf;
	int result;
	int recid = 0;
	

	if (!enif_inspect_binary(env, argv[0], &message)) {
       return enif_make_badarg(env);
    }

	if (!enif_inspect_binary(env, argv[1], &privkey)) {
       return enif_make_badarg(env);
    }

    if (!get_nonce_function(env, argv[2], argv[3], &noncefp, &noncedata)) {
		return error_result(env, "invalid nonce function name");
	}

    result = secp256k1_ecdsa_sign_compact(ctx, message.data, csignature, privkey.data, noncefp, noncedata.data, &recid);

    if (!result) {
		return error_result(env, "ecdsa_sign_compact returned 0");
	}

    finished_signature_buf = enif_make_new_binary(env, 64, &r); 
    memcpy(finished_signature_buf, csignature, 64);
    return enif_make_tuple3(env, enif_make_atom(env, "ok"), r, enif_make_int(env, recid));

}

static ERL_NIF_TERM
ecdsa_recover_compact(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM r;
	ErlNifBinary message, csignature;
	int result, pubkeylen, compressed;
	int recid = 0;
    unsigned char recpubkey[65];
    unsigned char* finished_recpubkey_buf;
    int recpubkeylen = 0;
	
	if (!enif_inspect_binary(env, argv[0], &message)) {
       return enif_make_badarg(env);
    }

	if (!enif_inspect_binary(env, argv[1], &csignature)) {
       return enif_make_badarg(env);
    }

	if (!get_compressed_flag(env, argv[2], &compressed, &pubkeylen)) {
		return error_result(env, "Compression flag invalid");
	}

	if (!get_recid(env, argv[3], &recid)) {
		return error_result(env, "Recovery id invalid 0-3");
	}

	result = secp256k1_ecdsa_recover_compact(ctx, message.data, csignature.data, recpubkey, &recpubkeylen, compressed, recid);

	if (!result) {
		return error_result(env, "ecdsa_recover_compact returned 0");
	}

	finished_recpubkey_buf = enif_make_new_binary(env, recpubkeylen, &r); 
    memcpy(finished_recpubkey_buf, recpubkey, recpubkeylen);

    return ok_result(env, &r);

}


// Utility functions


// Grab the compressed atom
int get_compressed_flag(ErlNifEnv* env, ERL_NIF_TERM arg, int* compressed, int* pubkeylen) {

	char compressed_atom[16];
	
	if (!enif_get_atom(env, arg, compressed_atom, 16, ERL_NIF_LATIN1)) {
		return 0;
    }

	if (strcmp(compressed_atom, "compressed")  == 0) {
		*pubkeylen = 33;
		*compressed = 1;
		return 1;
	} else if (strcmp(compressed_atom, "uncompressed") == 0) {
		*pubkeylen = 65;
		*compressed = 0;
		return 1;
	}

	return 0;

}


// Grab recovery id
int get_recid(ErlNifEnv* env, ERL_NIF_TERM argv, int* recid) {

	if (!enif_get_int(env, argv, recid)) {
		return 0;
	}

	if (*recid >= 0 && *recid <= 3) {
		return 1;
	}

	return 0;

}

// Get and validate nonce function and associated nonce
int get_nonce_function(ErlNifEnv* env, ERL_NIF_TERM nonce_term, ERL_NIF_TERM nonce_data_term, secp256k1_nonce_function_t* noncefp, ErlNifBinary* noncedata) {
	char nonce_atom[32];
	
    if (!enif_get_atom(env, nonce_term, nonce_atom, 32, ERL_NIF_LATIN1)) {
    	return 0;
    }

	if (strcmp(nonce_atom, "default") == 0) {
		*noncefp = NULL;
		noncedata->data = NULL;
		noncedata->size = 0;
		return 1;
	} else if (strcmp(nonce_atom, "nonce_function_rfc6979") == 0) {
		*noncefp = nonce_function_rfc6979;

		if (!enif_inspect_binary(env, nonce_data_term, noncedata)) {
			return 0;
		}
		return 1;
	}

	return 0;
}


static ERL_NIF_TERM error_result(ErlNifEnv* env, char* error_msg)
{
    return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_string(env, error_msg, ERL_NIF_LATIN1));
}

static ERL_NIF_TERM ok_result(ErlNifEnv* env, ERL_NIF_TERM *r)
{
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), *r);
}

static ERL_NIF_TERM
atom_from_result(ErlNifEnv* env, int res)
{
	char* ret_string;
	if (res == 1) {
		ret_string = "ok";
	} else {
		ret_string = "error";
	}

	return enif_make_atom(env, ret_string);
}

static ErlNifFunc nif_funcs[] = {
    {"sha256", 1, sha256},
	{"hmac_sha256", 2, hmac_sha256},
	{"rand32", 0, rand32},
	{"rand256", 0, rand256},
	{"ec_seckey_verify", 1, ec_seckey_verify},
	{"ec_pubkey_create", 2, ec_pubkey_create},
	{"ec_pubkey_decompress", 1, ec_pubkey_decompress},
	{"ec_pubkey_verify", 1, ec_pubkey_verify},
	{"ec_privkey_export", 2, ec_privkey_export},
	{"ec_privkey_import", 1, ec_privkey_import},
	{"ec_privkey_tweak_add", 2, ec_privkey_tweak_add},
	{"ec_pubkey_tweak_add", 2, ec_pubkey_tweak_add},
	{"ec_privkey_tweak_mul", 2, ec_privkey_tweak_mul},
	{"ec_pubkey_tweak_mul", 2, ec_pubkey_tweak_mul},
	{"ecdsa_sign", 4, ecdsa_sign},
	{"ecdsa_verify", 3, ecdsa_verify},
	{"ecdsa_sign_compact", 4, ecdsa_sign_compact},
	{"ecdsa_recover_compact", 4, ecdsa_recover_compact}
};

ERL_NIF_INIT(libsecp256k1, nif_funcs, &load, NULL, &upgrade, &unload);
