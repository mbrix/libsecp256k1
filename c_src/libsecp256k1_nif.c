/* Copyright, 2015 Matthew Branton
 * Distributed under the MIT license located in the LICENSE file.
 *
 * */

#include "erl_nif.h"

#include "libsecp256k1-config.h"
#include "secp256k1.c"
#include "testrand_impl.h"
#include "include/secp256k1_recovery.h"


// Prototypes


static ERL_NIF_TERM atom_from_result(ErlNifEnv* env, int res);
static ERL_NIF_TERM error_result(ErlNifEnv* env, char* error_msg);
static ERL_NIF_TERM ok_result(ErlNifEnv* env, ERL_NIF_TERM *r);
int get_compressed_flag(ErlNifEnv* env, ERL_NIF_TERM arg, int* compressed, size_t* pubkeylen);
int check_compressed(size_t Size);
int get_nonce_function(ErlNifEnv* env, ERL_NIF_TERM nonce_term, ERL_NIF_TERM nonce_data_term, secp256k1_nonce_function* noncefp, ErlNifBinary* noncedata);
int get_recid(ErlNifEnv* env, ERL_NIF_TERM argv, int* recid); 
// Global context
static secp256k1_context *ctx = NULL;

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
	secp256k1_scalar key;
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
	size_t pubkeylen;
	int compressed;
    secp256k1_pubkey pubkey;

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
	result = secp256k1_ec_pubkey_create(ctx, &pubkey, privkey.data);
	if (result == 1 && 
			(secp256k1_ec_pubkey_serialize(ctx, pubkey_buf, &pubkeylen, &pubkey, compressed) == 1)) {
			return ok_result(env, &r);
	} else {
		return error_result(env, "Public key generation error");
	}

}


static ERL_NIF_TERM
ec_pubkey_decompress(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{

	ErlNifBinary pubkey;
	ERL_NIF_TERM r;
	unsigned char* decompressedkey;
	size_t decompressedkeylen = 65;
    secp256k1_pubkey pubkeyt;

	if (!enif_inspect_binary(env, argv[0], &pubkey)) {
       return enif_make_badarg(env);
    }

	if ((pubkey.size != 33) && (pubkey.size != 65)) {
		return error_result(env, "Public key size != 33 or 65 bytes");
	}

	decompressedkey = enif_make_new_binary(env, decompressedkeylen, &r);

	if (secp256k1_ec_pubkey_parse(ctx, &pubkeyt, pubkey.data, pubkey.size) != 1) {
		return error_result(env, "Public key parse error");
	}

	if (secp256k1_ec_pubkey_serialize(ctx, decompressedkey, &decompressedkeylen, &pubkeyt, 0) != 1) {
		return error_result(env, "Public key decompression error");
	}
	
	return ok_result(env, &r);
	
}

static ERL_NIF_TERM
ec_pubkey_verify(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	int result;
	ErlNifBinary pubkey;
    secp256k1_pubkey pubkeyt;
	
	if (!enif_inspect_binary(env, argv[0], &pubkey)) {
       return enif_make_badarg(env);
    }

    if ((pubkey.size != 33) && (pubkey.size != 65)) {
		return error_result(env, "Public key size != 33 or 65 bytes");
	}
	
	result = secp256k1_ec_pubkey_parse(ctx, &pubkeyt, pubkey.data, pubkey.size);
	return atom_from_result(env, result); 
}

static ERL_NIF_TERM
ec_privkey_export(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM r;
	ErlNifBinary privkey;
	unsigned char exported_seckey[300];
	unsigned char* seckey_buf;
	size_t seckey_len = 300;
	int compressed, result;
	size_t pubkeylen;

	if (!enif_inspect_binary(env, argv[0], &privkey)) {
       return enif_make_badarg(env);
    }

    if (privkey.size != 32) {
    	return enif_make_badarg(env);
	}

	if (!get_compressed_flag(env, argv[1], &compressed, &pubkeylen)) {
		return error_result(env, "Compression flag invalid");
	}

	result = secp256k1_ec_privkey_export(ctx, exported_seckey, &seckey_len,
			privkey.data, compressed);
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
    secp256k1_pubkey pubkeyt;

	if (!enif_inspect_binary(env, argv[0], &pubkey)) {
       return enif_make_badarg(env);
    }

	if (!enif_inspect_binary(env, argv[1], &tweak)) {
       return enif_make_badarg(env);
    }

    pubkey_buf = enif_make_new_binary(env, pubkey.size, &r); 

	if (secp256k1_ec_pubkey_parse(ctx, &pubkeyt, pubkey.data, pubkey.size) != 1) {
		return enif_make_badarg(env);
	};

	if (secp256k1_ec_pubkey_tweak_add(ctx, &pubkeyt, tweak.data) != 1) {
		return error_result(env, "ec_pubkey_tweak_add returned 0");
	}

	if (secp256k1_ec_pubkey_serialize(ctx, pubkey_buf, (size_t *)&pubkey.size, &pubkeyt,
				check_compressed(pubkey.size)) != 1) {
		return error_result(env, "Public key serialize error");
	}
	
	return ok_result(env, &r);
}

int check_compressed(size_t Size) {
	if (Size == 33) {
		return 1;
	}
	return 0;
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
    secp256k1_pubkey pubkeyt;

	if (!enif_inspect_binary(env, argv[0], &pubkey)) {
       return enif_make_badarg(env);
    }

	if (!enif_inspect_binary(env, argv[1], &tweak)) {
       return enif_make_badarg(env);
    }

    pubkey_buf = enif_make_new_binary(env, pubkey.size, &r); 
	
	if (secp256k1_ec_pubkey_parse(ctx, &pubkeyt, pubkey.data, pubkey.size) != 1) {
		return enif_make_badarg(env);
	};

	if (secp256k1_ec_pubkey_tweak_mul(ctx, &pubkeyt, tweak.data) != 1) {
		return error_result(env, "ec_pubkey_tweak_mul returned 0");
	}

	if (secp256k1_ec_pubkey_serialize(ctx, pubkey_buf, (size_t *)&pubkey.size, &pubkeyt,
				check_compressed(pubkey.size)) != 1) {
		return error_result(env, "Public key serialize error");
	}

	return ok_result(env, &r);

}

//// Ecdsa Signing
//
static ERL_NIF_TERM
ecdsa_sign(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM r;
	ErlNifBinary message, privkey, noncedata;
	int result;
    secp256k1_ecdsa_signature signature;
	unsigned char* finishedsig;
	size_t siglen = 74;

	secp256k1_nonce_function noncefp;

	if (!enif_inspect_binary(env, argv[0], &message)) {
       return enif_make_badarg(env);
    }

	if (!enif_inspect_binary(env, argv[1], &privkey)) {
       return enif_make_badarg(env);
    }

    if (!get_nonce_function(env, argv[2], argv[3], &noncefp, &noncedata)) {
		return error_result(env, "Invalid nonce function name");
	}

	result = secp256k1_ecdsa_sign(ctx, &signature, message.data,
			privkey.data, noncefp, noncedata.data);
	if (!result) {
		return error_result(env, "ecdsa_sign returned 0");
	}
	
    finishedsig = enif_make_new_binary(env, siglen, &r); 
	if (secp256k1_ecdsa_signature_serialize_der(ctx, finishedsig, &siglen, &signature) != 1) {
		return error_result(env, "ecdsa_signature_serialize returned 0");
	}

	return ok_result(env, &r);

}

static ERL_NIF_TERM
ecdsa_verify(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary message, rawsignature, rawpubkey;
    secp256k1_ecdsa_signature signature;
    secp256k1_pubkey pubkey;
	int result;

	if (!enif_inspect_binary(env, argv[0], &message)) {
       return enif_make_badarg(env);
    }

	if (!enif_inspect_binary(env, argv[1], &rawsignature)) {
       return enif_make_badarg(env);
    }

	if (!enif_inspect_binary(env, argv[2], &rawpubkey)) {
       return enif_make_badarg(env);
    }

	// Parse serialized signature
	if (secp256k1_ecdsa_signature_parse_der(ctx, &signature, rawsignature.data, rawsignature.size) != 1) {
		return error_result(env, "ecdsa signature der parse error");
	}
	// Parse serialized public key
	
	if (secp256k1_ec_pubkey_parse(ctx, &pubkey, rawpubkey.data, rawpubkey.size) != 1) {
		return error_result(env, "Public key invalid");
	};

	result = secp256k1_ecdsa_verify(ctx, &signature, message.data, &pubkey);

	return atom_from_result(env, result);
}

static ERL_NIF_TERM
ecdsa_sign_compact(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM r;
	ErlNifBinary message, privkey, noncedata;
	int result;
    secp256k1_ecdsa_recoverable_signature signature;
	unsigned char* finishedsig;
	int siglen = 64;
	int recid = 0;

	secp256k1_nonce_function noncefp;

	if (!enif_inspect_binary(env, argv[0], &message)) {
       return enif_make_badarg(env);
    }

	if (!enif_inspect_binary(env, argv[1], &privkey)) {
       return enif_make_badarg(env);
    }

    if (!get_nonce_function(env, argv[2], argv[3], &noncefp, &noncedata)) {
		return error_result(env, "Invalid nonce function name");
	}

	result = secp256k1_ecdsa_sign_recoverable(ctx, &signature, message.data,
			privkey.data, noncefp, noncedata.data);
	if (!result) {
		return error_result(env, "ecdsa_sign returned 0");
	}
	
    finishedsig = enif_make_new_binary(env, siglen, &r); 
	if (secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx,
				finishedsig, &recid, &signature) != 1) {
		return error_result(env, "ecdsa_signature_serialize returned 0");
	}

	if (recid == -1) {
		return error_result(env, "invalid recovery id");
	}

    return enif_make_tuple3(env, enif_make_atom(env, "ok"), r, enif_make_int(env, recid));

}

static ERL_NIF_TERM
ecdsa_recover_compact(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ERL_NIF_TERM r;
	ErlNifBinary message, csignature;
	int result, compressed;
	size_t pubkeylen;
	int recid = 0;
    unsigned char* finished_recpubkey_buf;
    secp256k1_ecdsa_recoverable_signature signature;
    secp256k1_pubkey recpubkey;
	
	if (!enif_inspect_binary(env, argv[0], &message)) {
       return enif_make_badarg(env);
    }

	if (!enif_inspect_binary(env, argv[1], &csignature)) {
       return enif_make_badarg(env);
    }

	if (!get_compressed_flag(env, argv[2], &compressed, &pubkeylen)) {
		return error_result(env, "Compression flag invalid");
	}

	if (compressed) {
		pubkeylen = 33;
	} else {
		pubkeylen = 65;
	}

	if (!get_recid(env, argv[3], &recid)) {
		return error_result(env, "Recovery id invalid 0-3");
	}
	
	result = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &signature, csignature.data, recid);

	if (!result) {
		return error_result(env, "ecdsa_signature_parse_compact returned 0");
	}

	// Now do ECDSA recovery
	result = secp256k1_ecdsa_recover(ctx, &recpubkey, &signature, message.data);

	if (!result) {
	    return error_result(env, "ecdsa recovery problem");
	}

	// Now serialize recpubkey based on the compression flag
	finished_recpubkey_buf = enif_make_new_binary(env, pubkeylen, &r); 

	result = secp256k1_ec_pubkey_serialize(ctx, finished_recpubkey_buf,
			&pubkeylen, &recpubkey, compressed);

	if (!result) {
		return error_result(env, "ecdsa pubkey serialize error");
	}

    return ok_result(env, &r);

}


// Utility functions


// Grab the compressed atom
int get_compressed_flag(ErlNifEnv* env, ERL_NIF_TERM arg, int* compressed, size_t* pubkeylen) {

	char compressed_atom[16];
	
	if (!enif_get_atom(env, arg, compressed_atom, 16, ERL_NIF_LATIN1)) {
		return 0;
    }

	if (strcmp(compressed_atom, "compressed")  == 0) {
		*pubkeylen = 33;
		*compressed = SECP256K1_EC_COMPRESSED;
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
int get_nonce_function(ErlNifEnv* env, ERL_NIF_TERM nonce_term, ERL_NIF_TERM nonce_data_term, secp256k1_nonce_function* noncefp, ErlNifBinary* noncedata) {
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
