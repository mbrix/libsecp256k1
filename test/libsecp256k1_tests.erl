%% Copyright 2015 Matthew Branton. All Rights Reserved.
%% Use of this source code is governed by the MIT
%% license that can be found in the LICENSE file.
%%


-module(libsecp256k1_tests).
-author('mbranton@emberfinancial.com').

-include_lib("eunit/include/eunit.hrl").

start() ->
	ok.

stop(_) ->
	ok.

create_keys() ->
	A = crypto:rand_bytes(32), %% Should use strong_rand in production
	{ok, B} = libsecp256k1:ec_pubkey_create(A, compressed),
	{ok, B2} = libsecp256k1:ec_pubkey_create(A, uncompressed),
	{ok, C} = libsecp256k1:ec_pubkey_decompress(B),
	?assertEqual(B2, C),
	?assertEqual(ok, libsecp256k1:ec_pubkey_verify(B)),
	?assertEqual(ok, libsecp256k1:ec_pubkey_verify(C)).

invalid_keys() ->
	A = crypto:rand_bytes(16),
	?assertMatch({error, _Msg}, libsecp256k1:ec_pubkey_create(A, compressed)),
	?assertMatch({error, _Msg}, libsecp256k1:ec_pubkey_create(A, invalidflag)).

import_export() ->
	A = crypto:rand_bytes(32),
	{ok, B} = libsecp256k1:ec_privkey_export(A, compressed),
	{ok, C} = libsecp256k1:ec_privkey_import(B),
	?assertEqual(A, C).

tweaks() ->
	<<A:256/bitstring, Tweak:256/bitstring>> = crypto:rand_bytes(64),
	{ok, Pubkey} = libsecp256k1:ec_pubkey_create(A, compressed),
	{ok, A2} = libsecp256k1:ec_privkey_tweak_add(A, Tweak),
	{ok, A3} = libsecp256k1:ec_privkey_tweak_mul(A, Tweak),
	{ok, Pubkey2} = libsecp256k1:ec_pubkey_tweak_add(Pubkey, Tweak),
	{ok, Pubkey3} = libsecp256k1:ec_pubkey_tweak_mul(Pubkey, Tweak),
	{ok, PubkeyA2} = libsecp256k1:ec_pubkey_create(A2, compressed),
	{ok, PubkeyA3} = libsecp256k1:ec_pubkey_create(A3, compressed),
	?assertEqual(Pubkey2, PubkeyA2),
	?assertEqual(Pubkey3, PubkeyA3).

signing() ->
	Msg = <<"This is a secret message...">>,
	A = crypto:rand_bytes(32),
	{ok, Pubkey} = libsecp256k1:ec_pubkey_create(A, compressed),
	{ok, Signature} = libsecp256k1:ecdsa_sign(Msg, A, default, <<>>),
	?assertEqual(ok, libsecp256k1:ecdsa_verify(Msg, Signature, Pubkey)).

blank_msg() ->
	Msg = <<>>,
	A = crypto:rand_bytes(32),
	{ok, Pubkey} = libsecp256k1:ec_pubkey_create(A, compressed),
	{ok, Signature} = libsecp256k1:ecdsa_sign(Msg, A, default, <<>>),
	?assertEqual(ok, libsecp256k1:ecdsa_verify(Msg, Signature, Pubkey)).

compact_signing() ->
	Msg = <<"This is a very secret compact message...">>,
	A = crypto:rand_bytes(32),
	{ok, Pubkey} = libsecp256k1:ec_pubkey_create(A, uncompressed),
	{ok, Signature, RecoveryID} = libsecp256k1:ecdsa_sign_compact(Msg, A, default, <<>>),
	{ok, RecoveredKey} = libsecp256k1:ecdsa_recover_compact(Msg, Signature, uncompressed, RecoveryID),
	?assertEqual(Pubkey, RecoveredKey).

secp235k1_test_() -> 
  {foreach,
  fun start/0,
  fun stop/1,
   [
		{"Create keys", fun create_keys/0},
		{"Invalid keys", fun invalid_keys/0},
		{"Import export", fun import_export/0},
		{"Curve tweaks", fun tweaks/0},
		{"Signing", fun signing/0},
		{"Blank sign", fun blank_msg/0},
		{"Compact", fun compact_signing/0}
   ]
  }.
