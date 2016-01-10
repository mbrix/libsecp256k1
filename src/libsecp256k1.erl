%% Copyright 2015 Matthew Branton. All Rights Reserved.
%% Use of this source code is governed by the MIT
%% license that can be found in the LICENSE file.
%%
%% @doc Erlang NIF bindings
%% <a href="https://github.com/bitcoin/secp256k1">libsec256k1</a> elliptic curve library

-module(libsecp256k1).
-author("mbranton@emberfinancial.com").

-export([dsha256/1,
		 sha256/1,
		 hmac_sha256/2,
		 rand32/0,
		 rand256/0,
		 ec_seckey_verify/1,
		 ec_pubkey_create/2,
		 ec_pubkey_decompress/1,
		 ec_pubkey_verify/1,
		 ec_privkey_export/2,
		 ec_privkey_import/1,
		 ec_privkey_tweak_add/2,
		 ec_pubkey_tweak_add/2,
		 ec_privkey_tweak_mul/2,
		 ec_pubkey_tweak_mul/2,
		 ecdsa_sign/4,
		 ecdsa_verify/3,
		 ecdsa_sign_compact/4,
		 ecdsa_recover_compact/4]).

-on_load(init/0).

-define(APPNAME, libsecp256k1).
-define(LIBNAME, libsecp256k1_nif).

%% API

dsha256(_) ->
	not_loaded(?LINE).

sha256(_) ->
    not_loaded(?LINE).

hmac_sha256(_, _) ->
	not_loaded(?LINE).

%% testing PRNG
rand32() ->
	not_loaded(?LINE).

rand256() ->
	not_loaded(?LINE).

%% Ecdsa functions
ec_seckey_verify(_) ->
	not_loaded(?LINE).

ec_pubkey_create(_, _) ->
	not_loaded(?LINE).

ec_pubkey_decompress(_) ->
	not_loaded(?LINE).

ec_pubkey_verify(_) ->
	not_loaded(?LINE).

ec_privkey_export(_, _) ->
	not_loaded(?LINE).

ec_privkey_import(_) ->
	not_loaded(?LINE).

ec_privkey_tweak_add(_, _) ->
	not_loaded(?LINE).

ec_pubkey_tweak_add(_, _) ->
	not_loaded(?LINE).

ec_privkey_tweak_mul(_, _) ->
	not_loaded(?LINE).

ec_pubkey_tweak_mul(_, _) -> 
	not_loaded(?LINE).

ecdsa_sign(_, _, _, _) ->
	not_loaded(?LINE).

ecdsa_verify(_, _, _) ->
	not_loaded(?LINE).

ecdsa_sign_compact(_, _, _, _) ->
	not_loaded(?LINE).

ecdsa_recover_compact(_, _, _, _) ->
	not_loaded(?LINE).

%% Iternal functions

init() ->
    SoName = case code:priv_dir(?APPNAME) of
        {error, bad_name} ->
            case filelib:is_dir(filename:join(["..", priv])) of
                true ->
                    filename:join(["..", priv, ?LIBNAME]);
                _ ->
                    filename:join([priv, ?LIBNAME])
            end;
        Dir ->
            filename:join(Dir, ?LIBNAME)
    end,
    erlang:load_nif(SoName, 0).

% This is just a simple place holder. It mostly shouldn't ever be called
% unless there was an unexpected error loading the NIF shared library.

not_loaded(Line) ->
    exit({not_loaded, [{module, ?MODULE}, {line, Line}]}).
