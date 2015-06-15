Erlang NIF C libsecp256k1
============

Bindings for most of the library functionality
Tested with Erlang/OTP 17+

Build and usage steps
---------------------
	$ rebar compile eunit
	$ erl -pa ebin/
	  Privkey = crypto:strong_rand_bytes(32).
	  {ok, Pubkey} = libsecp256k1:ec_pubkey_create(Privkey, compressed).

Check the test suite for more details

Debugging
---------

Library should be statically compiled.
