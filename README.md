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

If you have trouble loading the NIF, make sure that the libsecp256k1 library is built under c_src, and the shared object file is there.

Also check ldd priv/libsecp256k1_nif.so for library path resolutions.
