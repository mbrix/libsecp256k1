#!/bin/sh

set -e

test `basename $PWD` != "c_src" && cd c_src

case "$1" in
  clean)
    rm -rf secp256k1
    ;;

  *)
  	test -f secp256k1/.libs/libsecp256k1.so && exit 0

    (test -d secp256k1 || git clone https://github.com/bitcoin/secp256k1)

	(cd secp256k1 && git reset --hard 7450ef171db18361962ce1cabc5f3f233648789b &&  ./autogen.sh && ./configure --enable-module-recovery && make)
    ;;
esac
