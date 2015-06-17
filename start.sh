#!/bin/sh
ERL=erl
COOKIE=eldap_cookie
NODE_NAME=eldap@127.0.0.1
CONFIG=priv/eldap.config
LIBS_DIR="deps"

exec $ERL \
    -pa ebin \
    -boot start_sasl \
    -setcookie $COOKIE \
    -config $CONFIG \
    -env ERL_LIBS $LIBS_DIR \
    -s lager \
    -name $NODE_NAME \
    -s eldap 


