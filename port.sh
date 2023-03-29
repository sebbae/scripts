#!/bin/sh
PORT=$1

if [ -z "${PORT}" ]; then
	lsof -nP -iTCP -sTCP:LISTEN
else
	lsof -nP -iTCP:$PORT -sTCP:LISTEN
fi
