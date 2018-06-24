#!/bin/bash
openssl s_client -connect $1 < /dev/null 2>/dev/null | openssl x509 -fingerprint -noout -in /dev/stdin
