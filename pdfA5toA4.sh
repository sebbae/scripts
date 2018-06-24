#!/bin/bash
IN=$1
OUT=${2:-${IN%.pdf}_A4.pdf}
pdfjam --nup 2x1 $IN --landscape --a4paper --outfile $OUT
