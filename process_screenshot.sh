#!/bin/bash
INFILE=$1
OUTFILE=$2
convert -resize 1080x -quality 43 -strip "${INFILE}" "${OUTFILE}"
