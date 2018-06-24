#!/bin/bash
EPS_FILE=$1
JPG_FILE=${EPS_FILE%.eps}.jpg
echo Convert $EPS_FILE to $JPG_FILE
gs -sDEVICE=jpeg -dJPEGQ=100 -dNOPAUSE -dBATCH -dSAFER -r300 -sOutputFile=$JPG_FILE $EPS_FILE
mogrify -trim -resize 800 $JPG_FILE
