#!/bin/bash

XRES=$1
YRES=$2

for FILE in `ls *.dot | sort -n`;
do
SVG_IMAGE_FILE=${FILE%.dot}.svg
#echo "creating image $SVG_IMAGE_FILE from $FILE"
dot -Tsvg -o $SVG_IMAGE_FILE $FILE || exit -1

#echo "resizing image $FILE"
#convert $IMAGE_FILE -resize ${XRES}x\> -sharpen 0x1.0 -bordercolor white -border ${YRES} -gravity center -crop ${XRES}x${YRES}+0+0 +repage $IMAGE_FILE || exit -1
done
