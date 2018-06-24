#!/bin/bash

XRES=$1
YRES=$2

FILES=$1

trap 'exit' INT

if [ -z $FILES ]
then
    FILES=`ls *.dot | sort -n`
fi

for FILE in ${FILES}
do
GIF_IMAGE_FILE=${FILE%.dot}.gif
echo "creating image $GIF_IMAGE_FILE from $FILE"
dot -Tgif -o $GIF_IMAGE_FILE ${FILE} || exit -1

#echo "resizing image $FILE"
#convert $IMAGE_FILE -resize ${XRES}x\> -sharpen 0x1.0 -bordercolor white -border ${YRES} -gravity center -crop ${XRES}x${YRES}+0+0 +repage $IMAGE_FILE || exit -1
done
