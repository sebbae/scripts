#!/bin/bash
INFILE="$1"
OUTFILE="$2"
START=${3:=0}
LENGTH=${4:=10}
SCALE=1080
FPS=3
ffmpeg -ss ${START} -t ${LENGTH} -i "${INFILE}" -filter_complex "[0:v] fps=${FPS},scale=${SCALE}:-1:flags=lanczos,split [vid1][vid2];[vid1] palettegen [palette];[vid2][palette] paletteuse" -crf 30 "${OUTFILE}"
