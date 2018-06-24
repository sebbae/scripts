#!/bin/bash
PATH=${1:/media/ramdisk}

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root" 
  exit 1
fi

modprobe rd || exit 1
mke2fs -m 0 /dev/ram0 || exit 1
mkdir -p ${PATH} || exit 1
mount /dev/ram0 ${PATH} || exit 1
chmod 777 ${PATH} || exit 1
