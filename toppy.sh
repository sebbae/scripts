#!/bin/bash
top -p `ps -C $1 -o pid=`
