#!/bin/bash

REPEAT=5

for i in 4096 8192 16384 32768 65536 131072 262144 524288 1048576 2097152 4194304; do
  for r in `seq $REPEAT`; do
    ibv_rc_pingpong --size $i $1
    if [ -n "$1" ]; then
      echo "Client sleeps"
      sleep 2
    fi
  done
done

