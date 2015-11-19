#!/bin/sh

while true; do
  res=$(git pull)
  if [[ "$res" != "Already up-to-date." ]]; then
    echo "updating now\n"
    date
    ./do
    killall cjdroute
    sleep 0.01
    killall -9 cjdroute
  fi
  sleep 1
done

exit 0
