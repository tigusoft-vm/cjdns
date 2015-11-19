#!/bin/sh

killall cjdroute
sleep 0.001
killall -9 cjdroute
while true; do
   echo -e "starting now\n"
   date
  ./cjdroute < ./cjdroute.conf
  sleep 1
done

exit 0
