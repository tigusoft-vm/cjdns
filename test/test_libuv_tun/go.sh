#!/bin/bash

gcc main.cpp  -I ../../node_build/dependencies/libuv/include/ -L ../../build_linux/dependencies/libuv/out/Release/ -lpthread -luv

prog=$(which libcap_allow_tun)
echo "libcap program is $prog"

if [[ -x "${prog}" ]] ;
then
	echo "Will try to use libcap tool to have rights needed for TUN/TAP interface creation"
	sudo libcap_allow_tun ./a.out && echo "Libcap seems OK"
else
	echo "You should probably install the program libcap_allow_tun from install_in_system/ and allow current user to sudo run it."
	echo "Or else run this program as root"
fi

echo

./a.out
