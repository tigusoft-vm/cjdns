#!/bin/bash

normal_dir=$(pwd)

echo "First compile (it will fail)"
echo "TODO optimize this (it just need to 1. download code 2. copy like ./do 3. more?)"

./do 

echo "Ok, now FIXING it:"

cd build_win32/dependencies/gyp

python setup.py install

cd ..
cd libuv/

python gyp_uv.py

cd "normal_dir"
echo "Ok now building again, it should work this time"
./do





