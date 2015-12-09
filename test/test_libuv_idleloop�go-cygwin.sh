CXX=i686-w64-mingw32-g++
$CXX main.cpp  -I ../../node_build/dependencies/libuv/include/ -L ../../build_win32/dependencies/libuv/out/Release/obj.target -lpthread -luv  -lws2_32 -lpsapi -luserenv -liphlpapi
echo "TODO: copy libgcc_s_sjlj-1.dll"
cp /usr/i686-w64-mingw32/sys-root/mingw/bin/libgcc_s_sjlj-1.dll .