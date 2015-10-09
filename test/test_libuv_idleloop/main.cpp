

// TODO(rfree) needed for the test
#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif


// to get and log the version of library:
#include "uv-version.h"
#include "uv.h"

#include <stdio.h>

#include "../test_version.inc"


volatile int64_t counter = 0;

void wait_for_a_while(uv_idle_t* handle) {
    counter++;

    if (counter >= 10e5) {
    		printf("Ok, couter done.\n");
    		counter = 0;
        uv_idle_stop(handle);
		}
}

int main() {
		test_libuv_version();

    uv_idle_t idler;

    uv_idle_init(uv_default_loop(), &idler);

		for (int i=0; i<10; ++i) {
    	uv_idle_start(&idler, wait_for_a_while);
			printf("Idling... (wait a moment)\n");
			uv_run(uv_default_loop(), UV_RUN_DEFAULT);
			printf("Done\n");
		}

    uv_loop_close(uv_default_loop());
    return 0;
}


