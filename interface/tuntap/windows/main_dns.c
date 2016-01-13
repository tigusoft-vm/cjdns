#include "interface/tuntap/windows/set_dns.h"
#include "util/Linker.h"
Linker_require("interface/tuntap/windows/set_dns.c")

#include <stdio.h>

int main(int argc, char* argv[])
{
	//set_dns_for_tun("fc5f:c567:102:c14e:326e:5035:d7e5:9f78");
	if (argc > 3)
	{
		printf("usage: main_dns <dns_address_1> <dns_address_2>\n");
		return 1;
	}
	
	int ret = set_dns_for_tun(argv[1], argv[2]);
	if (ret)
	{
		printf("Internal error\n");
		printf("Error code %d\n", ret);
		return 2;
	}
	
	return 0;
}