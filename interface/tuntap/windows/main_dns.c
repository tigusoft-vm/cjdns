#include "interface/tuntap/windows/TAPDevice.h"

#include <stdio.h>
#include <windows.h>
#include <Winreg.h>

#define NAME_SIZE 256
#define REG_KEY_PATH_PREFIX "SYSTEM\\ControlSet001\\services\\TCPIP6\\Parameters\\Interfaces\\"

int set_dns_for_tun(const char *dns_address_first, const char *dns_address_second)
{
	struct Except eh;
	char name[NAME_SIZE];
	char actual_name[NAME_SIZE];
	TAPDevice_get_device_guid((char *)name, NAME_SIZE, actual_name, NAME_SIZE, &eh);
	
	char reg_key_path[NAME_SIZE];
	snprintf(reg_key_path, NAME_SIZE, "%s%s", REG_KEY_PATH_PREFIX, name);
	
	char dns_address[NAME_SIZE];
	snprintf(dns_address, NAME_SIZE, "%s,%s", dns_address_first, dns_address_second);

	LONG status;
	HKEY netcard_key;
	status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, reg_key_path, 0, KEY_SET_VALUE, &netcard_key);
	if (status) return status;

	status = RegSetValueEx(netcard_key,
	              "NameServer",
				  0,
				  REG_SZ,
				  dns_address,
				  strlen(dns_address)+1);
	if (status) return status;
				  
	status = RegCloseKey(netcard_key);
	if (status) return status;
	
	return 0;
}

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