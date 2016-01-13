#include "interface/tuntap/windows/TAPDevice.h"
#include "interface/tuntap/windows/set_dns.h"

#include <stdio.h>
#include <windows.h>
#include <winreg.h>

#define NAME_SIZE 256
#define REG_KEY_PATH_PREFIX_V6 "SYSTEM\\ControlSet001\\services\\TCPIP6\\Parameters\\Interfaces\\"
#define REG_KEY_PATH_PREFIX_V4 "SYSTEM\\ControlSet001\\services\\TCPIP\\Parameters\\Interfaces\\"

int set_dns_for_tun(const char *dns_address_first, const char *dns_address_second)
{
	struct Except eh;
	char name[NAME_SIZE];
	char actual_name[NAME_SIZE];
	TAPDevice_get_device_guid((char *)name, NAME_SIZE, actual_name, NAME_SIZE, &eh);

	char reg_key_path_v6[NAME_SIZE];
	char reg_key_path_v4[NAME_SIZE];

	snprintf(reg_key_path_v6, NAME_SIZE, "%s%s", REG_KEY_PATH_PREFIX_V6, name);
	snprintf(reg_key_path_v4, NAME_SIZE, "%s%s", REG_KEY_PATH_PREFIX_V4, name);

	char dns_address[NAME_SIZE];
	snprintf(dns_address, NAME_SIZE, "%s,%s", dns_address_first, dns_address_second);

	LONG status;
	HKEY netcard_key;
	printf("reg_key_path_v6 %s\n", reg_key_path_v6);
	printf("reg_key_path_v4 %s\n", reg_key_path_v4);
	// set ipv6 dns
	printf("open\n");
	status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, reg_key_path_v6, 0, KEY_SET_VALUE, &netcard_key);
	if (status) return status;
	printf("set\n");
	status = RegSetValueEx(netcard_key,
	              "NameServer",
				  0,
				  REG_SZ,
				  dns_address,
				  strlen(dns_address)+1);
	if (status) return status;
	printf("close\n");
	status = RegCloseKey(netcard_key);
	if (status) return status;

	printf("set ipv4 dns\n");
	// set ipv4 dns
	status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, reg_key_path_v4, 0, KEY_SET_VALUE, &netcard_key);
	if (status) return status;

	status = RegSetValueEx(netcard_key,
	              "NameServer",
				  0,
				  REG_SZ,
				  "8.8.8.8",
				  strlen("8.8.8.8")+1);
	if (status) return status;

	status = RegCloseKey(netcard_key);
	if (status) return status;

	return 0;
}