#include "interface/tuntap/windows/set_dns.h"
#include "util/Linker.h"
Linker_require("interface/tuntap/windows/set_dns.c")

#include <windowsx.h>
#include <winnls.h>
#include <windows.h>

#define UNUSED(expr) do { (void)(expr); } while (0)
#define MAX_IPV6_LEN 41

LPSTR main_window_name = "Main window";
MSG msg;

HWND hSetButton;
HWND hComboDNS1;
HWND hComboDNS2;

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch(msg)
    {
    case WM_CLOSE:
        DestroyWindow(hwnd);
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

	case WM_COMMAND:
		if ((HWND)lParam == hSetButton) {
			char dns1[MAX_IPV6_LEN];
			char dns2[MAX_IPV6_LEN];
            ComboBox_GetText(hComboDNS1, dns1, MAX_IPV6_LEN - 1);
			ComboBox_GetText(hComboDNS2, dns2, MAX_IPV6_LEN - 1);
			int ret = set_dns_for_tun(dns1, dns2);
			if (ret != 0)
				MessageBox(hwnd, "ERROR", "", MB_ICONINFORMATION);
		}
		break;

        default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }

    return 0;
}

WNDCLASSEX create_main_window(HINSTANCE hInstance)
{
	WNDCLASSEX main_window;
	main_window.cbSize = sizeof( WNDCLASSEX );
	main_window.style = 0;
	main_window.lpfnWndProc = WndProc;
	main_window.cbClsExtra = 0;
	main_window.cbWndExtra = 0;
	main_window.hInstance = hInstance;
	main_window.hIcon = LoadIcon( NULL, IDI_APPLICATION );
	main_window.hCursor = LoadCursor( NULL, IDC_ARROW );
	main_window.hbrBackground =( HBRUSH )( COLOR_WINDOW + 1 );
	main_window.lpszMenuName = NULL;
	main_window.lpszClassName = main_window_name;
	main_window.hIconSm = LoadIcon( NULL, IDI_APPLICATION );
	return main_window;
}

// function from https://msdn.microsoft.com/en-us/library/aa376389%28v=VS.85%29.aspx
BOOL IsUserAdmin(VOID)
/*++
Routine Description: This routine returns TRUE if the caller's
process is a member of the Administrators local group. Caller is NOT
expected to be impersonating anyone and is expected to be able to
open its own process and process token.
Arguments: None.
Return Value:
   TRUE - Caller has Administrators local group.
   FALSE - Caller does not have Administrators local group. --
*/
{
	BOOL b;
	SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
	PSID AdministratorsGroup;
	b = AllocateAndInitializeSid(
		&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&AdministratorsGroup);
	if(b)
	{
		if (!CheckTokenMembership( NULL, AdministratorsGroup, &b))
		{
			 b = FALSE;
		}
		FreeSid(AdministratorsGroup);
	}
	return(b);
}


int WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow )
{
	FreeConsole();
	if (!IsUserAdmin())
	{
		if (GetUserDefaultUILanguage() == 1045)
			MessageBoxW(NULL,
				L"Musisz uruchomić ten program jako Administrator systemu Windows.\r\n\r\nKliknij ponownie na tym programie prawym klawiszem myszy i powinna tam być opcja 'Uruchom program jako administrator' lub 'Run as Admin' lub podobna, wybierz tą opcję.", L"ERROR", MB_ICONINFORMATION | MB_OK);
		else
			MessageBox(NULL,
				"You must run this program as Administrator of Windows system.\r\n\r\nPlease click again on this program, with right-mouse-button and there should be option 'Run this as Admin' or such, select this option.", "ERROR", MB_ICONINFORMATION | MB_OK);

		return 1;
	}

	WNDCLASSEX main_window = create_main_window(hInstance);
    if(!RegisterClassEx(&main_window))
    {
        MessageBox( NULL, "RegisterClassEx", "", MB_ICONEXCLAMATION | MB_OK );
        return 1;
    }
	HWND hwnd;
	hwnd = CreateWindowEx( WS_EX_CLIENTEDGE, main_window_name, "Set DNS", WS_OVERLAPPEDWINDOW,
    CW_USEDEFAULT, CW_USEDEFAULT, 450, 220, NULL, NULL, hInstance, NULL );
	if(hwnd == NULL)
    {
        MessageBox(NULL, "CreateWindowEx error", "", MB_ICONEXCLAMATION);
        return 1;
    }

	hComboDNS1 = CreateWindowEx(WS_EX_CLIENTEDGE, "COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | WS_BORDER |
		CBS_DROPDOWN, 20, 40, 300, 200, hwnd, NULL, hInstance, NULL);
	SendMessage(hComboDNS1, CB_ADDSTRING, 0,( LPARAM ) "fc5f:c567:102:c14e:326e:5035:d7e5:9f78");
	SendMessage(hComboDNS1, CB_ADDSTRING, 0,( LPARAM ) "fc2f:22bf:e287:88ca:a896:896e:7e62:b411");

	hComboDNS2 = CreateWindowEx(WS_EX_CLIENTEDGE, "COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | WS_BORDER |
		CBS_DROPDOWN, 20, 70, 300, 200, hwnd, NULL, hInstance, NULL);
	SendMessage(hComboDNS2, CB_ADDSTRING, 0,( LPARAM ) "fc5f:c567:102:c14e:326e:5035:d7e5:9f78");
	SendMessage(hComboDNS2, CB_ADDSTRING, 0,( LPARAM ) "fc2f:22bf:e287:88ca:a896:896e:7e62:b411");

	hSetButton = CreateWindowEx(0, "BUTTON", "Set DNS", WS_CHILD | WS_VISIBLE,
		100, 100, 150, 30, hwnd, NULL, hInstance, NULL);
	UNUSED(hSetButton);

	ShowWindow(hwnd, nCmdShow);
	UpdateWindow(hwnd);

	while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return msg.wParam;
}