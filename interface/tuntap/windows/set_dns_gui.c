#include <windows.h>

#define UNUSED(expr) do { (void)(expr); } while (0)

LPSTR main_window_name = "Main window";
MSG msg;

LRESULT CALLBACK WndProc( HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam )
{
    switch( msg )
    {
    case WM_CLOSE:
        DestroyWindow( hwnd );
        break;
       
    case WM_DESTROY:
        PostQuitMessage( 0 );
        break;
       
        default:
        return DefWindowProc( hwnd, msg, wParam, lParam );
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

int WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow )
{
	FreeConsole();
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
	HWND hComboDNS1 = CreateWindowEx(WS_EX_CLIENTEDGE, "COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | WS_BORDER |
		CBS_DROPDOWN, 20, 40, 300, 200, hwnd, NULL, hInstance, NULL);
	SendMessage(hComboDNS1, CB_ADDSTRING, 0,( LPARAM ) "fc5f:c567:102:c14e:326e:5035:d7e5:9f78");
	SendMessage(hComboDNS1, CB_ADDSTRING, 0,( LPARAM ) "fc2f:22bf:e287:88ca:a896:896e:7e62:b411");

	HWND hComboDNS2 = CreateWindowEx(WS_EX_CLIENTEDGE, "COMBOBOX", NULL, WS_CHILD | WS_VISIBLE | WS_BORDER |
		CBS_DROPDOWN, 20, 70, 300, 200, hwnd, NULL, hInstance, NULL);
	SendMessage(hComboDNS2, CB_ADDSTRING, 0,( LPARAM ) "fc5f:c567:102:c14e:326e:5035:d7e5:9f78");
	SendMessage(hComboDNS2, CB_ADDSTRING, 0,( LPARAM ) "fc2f:22bf:e287:88ca:a896:896e:7e62:b411");

	ShowWindow(hwnd, nCmdShow);
	UpdateWindow(hwnd);

	while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return msg.wParam;
	
    return 0;
}