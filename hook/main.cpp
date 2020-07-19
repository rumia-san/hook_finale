#include <cstdio>
#include <Windows.h>

#include "utils.hpp"
#include "hook.hpp"

extern "C" {
	int WINAPI MessageBoxWHookFunc(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
}

static HookManager MessageBoxWHookManager{
	getLibraryProcAddress("user32.dll", "MessageBoxW"),
	MessageBoxWHookFunc
};

int WINAPI MessageBoxWHookFunc(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	puts("Hook MessageBoxW");
	MessageBoxWHookManager.unhook();
	int ret = MessageBoxW(hWnd, L"MessageBoxW��HOOK", lpCaption, uType);
	MessageBoxWHookManager.hook();
	return ret;
}

int main(void)
{
	MessageBoxW(
		NULL,
		(LPCWSTR)L"���\n����\n",
		(LPCWSTR)L"����",
		MB_ICONWARNING | MB_CANCELTRYCONTINUE | MB_DEFBUTTON2
	);
	MessageBoxWHookManager.hook();
	MessageBoxW(
		NULL,
		(LPCWSTR)L"���\n����\n",
		(LPCWSTR)L"����",
		MB_ICONWARNING | MB_CANCELTRYCONTINUE | MB_DEFBUTTON2
	);
	MessageBoxWHookManager.unhook();
	return 0;
}

