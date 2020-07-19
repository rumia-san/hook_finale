// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <Windows.h>
#include "hook/utils.hpp"
#include "hook/hook.hpp"

extern "C"
{
    //使用MessageBoxTimeoutA可以让提示框在指定时间自动关闭，但是这是一个未公开的API，
    //所以需要用extern "C"声明一下
    int WINAPI MessageBoxTimeoutA(
        IN HWND hWnd, 
        IN LPCSTR lpText, 
        IN LPCSTR lpCaption, 
        IN UINT uType, 
        IN WORD wLanguageId, 
        IN DWORD dwMilliseconds
    );
};

DWORD WINAPI GdiGetCodePageHookFunc(DWORD param)
{
    return (DWORD)932;
}

static HookManager GdiGetCodePageHookManager{
    getLibraryProcAddress("gdi32.dll", "GdiGetCodePage"),
    GdiGetCodePageHookFunc
};

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxTimeoutA(NULL, "DLL inject success!", "Great!", MB_OK, 0, 1000);
        GdiGetCodePageHookManager.hook();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

