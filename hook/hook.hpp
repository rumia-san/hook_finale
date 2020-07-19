#pragma once
#include <Windows.h>
#include "utils.hpp"
namespace {
	class HookManager
{
	enum { SHELLCODE_SIZE = 5 };
private:
	LPVOID targetFuncAddr;
	LPVOID hookFuncAddr;
	BYTE originalBytes[SHELLCODE_SIZE];
	BYTE shellCode[SHELLCODE_SIZE];
	DWORD oldProtect = 0;
public:
	// 参数是目标函数地址targetFuncAddress，我们自己的hook函数的地址hookFuncAddress
	explicit HookManager(PVOID targetFuncAddress, PVOID hookFuncAddress)
		:targetFuncAddr(targetFuncAddress), hookFuncAddr(hookFuncAddress)
	{
		// 计算相对偏移生成shellcode
		Address offset((DWORD)hookFuncAddress - ((DWORD)targetFuncAddress + 5));
		BYTE tempShellCode[SHELLCODE_SIZE] = {
			0xE9, offset[0], offset[1], offset[2], offset[3],
		};
		memcpy(shellCode, tempShellCode, SHELLCODE_SIZE);

		//保存原有的字节，需要先把目标函数的虚拟内存设置为可读写
		VirtualProtect(targetFuncAddr, SHELLCODE_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
		memcpy(originalBytes, targetFuncAddr, SHELLCODE_SIZE);
	}
	void hook()
	{
		//将shellcode写入目标函数来hook
		memcpy(targetFuncAddr, shellCode, SHELLCODE_SIZE);
	}
	void unhook()
	{
		//恢复原先的字节来unhook
		memcpy(targetFuncAddr, originalBytes, SHELLCODE_SIZE);
	}
	~HookManager()
	{
		//析构时将目标函数的虚拟内存的保护属性恢复
		VirtualProtect(targetFuncAddr, SHELLCODE_SIZE, oldProtect, &oldProtect);
	}
};

}
