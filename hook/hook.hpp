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
	// ������Ŀ�꺯����ַtargetFuncAddress�������Լ���hook�����ĵ�ַhookFuncAddress
	explicit HookManager(PVOID targetFuncAddress, PVOID hookFuncAddress)
		:targetFuncAddr(targetFuncAddress), hookFuncAddr(hookFuncAddress)
	{
		// �������ƫ������shellcode
		Address offset((DWORD)hookFuncAddress - ((DWORD)targetFuncAddress + 5));
		BYTE tempShellCode[SHELLCODE_SIZE] = {
			0xE9, offset[0], offset[1], offset[2], offset[3],
		};
		memcpy(shellCode, tempShellCode, SHELLCODE_SIZE);

		//����ԭ�е��ֽڣ���Ҫ�Ȱ�Ŀ�꺯���������ڴ�����Ϊ�ɶ�д
		VirtualProtect(targetFuncAddr, SHELLCODE_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
		memcpy(originalBytes, targetFuncAddr, SHELLCODE_SIZE);
	}
	void hook()
	{
		//��shellcodeд��Ŀ�꺯����hook
		memcpy(targetFuncAddr, shellCode, SHELLCODE_SIZE);
	}
	void unhook()
	{
		//�ָ�ԭ�ȵ��ֽ���unhook
		memcpy(targetFuncAddr, originalBytes, SHELLCODE_SIZE);
	}
	~HookManager()
	{
		//����ʱ��Ŀ�꺯���������ڴ�ı������Իָ�
		VirtualProtect(targetFuncAddr, SHELLCODE_SIZE, oldProtect, &oldProtect);
	}
};

}
