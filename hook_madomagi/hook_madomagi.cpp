#include <Windows.h>
#include <cstdio>
#include <array>
#include <stdexcept>
#include "hook/utils.hpp"

//����shellcode����
class ShellCode
{
public:
	enum { SIZE = 22 };
private:
	std::array<BYTE, SIZE> shellCode;
public:
	explicit ShellCode(const Address& eip, const Address& dllPath)
	{
		const Address proc(getLoadLibraryAddress());
		shellCode = {
			// Push eip
			0x68, eip[0], eip[1], eip[2], eip[3],
			// Push all flags
			0x9C,
			// Push all register
			0x60,
			// Push &string
			0x68, dllPath[0], dllPath[1], dllPath[2], dllPath[3],
			// Mov eax, &LoadLibrary
			0xB8, proc[0], proc[1], proc[2], proc[3],
			// Call eax
			0xFF, 0xD0,
			// Pop all register
			0x61,
			// Pop all flags
			0x9D,
			// Ret
			0xC3
		};
	}
	const BYTE* data() const
	{
		return shellCode.data();
	}
};

//���������ڴ����
class VirtualMemory
{
private:
	LPVOID address;
public:
	const HANDLE process;
	const SIZE_T size;
	const DWORD protectFlag;
	explicit VirtualMemory(HANDLE hProcess, SIZE_T dwSize, DWORD flProtect) :
		process(hProcess), size(dwSize), protectFlag(flProtect)
	{
		address = VirtualAllocEx(process, NULL, size, MEM_COMMIT, protectFlag);
		if (address == NULL)
			throw std::runtime_error("Failed to allocate virtual memory!");
	}
	~VirtualMemory()
	{
		if (address != NULL)
			VirtualFreeEx(process, address, 0, MEM_RELEASE);
	}
	//��buffer�е����ݿ����������ڴ�
	BOOL copyFromBuffer(LPCVOID buffer, SIZE_T size)
	{
		if (size > this->size)
			return FALSE;
		return WriteProcessMemory(process, address, buffer, size, NULL);
	}
	LPVOID getAddress()
	{
		return address;
	}
};

//�����ӽ��̵���
class ChildProcess
{
private:
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
public:
	explicit ChildProcess(LPCSTR applicationPath, DWORD creationFlags)
	{
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		ZeroMemory(&pi, sizeof(pi));
		if (!CreateProcessA(applicationPath,
			NULL, NULL, NULL, FALSE, creationFlags, NULL, NULL,
			&si, &pi))
		{
			throw std::runtime_error("Failed to create child process!");
		}
	}
	PROCESS_INFORMATION& getProcessInformation()
	{
		return pi;
	}
	~ChildProcess()
	{
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
};

//����Ȩ�ޣ���Ϊ�����ص��ֱ�����˿�ѩ��̳��IamHuskar�Ĵ��룬����Ͳ�չ�����ˣ�
//��ϸ���Բο�MSDN��΢���AdjustTokenPrivileges����غ����Ľ���
BOOL EnableDebugPriv()
{
	HANDLE   hToken;
	LUID   sedebugnameValue;
	TOKEN_PRIVILEGES   tkp;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		return   FALSE;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
	{
		CloseHandle(hToken);
		return   FALSE;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
	{
		return   FALSE;
	}
	CloseHandle(hToken);
	return TRUE;
}

void injectWithRemoteThread(PROCESS_INFORMATION& pi, const char *dllPath)
{
	//����dll·�����ڴ棬��ȡLoadLibraryA��ַ
	puts("Allocating Remote Memory For dll path");
	const int bufferSize = strlen(dllPath) + 1;
	VirtualMemory dllPathMemory(pi.hProcess, bufferSize, PAGE_READWRITE);
	dllPathMemory.copyFromBuffer(dllPath, bufferSize);
	PTHREAD_START_ROUTINE startRoutine = (PTHREAD_START_ROUTINE)getLoadLibraryAddress();

	//��dll·����LoadLibraryA�ĵ�ַ����Զ���߳�
	puts("Creatint remote thread");
	HANDLE remoteThreadHandle = CreateRemoteThread(
		pi.hProcess, NULL, NULL, startRoutine, dllPathMemory.getAddress(), CREATE_SUSPENDED, NULL);
	if (remoteThreadHandle == NULL) {
		throw std::runtime_error("Failed to create remote thread!");
	}

	//����Զ���߳���ִ��LoadLibraryA���ȴ���ִ�����
	puts("Resume remote thread");
	ResumeThread(remoteThreadHandle);
	WaitForSingleObject(remoteThreadHandle, INFINITE);
	CloseHandle(remoteThreadHandle);

	//�������߳�
	puts("Resume main thread");
	ResumeThread(pi.hThread);
}

void injectWithShellCode(PROCESS_INFORMATION& pi, const char* dllPath)
{
	//��ȡ�������߳�eip
	puts("Get EIP");
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, &ctx);

	//����dll·�����ڴ棬����shellcode
	puts("Allocating Remote Memory For dll path");
	int bufferSize = strlen(dllPath) + 1;
	VirtualMemory dllPathMemory(pi.hProcess, bufferSize, PAGE_READWRITE);
	dllPathMemory.copyFromBuffer(dllPath, bufferSize);
	ShellCode shellCode(ctx.Eip, dllPathMemory.getAddress());

	//����shellcode���ڴ棬��shellcodeд��ռ���
	puts("Allocating Remote Memory For Shellcode");
	VirtualMemory shellCodeMemory(pi.hProcess, ShellCode::SIZE, PAGE_EXECUTE_READWRITE);
	shellCodeMemory.copyFromBuffer(shellCode.data(), ShellCode::SIZE);

	//���ý������߳�eipΪ�ո����뵽��shellcode���ڴ��ַ
	puts("Set EIP");
	ctx.Eip = (DWORD)shellCodeMemory.getAddress();
	SetThreadContext(pi.hThread, &ctx);

	//�������߳���ִ��shellcode
	puts("Resume main thread");
	ResumeThread(pi.hThread);

	//sleepһ����shellcodeִ����ϣ���Ȼûִ�����free�Ͳ���
	//��Ϊ���ǵ�DLL�е���ʾ����1����Զ��رգ���������͵�2��
	Sleep(2000);
}

int main(int argc, char* argv[])
{
	if (!EnableDebugPriv()) {
		puts("Failed to enable debug privileges");
		return -1;
	}
	puts("Choose inject method:");
	puts("1. remote thread 2. shellcode");
	puts("please enter your choice:");
	char choice = getchar();

	//���������߳�
	ChildProcess process("C:\\GAMES\\madomagi\\madomagi 1.28\\Player.exe", CREATE_SUSPENDED);

	if (choice == '1') {
		//ע��Զ���߳�
		injectWithRemoteThread(process.getProcessInformation(), "hook_dll.dll");
	} else {
		//ע��shellcode
		injectWithShellCode(process.getProcessInformation(), "hook_dll.dll");
	}
	
	return 0;
}