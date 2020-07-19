#include <Windows.h>
#include <cstdio>
#include <array>
#include <stdexcept>
#include "hook/utils.hpp"

//生成shellcode的类
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

//管理虚拟内存的类
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
	//将buffer中的内容拷贝到虚拟内存
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

//管理子进程的类
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

//提升权限，因为不是重点就直接用了看雪论坛上IamHuskar的代码，这里就不展开讲了，
//详细可以参考MSDN上微软对AdjustTokenPrivileges等相关函数的讲解
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
	//申请dll路径的内存，获取LoadLibraryA地址
	puts("Allocating Remote Memory For dll path");
	const int bufferSize = strlen(dllPath) + 1;
	VirtualMemory dllPathMemory(pi.hProcess, bufferSize, PAGE_READWRITE);
	dllPathMemory.copyFromBuffer(dllPath, bufferSize);
	PTHREAD_START_ROUTINE startRoutine = (PTHREAD_START_ROUTINE)getLoadLibraryAddress();

	//用dll路径和LoadLibraryA的地址创建远程线程
	puts("Creatint remote thread");
	HANDLE remoteThreadHandle = CreateRemoteThread(
		pi.hProcess, NULL, NULL, startRoutine, dllPathMemory.getAddress(), CREATE_SUSPENDED, NULL);
	if (remoteThreadHandle == NULL) {
		throw std::runtime_error("Failed to create remote thread!");
	}

	//继续远程线程以执行LoadLibraryA，等待其执行完毕
	puts("Resume remote thread");
	ResumeThread(remoteThreadHandle);
	WaitForSingleObject(remoteThreadHandle, INFINITE);
	CloseHandle(remoteThreadHandle);

	//继续主线程
	puts("Resume main thread");
	ResumeThread(pi.hThread);
}

void injectWithShellCode(PROCESS_INFORMATION& pi, const char* dllPath)
{
	//获取进程主线程eip
	puts("Get EIP");
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, &ctx);

	//申请dll路径的内存，生成shellcode
	puts("Allocating Remote Memory For dll path");
	int bufferSize = strlen(dllPath) + 1;
	VirtualMemory dllPathMemory(pi.hProcess, bufferSize, PAGE_READWRITE);
	dllPathMemory.copyFromBuffer(dllPath, bufferSize);
	ShellCode shellCode(ctx.Eip, dllPathMemory.getAddress());

	//申请shellcode的内存，将shellcode写入空间中
	puts("Allocating Remote Memory For Shellcode");
	VirtualMemory shellCodeMemory(pi.hProcess, ShellCode::SIZE, PAGE_EXECUTE_READWRITE);
	shellCodeMemory.copyFromBuffer(shellCode.data(), ShellCode::SIZE);

	//设置进程主线程eip为刚刚申请到的shellcode的内存地址
	puts("Set EIP");
	ctx.Eip = (DWORD)shellCodeMemory.getAddress();
	SetThreadContext(pi.hThread, &ctx);

	//继续主线程以执行shellcode
	puts("Resume main thread");
	ResumeThread(pi.hThread);

	//sleep一下让shellcode执行完毕，不然没执行完就free就惨了
	//因为我们的DLL中的提示框是1秒后自动关闭，所以这里就等2秒
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

	//创建挂起线程
	ChildProcess process("C:\\GAMES\\madomagi\\madomagi 1.28\\Player.exe", CREATE_SUSPENDED);

	if (choice == '1') {
		//注入远程线程
		injectWithRemoteThread(process.getProcessInformation(), "hook_dll.dll");
	} else {
		//注入shellcode
		injectWithShellCode(process.getProcessInformation(), "hook_dll.dll");
	}
	
	return 0;
}