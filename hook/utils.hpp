#pragma once
#include <array>
#include <Windows.h>
#include <stdexcept>

//用于将地址转换为byte数组的类，其实用union也可以办到，
//不过是C++的未定义行为，所以这里写了一个转换类
class Address
{
private:
	enum { SIZE = 4 };
	BYTE bytes[SIZE];
public:
	const BYTE operator[](int i) const
	{
		return bytes[i];
	}
	Address(LPVOID address)
	{
		memcpy(bytes, &address, SIZE);
	}
	Address(DWORD address)
	{
		memcpy(bytes, &address, SIZE);
	}
};

//获取dll中指定函数的地址
FARPROC getLibraryProcAddress(LPCSTR libName, LPCSTR procName)
{
	auto dllModule = LoadLibraryA(libName);
	if (dllModule == NULL) {
		throw std::runtime_error("Unable to load library!");
	}
	auto procAddress = GetProcAddress(dllModule, procName);
	if (procAddress == NULL) {
		throw std::runtime_error("Unable to get proc address!");
	}
	return procAddress;
}

//获取LoadLibraryA的地址
inline FARPROC getLoadLibraryAddress()
{
	return getLibraryProcAddress("kernel32.dll", "LoadLibraryA");
}
