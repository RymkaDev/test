#pragma once
#include <windows.h>
#include <string>
#include <tchar.h>
#include <vector>
#include "time.h"
#include <list>
using namespace std;

	bool WriteMemory(DWORD dwDestAddress, LPVOID pData, DWORD dwSize);
	void NOPMemory(INT32 Address, INT32 len);

class Utils
{
public:

	static void WriteMemoryBYTES(DWORD Address, VOID *bytes, int len);
	static void WriteMemoryQWORD(DWORD Address, INT64 value);
	static void WriteMemoryDWORD(DWORD Address, DWORD value);
	static void WriteMemoryWORD(DWORD Address, WORD value);
	static void WriteMemoryBYTE(DWORD Address, BYTE value);

};
